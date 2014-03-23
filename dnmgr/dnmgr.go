package main

import (
	"code.google.com/p/goprotobuf/proto"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/agl/ed25519"
	"github.com/andres-erbsen/dename/dnmclient"
	"github.com/andres-erbsen/dename/protocol"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

var configDir *string = flag.String("config-dir", "", "Location of the config directory [default: ~/.config/dename/]")

const tokenRequestURL = "http://localhost/"

const text_askEmail = "Registration of dename names is limited to keep the pool of possible names from getting exhausted. Currently, an university or non-profit email address is required for registration. The email address is used only for the purpose of rate limiting, no other information than the fact that it requested the right to register some name is stored.\nemail: "
const text_askRegToken = "ticket from email: "
const text_askName = "desired name: "
const text_nameTaken = "this name is already taken."

func barf(s string, c int) {
	os.Stderr.WriteString(s + "\n")
	os.Exit(c)
}

func ask(question string) (answer string) {
	_, err := fmt.Printf(question)
	if err != nil {
		barf(err.Error(), 1)
	}
	_, err = fmt.Scanf("%s\n", &answer)
	if err != nil && err.Error() != "unexpected newline" {
		barf(err.Error(), 1)
	}
	return
}

func main() {
	flag.Parse()
	if len(*configDir) == 0 {
		homeDir := os.Getenv("HOME")
		if len(homeDir) == 0 {
			homeDir = "/"
		}
		*configDir = homeDir + "/.config/dename/"
	}
	skPath := *configDir + "sk"
	cfgPath := *configDir + "config"
	namePath := *configDir + "name"

	var dnmc *dnmclient.DenameClient
	if _, err := os.Stat(cfgPath); err == nil {
		dnmc, err = dnmclient.NewFromFile(cfgPath, nil)
		if err != nil {
			barf(err.Error(), 1)
		}
	} else {
		dnmc = dnmclient.New(nil, "", nil)
	}

	switch flag.Arg(0) {
	case "init":
		if _, err := os.Stat(skPath); err == nil {
			barf("init: secret key already exists, aborting", 1)
		}

		email := ask(text_askEmail)

		if email != "" {
			// request a registration token to be sent to that email
			resp, err := http.PostForm(tokenRequestURL,
				url.Values{"email": {email}})
			if err != nil {
				barf("init: request email: "+err.Error(), 1)
			}
			if resp.StatusCode != 200 {
				barf("init: request email: "+resp.Status, 1)
			}
			io.Copy(os.Stdout, resp.Body)
			resp.Body.Close()
		}
		regtoken := ask(text_askRegToken)

		var name string
		for {
			name = ask(text_askName)
			_, err := dnmc.Lookup(name)
			if err == dnmclient.ErrNotFound {
				break
			} else if err == nil {
				fmt.Println(text_nameTaken)
			} else {
				barf(err.Error(), 1)
			}
		}

		// generate and save secret key
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		iden := &protocol.Identity{Dename: &protocol.PublicKey{Ed25519: pk[:]}}

		err = os.MkdirAll(*configDir, 0600)
		if err != nil {
			barf("init: create \""+*configDir+"\" :"+err.Error(), 1)
		}
		skFile, err := os.OpenFile(skPath, os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			barf("init: create \""+skPath+"\": "+err.Error(), 1)
		}
		err = binary.Write(skFile, binary.LittleEndian, sk)
		if err != nil {
			barf("init: write \""+skPath+"\": "+err.Error(), 1)
		}

		for {
			sk_ := (*protocol.Ed25519Secret)(sk)
			err := dnmc.Register(sk_, iden, name, regtoken)
			if err == nil {
				break
			} else {
				fmt.Println(err.Error, ", retrying...")
			}
		}
		err = ioutil.WriteFile(namePath, []byte(name), 0600)
		if err != nil {
			barf("init: write \""+namePath+"\": "+err.Error(), 1)
		}
	case "set":
		args := flag.Args()[1:]
		if len(args)%2 == 1 {
			barf("set: usage: dnmgr set field value", 2)
		}

		if _, err := os.Stat(skPath); err != nil {
			barf("set: unable to find secret key; maybe run 'dnmgr init'?", 1)
		}
		skFile, err := os.Open(skPath)
		if err != nil {
			barf("set: open \""+skPath+"\": "+err.Error(), 1)
		}
		var sk [ed25519.PrivateKeySize]byte
		err = binary.Read(skFile, binary.LittleEndian, &sk)
		if err != nil {
			barf("set: read \""+skPath+"\": "+err.Error(), 1)
		}

		name_bs, err := ioutil.ReadFile(namePath)
		if err != nil {
			barf("set: read \""+namePath+"\": "+err.Error(), 1)
		}
		name := string(name_bs)
		iden, err := dnmc.Lookup(name)
		if err != nil {
			barf("set: lookup name: "+err.Error(), 1)
		}

		sk_ := (*protocol.Ed25519Secret)(&sk)
		test_sig := sk_.SignDetached([]byte{}, 0)
		err = iden.Dename.VerifyDetached([]byte{}, test_sig, 0)
		if err != nil {
			barf("set: this name does not seem to belong to us: "+err.Error(), 1)
		}

		for i := 0; i < len(args); i += 2 {
			n, lookup_ok := protocol.ProfileFields[args[i]]
			_, scan_err := fmt.Sscan(args[i], &n)
			if !(lookup_ok || scan_err == nil) {
				barf("set: unknown non-numeric field type", 2)
			}
			desc := proto.ExtensionDesc{
				ExtendedType:  (*protocol.Identity)(nil),
				ExtensionType: ([]byte)(nil),
				Field:         n,
				Tag:           fmt.Sprintf("bytes,%d,opt", n),
			}

			func() {
				// repeatedly registrering the same extension panics
				defer recover()
				proto.RegisterExtension(&desc)
			}()
			err := proto.SetExtension(iden, &desc, []byte(args[i+1]))
			if err != nil {
				barf("set: "+err.Error(), 1)
			}
		}
		for {
			err := dnmc.Modify(sk_, name, iden)
			if err == nil {
				break
			} else {
				fmt.Printf("set: %s: retrying...\n", err.Error())
			}
		}
	}
}
