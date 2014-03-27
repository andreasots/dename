package main

import (
	"flag"
	"fmt"
	"github.com/andres-erbsen/dename/dnmclient"
	"github.com/andres-erbsen/dename/protocol"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var configDir *string = flag.String("config-dir", "", "Location of the config directory [default: ~/.config/dename/]")
var name *string = flag.String("name", "", "name to modify")

var tokenRequestURL = "http://" + strings.Replace(dnmclient.PilotVerifierAddress, ":6362", "/", -1)

const text_askEmail = "Registration of dename names is limited to keep the pool of possible names from getting exhausted. Currently, an university or non-profit email address is required for registration. The email address is used only for the purpose of rate limiting, no other information than the fact that it requested the right to register some name is stored. If you already have a registration token, leave the email blank.\nemail: "
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
		*configDir = dnmclient.DefaultProfilePath
	}

	cfgPath := filepath.Join(*configDir, "dename.cfg")
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

		nameTaken := true // assume the worst
		for nameTaken {
			if len(*name) == 0 {
				*name = ask(text_askName)
			}
			_, err := dnmc.Lookup(*name)
			if err == dnmclient.ErrNotFound {
				nameTaken = false
			} else if err == nil {
				fmt.Println(text_nameTaken)
				*name = ""
			} else {
				barf(err.Error(), 1)
			}
		}

		profile, err := dnmclient.CreateProfilePath(
			filepath.Join(*configDir, *name), *name)
		if err != nil {
			barf("init: save: "+err.Error(), 1)
		}
		if err := dnmc.RegisterPersistent(profile, regtoken); err != nil {
			barf("init: register: "+err.Error(), 1)
		}
		profile.Close()
	case "set":
		if len(*name) == 0 {
			dircontents, err := ioutil.ReadDir(*configDir)
			if err != nil {
				barf("set: ls "+*configDir+": "+err.Error(), 1)
			}
			for _, node := range dircontents {
				if node.IsDir() {
					if len(*name) == 0 {
						*name = node.Name()
					} else {
						barf("set: specify --name=NAME (multiply names present)", 1)
					}
				}
			}
		}
		profile, err := dnmclient.OpenProfilePath(filepath.Join(*configDir, *name))
		if err != nil {
			barf("set: open profile: "+err.Error(), 1)
		}

		args := flag.Args()[1:]
		if len(args)%2 == 1 && len(args) >= 2 {
			barf("set: usage: dnmgr set field value", 2)
		}

		for i := 0; i < len(args); i += 2 {
			field, lookup_ok := protocol.ProfileFields[args[i]]
			_, scan_err := fmt.Sscan(args[i], &field)
			if !lookup_ok && scan_err != nil {
				barf("set: unknown non-numeric field", 2)
			}
			if err := profile.Set(field, []byte(args[i+1])); err != nil {
				barf("set: save: "+err.Error(), 1)
			}
		}
		if err := dnmc.Push(profile); err != nil {
			barf("init: push: "+err.Error(), 1)
		}
		profile.Close()
	}
}
