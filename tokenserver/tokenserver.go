package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"github.com/andres-erbsen/dename/pgutil"
	"github.com/mqu/openldap"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	txt_template "text/template"
)

var templates = template.Must(template.ParseFiles("index.html", "success.html", "error.html"))
var txt_templates = txt_template.Must(txt_template.ParseFiles("body.txt"))
var mac_key []byte
var db *sql.DB
var errQuota = errors.New("This address has already been sent a registration token.")

const emailUserRegex = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*"

type EmailRule struct {
	Pattern     string
	handler     func(addr string) error
	Explanation string
}

func validatedEmailHandler(email string) error {
	h := sha256.Sum256([]byte(email))
	_, err := db.Exec(`INSERT INTO blacklist(hash) VALUES($1)`, h[:])
	if pgutil.IsError(err, pgutil.ErrUniqueViolation) {
		return errQuota
	} else if err != nil {
		log.Fatalf("Lookup hash from blacklist: %s", err)
	}
	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, mac_key)
	mac.Write(nonce[:])
	ticket := append(nonce, mac.Sum(nil)[:16]...)
	ticket_b64 := base64.StdEncoding.EncodeToString(ticket)
	c, err := smtp.Dial("outgoing.mit.edu:25")
	if err != nil {
		return err
	}
	c.Mail("dename-tickets@mit.edu")
	c.Rcpt(email)
	w, err := c.Data()
	if err != nil {
		return err
	}
	defer w.Close()
	args := struct {
		To     string
		Ticket string
	}{email, ticket_b64}
	return txt_templates.ExecuteTemplate(w, "body.txt", args)
}

func mitKerberosHandler(email string) error {
	username := strings.Split(email, "@")[0]
	ldap, err := openldap.Initialize("ldap://ldap-too.mit.edu:389/")
	if err != nil {
		return err
	}
	ldap.SetOption(openldap.LDAP_OPT_PROTOCOL_VERSION, openldap.LDAP_VERSION3)
	result, err := ldap.SearchAll("ou=users,ou=moira,dc=mit,dc=edu",
		openldap.LDAP_SCOPE_SUBTREE, "uid="+username, []string{"uid"})
	if err != nil {
		return err
	}
	if result.Count() != 1 {
		return errors.New("!= 1 ldap responses")
	}
	if len(result.Entries()[0].Attributes()) != 1 {
		return errors.New("!= 1 attributes in the only ldap response")
	}
	attr := result.Entries()[0].Attributes()[0]
	if len(attr.Values()) != 1 {
		return errors.New("!= 1 values in the only ldap attribute")
	}
	if attr.Name() == "uid" && attr.Values()[0] == username {
		return validatedEmailHandler(email)
	}
	return errors.New("Not a kerberos account")
}

var allowedEmails = []EmailRule{
	{`*@mit.edu`, mitKerberosHandler, "MIT Kerberos accounts"},
	{`*@college.harvard.edu`, validatedEmailHandler, ""},
	{`*@fsfe.org`, validatedEmailHandler, ""},
	{`*@member.fsf.org `, validatedEmailHandler, ""},
	{`*@eesti.ee`, validatedEmailHandler, ""},
	{`*@riseup.net`, validatedEmailHandler, ""},
	{`*@anche.no`, validatedEmailHandler, ""},
	{`*@autistiche.org`, validatedEmailHandler, ""},
	{`*@autistici.org`, validatedEmailHandler, ""},
	{`*@autoproduzioni.net`, validatedEmailHandler, ""},
	{`*@bastardi.net`, validatedEmailHandler, ""},
	{`*@bruttocarattere.org`, validatedEmailHandler, ""},
	{`*@canaglie.net`, validatedEmailHandler, ""},
	{`*@canaglie.org`, validatedEmailHandler, ""},
	{`*@cryptolab.net`, validatedEmailHandler, ""},
	{`*@distruzione.org`, validatedEmailHandler, ""},
	{`*@grrlz.net`, validatedEmailHandler, ""},
	{`*@hacari.com`, validatedEmailHandler, ""},
	{`*@hacari.net`, validatedEmailHandler, ""},
	{`*@hacari.org`, validatedEmailHandler, ""},
	{`*@insiberia.net`, validatedEmailHandler, ""},
	{`*@insicuri.net`, validatedEmailHandler, ""},
	{`*@inventati.org`, validatedEmailHandler, ""},
	{`*@krutt.org`, validatedEmailHandler, ""},
	{`*@logorroici.org`, validatedEmailHandler, ""},
	{`*@mortemale.org`, validatedEmailHandler, ""},
	{`*@onenetbeyond.org`, validatedEmailHandler, ""},
	{`*@paranoici.org`, validatedEmailHandler, ""},
	{`*@privacyrequired.com`, validatedEmailHandler, ""},
	{`*@stronzi.org`, validatedEmailHandler, ""},
	{`*@subvertising.org`, validatedEmailHandler, ""},
}

func match(rule EmailRule, email string) bool {
	rgx := emailUserRegex + strings.Replace(rule.Pattern[1:], `.`, `\.`, -1)
	return regexp.MustCompilePOSIX(rgx).Match([]byte(email))
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if email == "" {
		templates.ExecuteTemplate(w, "index.html", allowedEmails)
	} else {
		for _, rule := range allowedEmails {
			if match(rule, email) {
				if err := rule.handler(email); err != nil {
					log.Printf("Error: %s", err)
					http.Error(w, err.Error(), http.StatusForbidden)
				} else {
					http.Redirect(w, r, "/success.html", http.StatusFound)
				}
				return
			}
		}
		http.Error(w, "disallowed email", http.StatusForbidden)
	}
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, r.URL.Path[1:], nil)
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: %s SECRETKEYFILE", os.Args[0])
	}
	var err error
	mac_key, err = ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", "user=tokenserver password=tokenpw dbname=tokendb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS blacklist (
		hash bytea not null primary key);`)
	if err != nil {
		log.Fatal("Cannot create table blacklist: ", err)
	}
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/success.html", staticHandler)
	panic(http.ListenAndServe(":80", nil))
}
