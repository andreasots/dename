package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"github.com/andres-erbsen/dename/pgutil"
	dename "github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/sgp"
	"github.com/mqu/openldap"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"regexp"
	"strings"
	txt_template "text/template"
)

var templates = template.Must(template.ParseFiles("index.html", "success.html", "error.html"))
var txt_templates = txt_template.Must(txt_template.ParseFiles("body.txt"))
var our_sk sgp.SecretKey
var db *sql.DB
var errQuota = errors.New("This address has already been sent a registration token.")

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
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		return err
	}
	ticket := our_sk.SignAmbiguous(nonce[:], dename.SIGN_TAG_PERSONATICKET)
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
	ticket_b64 := base64.StdEncoding.EncodeToString(ticket)
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
	{`.*@mit\.edu`, mitKerberosHandler, "MIT Kerberos accounts"},
	{`.*@college\.harvard\.edu`, validatedEmailHandler, ""},
	{`.*@fsfe\.org`, validatedEmailHandler, ""},
	{`.*@member\.fsf\.org `, validatedEmailHandler, ""},
	{`.*@eesti\.ee`, validatedEmailHandler, ""},
	{`.*@riseup\.net`, validatedEmailHandler, ""},
	{`.*@anche\.no`, validatedEmailHandler, ""},
	{`.*@autistiche\.org`, validatedEmailHandler, ""},
	{`.*@autistici\.org`, validatedEmailHandler, ""},
	{`.*@autoproduzioni\.net`, validatedEmailHandler, ""},
	{`.*@bastardi\.net`, validatedEmailHandler, ""},
	{`.*@bruttocarattere\.org`, validatedEmailHandler, ""},
	{`.*@canaglie\.net`, validatedEmailHandler, ""},
	{`.*@canaglie\.org`, validatedEmailHandler, ""},
	{`.*@cryptolab\.net`, validatedEmailHandler, ""},
	{`.*@distruzione\.org`, validatedEmailHandler, ""},
	{`.*@grrlz\.net`, validatedEmailHandler, ""},
	{`.*@hacari\.com`, validatedEmailHandler, ""},
	{`.*@hacari\.net`, validatedEmailHandler, ""},
	{`.*@hacari\.org`, validatedEmailHandler, ""},
	{`.*@insiberia\.net`, validatedEmailHandler, ""},
	{`.*@insicuri\.net`, validatedEmailHandler, ""},
	{`.*@inventati\.org`, validatedEmailHandler, ""},
	{`.*@krutt\.org`, validatedEmailHandler, ""},
	{`.*@logorroici\.org`, validatedEmailHandler, ""},
	{`.*@mortemale\.org`, validatedEmailHandler, ""},
	{`.*@onenetbeyond\.org`, validatedEmailHandler, ""},
	{`.*@paranoici\.org`, validatedEmailHandler, ""},
	{`.*@privacyrequired\.com`, validatedEmailHandler, ""},
	{`.*@stronzi\.org`, validatedEmailHandler, ""},
	{`.*@subvertising\.org`, validatedEmailHandler, ""},
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if email == "" {
		templates.ExecuteTemplate(w, "index.html", allowedEmails)
	} else {
		for _, rule := range allowedEmails {
			if regexp.MustCompilePOSIX(rule.Pattern).Match([]byte(email)) {
				if err := rule.handler(email); err != nil {
					log.Printf("Error: %s", err)
					templates.ExecuteTemplate(w, "error.html", err)
				} else {
					http.Redirect(w, r, "/success.html", http.StatusFound)
				}
				return
			}
		}
		http.Redirect(w, r, "/index.html", http.StatusFound)
	}
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, r.URL.Path[1:], nil)
}

func main() {
	var err error
	our_sk, err = sgp.LoadSecretKeyFromFile("SECRETKEY")
	if err != nil {
		log.Fatal(err)
	}

	// sudo sudo -u postgres createuser -P -S -D -R ticketer # ticketpw \n ticketpw
	// sudo sudo -u postgres createdb ticketing
	// reset: echo "TRUNCATE blacklist;" | sudo sudo -u postgres psql
	db, err = sql.Open("postgres", "user=ticketer password=ticketpw dbname=ticketing sslmode=disable")
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
