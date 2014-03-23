package protocol

var ProfileFields = map[string]int32{
	"dename":   1,     // 32 bytes: ed25519 signing key
	"ssh":      22,    // first to two space-separated fields for .ssh/authorzed_keys
	"ssh-host": 21,    // a line for .ssh/known_hosts
	"email":    25,    // an email address
	"e-mail":   25,    // ^
	"smtp":     25,    // ^
	"dns":      25,    // a domain name
	"http":     80,    // a http:// or https:// url
	"web":      80,    // ^
	"pgp":      11371, // 20 bytes: an OpenPGP key fingerprint
	"gpg":      11371, // ^
	"xmpp":     5222,  // a XMPP address
	"jabber":   5222,  // ^
	"otr":      5223,  // 20 bytes: OTR fingerprint
}
