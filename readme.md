What `dename` is
================

Dename is a decentralized system that securely maps usernames to
profiles which can contain any information the user wishes. For example,
it can serve as a public key infrastructure, a store of electronic
business cards or as a domain name system. In this context, *secure*
means that everybody who looks up a name sees the same profile.

What it does
============

Let's say a friend of yours wishes to grant you write access to a `git`
repository on his server. However, as nobody other than the two of you
should be able to change the code, you decide to use `git` over `ssh`
with public-key authentication.

Everything seems fine, except that all ways of telling each other your
public keys seem to be lacking something. Sending them over email or
other conventional online channel would be susceptible to attack --
anybody could send an email from your address to your friend, asking to
add their key instead. Printing out the keys and handing them to each
other the next time you meet would definitely establish their
authenticity, but typing them in again would be tedious. Handing over
hashes of keys on paper, downloading the keys separately and verifying
the hashes is also a fine strategy, but neither of you is well-versed in
cryptography and you are rightfully doubting whether this convoluted
strategy would be secure, and even if it would, it would still be
inconvenient.

This is where `dename` comes in. You can upload your public key to your
`dename` profile, tell the friend your username and he can look it up.
Here is how:

    dnmgr init # enter and verify your email, pick an username
    dnmgr set ssh "$(cut -d' ' -f-2 ~/.ssh/id_rsa.pub)"

After you have told your friend your username, he will look up your
`ssh` key:

    dnmlookup your_username ssh

Installation
------------

Too simple to be true? For now, yes -- the description above omitted the
step of installing `dename`! We hope it will be available in Your
Favorite Distribution's package manager in the future, but for now, you
have to install from source. The following is a sketch of how you might
go about it on a Debian-based system, you may need to do some steps
differently:

    sudo apt-get install golang-go
    mkdir -p ~/.go/bin
    echo 'export GOPATH=~/.go; export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    . <(tail -1  ~/.bashrc)
    go get github.com/andres-erbsen/dename/dnmgr github.com/andres-erbsen/dename/dnmlookup

How `dename` works
==================

The main goal of dename is to allow human-readable identifiers (names)
to be securely and unambiguously resolved to public keys, thus squaring
the [Zooko's triangle](http://en.wikipedia.org/wiki/Zooko's\_triangle)
and making public-key cryptography easier to use. To achieve this, a
universally known (but not trusted) group of servers continuously runs a
program that maintains the name-profile mapping. Clients can contact any
of the servers to look up names and be assured that unless *all* servers
are broken or colluding against them, the result is correct. It is in
everybody's interest to have very different parties run the servers.

Names are allocated to users on a first-come first-serve basis.
Specifically, any user can at any time contact a server and ask them to
"assign name N to public key P". Rate-limiting and spam prevention is
the responsibility of any individual server: currently, a non-profit
email address is required for registration. The bearer of a name can
transfer the name to another key (their own or somebody else's) by
signing with the secret key associated with the name the message
"transfer name N to public key P'" and sending it to a server. This is
to allow for key revocations/upgrades and (domain) name sales.

When a server receives a request, it first verifies that it is valid
(the name is available / the transfer is signed by the bearer of the
name) and then encrypts it and forwards it to other servers. With some
regularity, all servers commit to the requests they have has forwarded,
reveal the keys to them, handle all requets they have seen, and sign the
new name assignments. This is done in lockstep; the changes only appear
to clients after all servers have ratified them.

To speed up updating and signing the name assignments, the names-profile
mapping is stored in a radix tree with Merkle hashing. That is, every
radix tree node also contains the hash of its children. This way the
hash of the root node summarizes the state of all the names and can be
signed instead of the possibly large table of all names. When a client
asks for the profile associated with a name, the server also returns all
children of the nodes on the path from the root to the node storing that
name and the corresponding profile. The client can use the hashes of
these nodes to compute the root and be assured that the name,profile
pair is indeed present in that tree. After verifying the servers'
signatures on that root, the client can be assured that if at least
least one server is correct then the profile he saw is the same that
everybody else sees.

Features to come
================

Using a Merkle tree for the mapping enables other useful features: -
Clients with accurate clocks can require the root timestamp to be within
some interval of the current time. - Clients can compare the roots they
saw to detect server collusion. For example, if there are two different
roots for the same round number, on of them must be the result of
wrongdoing on the part of servers. - If one wishes to verify that the
servers are operating correctly, they do not need to store the whole
mapping -- the root can be updated based on the requests without knowing
about significantly more names than those who were transferred. - The
verifier can also serve as a coherent cache

Use cases
=========

How to use `dename` for distributing ssh keys is described above. I
patched [pond](https://pond.imperialviolet.org) (an asynchronous
messaging system) to support looking up keys from dename as an
introduction mechanism. The code is
[here](https://github.com/andres-erbsen/pond), you are welcome to play
with it.

Some other obvious candidates are synchronous messaging (OTR), document
signing, logging in to websites, ssh host authentication (trivial, see
`doc/dnmgr.txt`), .onion/cjnds addressing, tying TLS keys to domain
names, and online voting.

Related work
============

<http://www.aaronsw.com/weblog/squarezooko> proposes a design to solve
the same problem. Namecoin exists and (sort-of) works. Sadly, these
systems are bound to use enormous amounts of hashing power to stay
secure, and even then there remains the risk of 51% of the power falling
into bad hands. The described cost of this will also most likely be
passed on to users, this increasing the adaption barrier. There also are
Kerberos, the CA system and other centralized systems that solve the
same problem, but in a very different setting -- they assume that there
is an universally trusted party.

Open questions
==============

-   How to better prevent name hoarding / spam?
-   How can different applications "gossip" about the roots to ensure
    that users have a consistent view of the world?

Contribute
==========

Use it and report back!
-----------------------

We would love to hear how `dename` worked for you, and even if it really
didn't you should let us know so that we can fix the issue, saving
somebody else the trouble. Technical and non-technical feedback are
equally appreciated. To get in touch with us, use the Github issues link
on this page or [contact us] by email.

Code for `dename`
-----------------

There is a lot to be done: the issues page and "Features to come" here
should give some idea of what I would like to see happen to this
project.

Integrate dename with `$YOUR_FAVORITE_APPLICATION`
--------------------------------------------------

`dename` is designed to be easy to integrated into other applications
for a seamless user experience. See "use cases" above for ideas and
[pond-dename](https://github.com/andres-erbsen/pond) for an example. How
long until there is an OTR-only chat-client that provides usable
security?

Run a server
------------

The security of `dename` depends on having a diverse set of verification
servers. Right now, we have two machines that might even be in the same
rack -- this is very much a non-ideal situation. If you are not at MIT,
have a machine to spare (it does not have to be fancy) and
`doc/server-operators-guide.txt` does not seem gibberish to you,
[contact us] and let's talk!

[contact us](mailto:dename@mit.edu)
