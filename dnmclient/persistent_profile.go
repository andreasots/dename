package dnmclient

import (
	"code.google.com/p/goprotobuf/proto"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/agl/ed25519"
	"github.com/andres-erbsen/dename/protocol"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"syscall"
)

var ErrExists = errors.New("A profile with this name already exists")
var ErrNameMismatch = errors.New("Corrupt profile directory: name mismatch")
var DefaultProfilePath = filepath.Join(os.Getenv("HOME"), ".config", "dename")

type PersistentProfile struct {
	Directory, Name string
	Profile         *protocol.Identity
	SecretKey       *[ed25519.PrivateKeySize]byte
	profileFile     *os.File
}

var errProfileNotFound = errors.New("Could not find dename profile")

func OpenProfile(name string) (p *PersistentProfile, err error) {
	p, err = OpenProfile(filepath.Join(DefaultProfilePath, name))
	if err != nil {
		return
	}
	if p.Name != name {
		return nil, ErrNameMismatch
	}
	return
}

func OpenProfilePath(path string) (p *PersistentProfile, err error) {
	profilePath := filepath.Join(path, "profile")
	profileFile, err := os.OpenFile(profilePath, os.O_RDWR, 0600)
	if err != nil {
		return
	}
	err = syscall.Flock(int(profileFile.Fd()), syscall.LOCK_EX)
	if err != nil {
		log.Printf("Failed to lock \"%s\": ", profilePath, err)
	}
	profile_bs, err := ioutil.ReadAll(profileFile)
	if err != nil {
		return
	}
	profile := new(protocol.Identity)
	if err = proto.Unmarshal(profile_bs, profile); err != nil {
		return
	}
	skFile, err := os.Open(filepath.Join(path, "sk"))
	if err != nil {
		return
	}
	sk := new([ed25519.PrivateKeySize]byte)
	_, err = io.ReadFull(skFile, sk[:])
	if err != nil {
		return
	}
	name_bs, err := ioutil.ReadFile(filepath.Join(path, "name"))
	if err != nil {
		return
	}
	p = &PersistentProfile{
		Directory:   path,
		SecretKey:   sk,
		Name:        string(name_bs),
		Profile:     profile,
		profileFile: profileFile,
	}
	return
}

func CreateProfile(name string) (p *PersistentProfile, err error) {
	return CreateProfilePath(filepath.Join(DefaultProfilePath, name), name)
}

func CreateProfilePath(path, name string) (p *PersistentProfile, err error) {
	skPath := filepath.Join(path, "sk")
	if _, err := os.Stat(skPath); err == nil {
		return nil, ErrExists
	}
	if err = os.MkdirAll(path, 0700); err != nil {
		return
	}
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	profile := &protocol.Identity{Dename: &protocol.PublicKey{Ed25519: pk[:]}}
	profile_bs, err := proto.Marshal(profile)
	if err != nil {
		panic(err)
	}
	profilePath := filepath.Join(path, "profile")
	profileFile, err := os.OpenFile(profilePath,
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	err = syscall.Flock(int(profileFile.Fd()), syscall.LOCK_EX)
	if err != nil {
		log.Printf("Failed to lock \"%s\": ", profilePath, err)
	}
	if err = ioutil.WriteFile(skPath, sk[:], 0600); err != nil {
		return
	}
	err = ioutil.WriteFile(filepath.Join(path, "name"), []byte(name), 0600)
	if err != nil {
		return
	}
	if _, err = profileFile.Write(profile_bs); err != nil {
		return
	}
	p = &PersistentProfile{
		Directory:   path,
		SecretKey:   sk,
		Name:        name,
		Profile:     profile,
		profileFile: profileFile,
	}
	return
}

func (p *PersistentProfile) Close() error {
	return p.profileFile.Close()
}

func (p *PersistentProfile) Set(field int32, value []byte) (err error) {
	err = p.Profile.Set(field, value)
	if err != nil {
		return
	}
	profile_bs, err := proto.Marshal(p.Profile)
	if err != nil {
		panic(err)
	}
	err = p.profileFile.Truncate(0)
	if err != nil {
		return
	}
	_, err = p.profileFile.Seek(0, 0)
	if err != nil {
		return
	}
	if _, err = p.profileFile.Write(profile_bs); err != nil {
		return
	}
	return nil
}

func (dnmc *DenameClient) RegisterPersistent(p *PersistentProfile,
	regtoken_b64 string) error {
	sk := (*protocol.Ed25519Secret)(p.SecretKey)
	fmt.Printf("register:\n%x\n%v\n%v\n%v\n", sk, p.Profile, p.Name, regtoken_b64)
	return dnmc.Register(sk, p.Profile, p.Name, regtoken_b64)
}

func (dnmc *DenameClient) Push(p *PersistentProfile) error {
	sk := (*protocol.Ed25519Secret)(p.SecretKey)
	return dnmc.Modify(sk, p.Name, p.Profile)
}
