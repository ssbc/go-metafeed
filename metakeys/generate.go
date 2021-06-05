package metakeys

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	refs "go.mindeco.de/ssb-refs"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

const (
	SeedLength = 64

	RootLabel = "ssb-meta-feeds-v1:metafeed"
)

func GenerateSeed() ([]byte, error) {
	sbuf := make([]byte, SeedLength)
	_, err := io.ReadFull(rand.Reader, sbuf)
	return sbuf, err
}

func DeriveFromSeed(seed []byte, label string) (KeyPair, error) {
	// TODO: confirm with @arj
	// if n := len(seed); n != SeedLength {
	// 	return KeyPair{}, fmt.Errorf("metakeys: seed has wrong length: %d", n)
	// }

	if len(label) == 0 {
		return KeyPair{}, fmt.Errorf("metakeys: label can't be empty")
	}

	out := make([]byte, ed25519.SeedSize)
	r := hkdf.New(sha256.New, seed, nil, []byte(label))
	_, err := r.Read(out)
	if err != nil {
		return KeyPair{}, fmt.Errorf("metakeys: error deriving key: %w", err)
	}

	var ekp EdKeyPair
	ekp.Public, ekp.Secret, err = ed25519.GenerateKey(bytes.NewReader(out))
	if err != nil {
		return KeyPair{}, fmt.Errorf("metakeys: failed to generate keypair from derived data: %w", err)
	}

	feed, err := refs.NewFeedRefFromBytes(ekp.Public, refs.RefAlgoFeedMetaBencode)
	return KeyPair{
		Feed: feed,
		Pair: ekp,
	}, err
}

type KeyPair struct {
	Feed refs.FeedRef
	Pair EdKeyPair
}

type EdKeyPair struct {
	Public ed25519.PublicKey
	Secret ed25519.PrivateKey
}
