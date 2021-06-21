// SPDX-License-Identifier: MIT

package metakeys

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
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

func DeriveFromSeed(seed []byte, label string, algo refs.RefAlgo) (KeyPair, error) {
	// TODO: confirm with @arj
	// if n := len(seed); n != SeedLength {
	// 	return KeyPair{}, fmt.Errorf("metakeys: seed has wrong length: %d", n)
	// }

	if len(label) == 0 {
		return KeyPair{}, fmt.Errorf("metakeys: label can't be empty")
	}

	derived := make([]byte, ed25519.SeedSize)
	r := hkdf.New(sha256.New, seed, nil, []byte(label))
	_, err := r.Read(derived)
	if err != nil {
		return KeyPair{}, fmt.Errorf("metakeys: error deriving key: %w", err)
	}

	public, secret, err := ed25519.GenerateKey(bytes.NewReader(derived))
	if err != nil {
		return KeyPair{}, fmt.Errorf("metakeys: failed to generate keypair from derived data: %w", err)
	}

	feed, err := refs.NewFeedRefFromBytes(public, algo)
	return KeyPair{
		Seed:       seed,
		Feed:       feed,
		PrivateKey: secret,
	}, err
}

type KeyPair struct {
	Seed []byte

	Feed       refs.FeedRef
	PrivateKey ed25519.PrivateKey
}

func (kp KeyPair) ID() refs.FeedRef {
	return kp.Feed
}

func (kp KeyPair) Secret() ed25519.PrivateKey {
	return kp.PrivateKey
}

var (
	_ json.Marshaler   = (*KeyPair)(nil)
	_ json.Unmarshaler = (*KeyPair)(nil)
)

type typedKeyPair struct {
	Type       string
	Seed       []byte
	Feed       refs.FeedRef
	PrivateKey ed25519.PrivateKey
}

func (kp KeyPair) MarshalJSON() ([]byte, error) {
	var tkp = typedKeyPair{"bendy-butt", kp.Seed, kp.Feed, kp.PrivateKey}
	return json.Marshal(tkp)
}

func (kp *KeyPair) UnmarshalJSON(input []byte) error {
	var newKp typedKeyPair
	err := json.Unmarshal(input, &newKp)
	if err != nil {
		return err
	}

	if newKp.Feed.Algo() != refs.RefAlgoFeedBendyButt {
		return fmt.Errorf("input data is not a bendybutt metafeed keypair")
	}

	if n := len(newKp.PrivateKey); n != ed25519.PrivateKeySize {
		return fmt.Errorf("private key has the wrong size: %d", n)
	}

	if n := len(newKp.Seed); n != SeedLength {
		return fmt.Errorf("seed data has the wrong size: %d", n)
	}

	// copy values
	kp.Feed = newKp.Feed
	kp.Seed = newKp.Seed
	kp.PrivateKey = newKp.PrivateKey

	return nil
}
