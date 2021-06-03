package metafeed

import (
	"fmt"
	"math"
	"time"

	"github.com/zeebo/bencode"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/auth"

	refs "go.mindeco.de/ssb-refs"
)

func NewEncoder(author ed25519.PrivateKey) *Encoder {
	pe := &Encoder{}
	pe.privKey = author
	return pe
}

type Encoder struct {
	privKey ed25519.PrivateKey

	hmacSecret   *[32]byte
	setTimestamp bool
}

func (e *Encoder) WithNowTimestamps(yes bool) {
	e.setTimestamp = yes
}

func (e *Encoder) WithHMAC(in []byte) error {
	var k [32]byte
	n := copy(k[:], in)
	if n != 32 {
		return fmt.Errorf("hmac key to short: %d", n)
	}
	e.hmacSecret = &k
	return nil
}

// for testable timestamps, so that now can be reset in the tests
var now = time.Now

func (e *Encoder) Encode(sequence int32, prev refs.MessageRef, val interface{}) (*Transfer, refs.MessageRef, error) {
	var (
		err  error
		next Payload

		pubKeyBytes = []byte(e.privKey.Public().(ed25519.PublicKey))
	)

	next.Author, err = refs.NewFeedRefFromBytes(pubKeyBytes, refs.RefAlgoFeedMetaBencode)
	if err != nil {
		return nil, refs.MessageRef{}, err
	}

	if sequence > math.MaxInt32 {
		return nil, refs.MessageRef{}, fmt.Errorf("metafeed: sequence limit reached. can't publish more then %d entries", math.MaxInt32)
	}
	next.Sequence = int(sequence)

	next.Previous = prev

	if e.setTimestamp {
		next.Timestamp = now()
	}

	next.Content, err = bencode.EncodeBytes(val)
	if err != nil {
		return nil, refs.MessageRef{}, fmt.Errorf("metafeed: failed to encode value: %w", err)
	}

	nextEncoded, err := next.MarshalBencode()
	if err != nil {
		return nil, refs.MessageRef{}, fmt.Errorf("metafeed: failed to encode next entry: %w", err)
	}

	toSign := nextEncoded
	if e.hmacSecret != nil {
		mac := auth.Sum(nextEncoded, e.hmacSecret)
		toSign = mac[:]
	}

	var tr Transfer
	tr.data = nextEncoded
	tr.signature = ed25519.Sign(e.privKey, toSign)

	return &tr, tr.Key(), nil
}

func refFromPubKey(pk ed25519.PublicKey) (refs.FeedRef, error) {
	if len(pk) != ed25519.PublicKeySize {
		return refs.FeedRef{}, fmt.Errorf("invalid public key")
	}
	return refs.NewFeedRefFromBytes(pk, refs.RefAlgoFeedMetaBencode)
}
