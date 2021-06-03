package metafeed

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/zeebo/bencode"
	"go.mindeco.de/encodedTime"
	refs "go.mindeco.de/ssb-refs"
	"golang.org/x/crypto/ed25519"
)

type Transfer struct {
	data bencode.RawMessage

	signature []byte

	payload *Payload
}

var (
	_ bencode.Marshaler   = (*Transfer)(nil)
	_ bencode.Unmarshaler = (*Transfer)(nil)
)

func (tr *Transfer) MarshalBencode() ([]byte, error) {
	return bencode.EncodeBytes([]interface{}{
		bencode.RawMessage(tr.data),
		tr.signature,
	})
}

func (tr *Transfer) UnmarshalBencode(input []byte) error {
	var raw []bencode.RawMessage

	err := bencode.NewDecoder(bytes.NewReader(input)).Decode(&raw)
	if err != nil {
		return fmt.Errorf("failed to decode raw transfer array: %w", err)
	}

	if n := len(raw); n != 2 {
		return fmt.Errorf("metafeed/transfer: expected two elemnts in the array, got %d", n)
	}

	// just take the data as is (that it's valid bencode was settled by the first decode pass)
	tr.data = raw[0]

	// make sure it's a valid byte string
	err = bencode.NewDecoder(bytes.NewReader(raw[1])).Decode(&tr.signature)
	if err != nil {
		return fmt.Errorf("metafeed/transfer: failed to decode signature portion: %w", err)
	}

	if n := len(tr.signature); n != ed25519.SignatureSize {
		return fmt.Errorf("metafeed/transfer: expected %d bytes of signture - only got %d", ed25519.SignatureSize, n)
	}

	return nil
}

// Verify returns true if the Message was signed by the author specified by the meta portion of the message
func (tr *Transfer) Verify(hmacKey *[32]byte) bool {
	if err := tr.getPayload(); err != nil {
		return false
	}
	pubKey := tr.payload.Author.PubKey()

	return ed25519.Verify(pubKey, tr.data, tr.signature)
}

func (tr *Transfer) Payload() (Payload, error) {
	if err := tr.getPayload(); err != nil {
		return Payload{}, err
	}
	return *tr.payload, nil
}

func (tr *Transfer) getPayload() error {
	if tr.payload != nil {
		return nil
	}
	var p Payload
	if err := p.UnmarshalBencode(tr.data); err != nil {
		return err
	}
	tr.payload = &p
	return nil
}

var _ refs.Message = (*Transfer)(nil)

func (tr *Transfer) Key() refs.MessageRef {

	bytes, err := tr.MarshalBencode()
	if err != nil {
		panic(err)
	}

	h := sha256.New()
	h.Write(bytes)

	msgKey, err := refs.NewMessageRefFromBytes(h.Sum(nil), refs.RefAlgoMessageMetaBencode)
	if err != nil {
		panic(err)
	}
	return msgKey
}

func (tr *Transfer) Seq() int64 {
	err := tr.getPayload()
	if err != nil {
		log.Println("gabbygrove/verify event decoding failed:", err)
		return -1
	}
	return int64(tr.payload.Sequence)
}

func (tr *Transfer) Author() refs.FeedRef {
	err := tr.getPayload()
	if err != nil {
		panic(err)
	}
	return tr.payload.Author
}

func (tr *Transfer) Previous() *refs.MessageRef {
	err := tr.getPayload()
	if err != nil {
		panic(err)
	}
	if tr.payload.Sequence == 1 {
		return nil
	}
	return &tr.payload.Previous
}

func (tr *Transfer) Received() time.Time {
	log.Println("received time is spoofed to claimed")
	return tr.Claimed()
}

func (tr *Transfer) Claimed() time.Time {
	err := tr.getPayload()
	if err != nil {
		panic(err)
	}
	return tr.payload.Timestamp
}

func (tr *Transfer) ContentBytes() []byte {
	return tr.data
}

// ValueContent returns a ssb.Value that can be represented as JSON.
// Note that it's signature is useless for verification in this form.
// Get the whole transfer message and use tr.Verify()
func (tr *Transfer) ValueContent() *refs.Value {
	err := tr.getPayload()
	if err != nil {
		panic(err)
	}
	var msg refs.Value
	if tr.payload.Sequence > 1 {
		msg.Previous = &tr.payload.Previous
	}

	msg.Author = tr.payload.Author
	msg.Sequence = int64(tr.payload.Sequence)
	msg.Hash = "metafeed-v1"
	msg.Signature = base64.StdEncoding.EncodeToString(tr.signature) + ".metafeed-v1.sig.ed25519"
	msg.Timestamp = encodedTime.Millisecs(tr.Claimed())

	// TODO: peek at first byte (tfk indicating box2 for instance)

	// switch tr.payload.Content.Type {
	// case ContentTypeArbitrary:
	// 	v, err := json.Marshal(tr.Content)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	msg.Content = json.RawMessage(v)
	// case ContentTypeJSON:
	// 	msg.Content = json.RawMessage(tr.Content)
	// }
	return &msg
}

func (tr *Transfer) ValueContentJSON() json.RawMessage {
	jsonB, err := json.Marshal(tr.ValueContent())
	if err != nil {
		panic(err.Error())
	}

	return jsonB
}
