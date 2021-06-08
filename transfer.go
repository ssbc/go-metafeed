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

// Message is used to create the (un)marshal a message to and from bencode while also acting as refs.Message for the rest of the ssb system.
type Message struct {
	data bencode.RawMessage

	signature []byte

	payload *Payload
}

var (
	_ bencode.Marshaler   = (*Message)(nil)
	_ bencode.Unmarshaler = (*Message)(nil)
)

// MarshalBencode turns data and signature into an bencode array [content, signature]
func (tr *Message) MarshalBencode() ([]byte, error) {
	return bencode.EncodeBytes([]interface{}{
		tr.data,
		tr.signature,
	})
}

// UnmarshalBencode expects a benocded array of [content, signature]
func (tr *Message) UnmarshalBencode(input []byte) error {
	var raw []bencode.RawMessage

	err := bencode.NewDecoder(bytes.NewReader(input)).Decode(&raw)
	if err != nil {
		return fmt.Errorf("failed to decode raw Message array: %w", err)
	}

	if n := len(raw); n != 2 {
		return fmt.Errorf("metafeed/Message: expected two elemnts in the array, got %d", n)
	}

	// just take the data as is (that it's valid bencode was settled by the first decode pass)
	tr.data = raw[0]

	// make sure it's a valid byte string
	err = bencode.NewDecoder(bytes.NewReader(raw[1])).Decode(&tr.signature)
	if err != nil {
		return fmt.Errorf("metafeed/Message: failed to decode signature portion: %w", err)
	}

	if n := len(tr.signature); n != ed25519.SignatureSize+2 {
		return fmt.Errorf("metafeed/Message: expected %d bytes of signture - only got %d", ed25519.SignatureSize+2, n)
	}

	return nil
}

// Verify returns true if the Message was signed by the author specified by the meta portion of the message
func (tr *Message) Verify(hmacKey *[32]byte) bool {
	if err := tr.getPayload(); err != nil {
		return false
	}
	pubKey := tr.payload.Author.PubKey()

	if !bytes.HasPrefix(tr.signature, signatureOutputPrefix) {
		return false
	}

	signedMessage := append(signatureInputPrefix, tr.data...)
	return ed25519.Verify(pubKey, signedMessage, tr.signature[2:])
}

// Payload returns the message payload inside the data portion of the Message object.
func (tr *Message) Payload() (Payload, error) {
	if err := tr.getPayload(); err != nil {
		return Payload{}, err
	}
	return *tr.payload, nil
}

func (tr *Message) getPayload() error {
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

// go-ssb compatability

var _ refs.Message = (*Message)(nil)

// Key returns the hash reference of the message
func (tr *Message) Key() refs.MessageRef {

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

// Seq returns the sequence of th message
func (tr *Message) Seq() int64 {
	err := tr.getPayload()
	if err != nil {
		log.Println("gabbygrove/verify event decoding failed:", err)
		return -1
	}
	return int64(tr.payload.Sequence)
}

// Author returns the author who signed the message
func (tr *Message) Author() refs.FeedRef {
	err := tr.getPayload()
	if err != nil {
		panic(err)
	}
	return tr.payload.Author
}

// Previous return nil for the first message and otherwise the hash reference of the previous message
func (tr *Message) Previous() *refs.MessageRef {
	err := tr.getPayload()
	if err != nil {
		panic(err)
	}
	if tr.payload.Sequence == 1 {
		return nil
	}
	return &tr.payload.Previous
}

// Received needs to be repalced by the database (this spoofs it as the calimed timestamp)
func (tr *Message) Received() time.Time {
	log.Println("received time is spoofed to claimed")
	return tr.Claimed()
}

// Claimed returns the time the message claims as it's timestamp
func (tr *Message) Claimed() time.Time {
	err := tr.getPayload()
	if err != nil {
		panic(err)
	}
	return tr.payload.Timestamp
}

// ContentBytes returns the pure bencoded content portion of the message
func (tr *Message) ContentBytes() []byte {
	return tr.data
}

// ValueContent returns a ssb.Value that can be represented as JSON.
// Note that it's signature is useless for verification in this form.
// Get the whole Message message and use tr.Verify()
func (tr *Message) ValueContent() *refs.Value {
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

	var helperMap map[string]interface{}
	bencode.NewDecoder(bytes.NewReader(tr.data)).Decode(&helperMap)

	msg.Content, err = json.Marshal(helperMap)
	if err != nil {
		panic(err)
	}

	return &msg
}

// ValueContentJSON encodes the Message into JSON like a normal SSB message.
func (tr *Message) ValueContentJSON() json.RawMessage {
	jsonB, err := json.Marshal(tr.ValueContent())
	if err != nil {
		panic(err.Error())
	}

	return jsonB
}
