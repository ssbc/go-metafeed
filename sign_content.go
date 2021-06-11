// SPDX-License-Identifier: MIT

package metafeed

import (
	"bytes"
	"fmt"

	"github.com/zeebo/bencode"
	"go.mindeco.de/ssb-refs/tfk"
	"golang.org/x/crypto/ed25519"
)

var (
	// this gets prepended to the sign()/verify() input and achives domain seperation
	signatureInputPrefix = []byte("metafeeds")

	// these two bytes are TFK/BFE identifiers to clerify that the bytes are a signature
	signatureOutputPrefix = []byte{0x04, 0x00}
)

// SubSignContent uses the passed private key to sign the passed content after it was encoded.
// It then packs both fields as an array [content, signature].
// TODO: add hmac signing
func SubSignContent(pk ed25519.PrivateKey, content bencode.Marshaler) (bencode.RawMessage, error) {
	contentBytes, err := content.MarshalBencode()
	if err != nil {
		return nil, fmt.Errorf("SubSignContent: failed to encode content for signing: %w", err)
	}

	signedMessage := append(signatureInputPrefix, contentBytes...)
	sig := ed25519.Sign(pk, signedMessage)

	signedValue := []interface{}{
		bencode.RawMessage(contentBytes),
		append(signatureOutputPrefix, sig...),
	}

	contentAndSig, err := bencode.EncodeBytes(signedValue)
	if err != nil {
		return nil, fmt.Errorf("SubSignContent: failed to put signed value into an array: %w", err)
	}

	return contentAndSig, nil
}

// VerifySubSignedContent expects an array of [content, signature] where 'content' needs to contain
// a 'subfeed' field which contains the tfk encoded publickey to verify the signature.
// TODO: add hmac signing
func VerifySubSignedContent(rawMessage []byte, content bencode.Unmarshaler) error {
	// make sure it's an array
	var arr []bencode.RawMessage
	err := bencode.DecodeBytes(rawMessage, &arr)
	if err != nil {
		return err
	}

	if n := len(arr); n != 2 {
		return fmt.Errorf("VerifySubSignedContent: expected two elements but got %d", n)
	}

	var justSubFeedBytes struct {
		SubFeed []byte `bencode:"subfeed"`
	}
	err = bencode.NewDecoder(bytes.NewReader(arr[0])).Decode(&justSubFeedBytes)
	if err != nil {
		return err
	}

	var subFeed tfk.Feed
	err = subFeed.UnmarshalBinary(justSubFeedBytes.SubFeed)
	if err != nil {
		return err
	}

	f, err := subFeed.Feed()
	if err != nil {
		return err
	}

	pubKey := f.PubKey()

	// decode the entry 2nd to strip of the length prefix to get the pure bytes
	var sigBytes []byte
	err = bencode.NewDecoder(bytes.NewReader(arr[1])).Decode(&sigBytes)
	if err != nil {
		return err
	}

	if !bytes.HasPrefix(sigBytes, signatureOutputPrefix) {
		return fmt.Errorf("VerifySubSignedContent: expected signature prefix")
	}

	// manually check the signature againt entry 1
	signedMessage := append(signatureInputPrefix, arr[0]...)
	verified := ed25519.Verify(pubKey, signedMessage, sigBytes[2:])
	if !verified {
		return fmt.Errorf("VerifySubSignedContent: signature failed")
	}

	// make sure it's an add message
	err = content.UnmarshalBencode(arr[0])
	if err != nil {
		return err
	}

	return nil
}
