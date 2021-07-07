// SPDX-License-Identifier: MIT

package metafeed

import (
	"bytes"
	"fmt"

	"github.com/zeebo/bencode"
	"golang.org/x/crypto/ed25519"

	"github.com/ssb-ngi-pointer/go-metafeed/internal/sign"
	"go.mindeco.de/ssb-refs/tfk"
)

// SubSignContent uses the passed private key to sign the passed content after it was encoded.
// It then packs both fields as an array [content, signature].
// TODO: add hmac signing
func SubSignContent(pk ed25519.PrivateKey, content bencode.Marshaler) (bencode.RawMessage, error) {
	contentBytes, err := content.MarshalBencode()
	if err != nil {
		return nil, fmt.Errorf("SubSignContent: failed to encode content for signing: %w", err)
	}

	signedValue := []interface{}{
		bencode.RawMessage(contentBytes),
		sign.Create(contentBytes, pk, nil), // TODO: pass hmac secret
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

	verified := sign.Verify(arr[0], sigBytes, pubKey, nil) // TODO: pass hmac secret
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
