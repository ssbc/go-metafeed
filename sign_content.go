package metafeed

import (
	"bytes"
	"fmt"

	"github.com/zeebo/bencode"
	"golang.org/x/crypto/ed25519"
)

func SubSignContent(pk ed25519.PrivateKey, content bencode.Marshaler) (bencode.RawMessage, error) {

	contentBytes, err := content.MarshalBencode()
	if err != nil {
		return nil, fmt.Errorf("SubSignContent: failed to encode content for signing: %w", err)
	}

	sig := ed25519.Sign(pk, contentBytes)

	signedValue := []interface{}{
		bencode.RawMessage(contentBytes),
		sig,
	}

	contentAndSig, err := bencode.EncodeBytes(signedValue)
	if err != nil {
		return nil, fmt.Errorf("SubSignContent: failed to put signed value into an array: %w", err)
	}

	return contentAndSig, nil
}

// TODO: we might not have the public key before we decode this. Get it from the rawMessage
func VerifySubSignedContent(pub ed25519.PublicKey, rawMessage []byte, content bencode.Unmarshaler) error {

	// make sure it's an array
	var arr []bencode.RawMessage
	err := bencode.DecodeBytes(rawMessage, &arr)
	if err != nil {
		return err
	}

	// decode the entry 2nd to strip of the length prefix to get the pure bytes
	var sigBytes []byte
	err = bencode.NewDecoder(bytes.NewReader(arr[1])).Decode(&sigBytes)
	if err != nil {
		return err
	}

	// manually check the signature againt entry 1
	verified := ed25519.Verify(pub, arr[0], sigBytes)
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
