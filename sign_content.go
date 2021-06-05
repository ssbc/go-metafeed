package metafeed

import (
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
