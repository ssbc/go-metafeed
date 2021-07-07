// SPDX-License-Identifier: MIT

// Package sign implements the domain seperated signature creation and verification used in bendybutt powered metafeeds.
package sign

import (
	"bytes"
	"crypto/ed25519"

	"golang.org/x/crypto/nacl/auth"
)

var (
	// this gets prepended to the sign()/verify() input and achives domain seperation
	inputPrefix = []byte("metafeeds")

	// these two bytes are TFK/BFE identifiers to clerify that the bytes are a signature
	outputPrefix = []byte{0x04, 0x00}
)

func Create(input []byte, key ed25519.PrivateKey, hmacSec *[32]byte) []byte {
	toSign := append(inputPrefix, input...)
	if hmacSec != nil {
		mac := auth.Sum(toSign, hmacSec)
		toSign = mac[:]
	}

	sig := ed25519.Sign(key, toSign)
	return append(outputPrefix, sig...)
}

func Verify(data, signature []byte, pubKey ed25519.PublicKey, hmacSec *[32]byte) bool {
	if !bytes.HasPrefix(signature, outputPrefix) {
		return false
	}

	signedMessage := append(inputPrefix, data...)
	if hmacSec != nil {
		mac := auth.Sum(signedMessage, hmacSec)
		signedMessage = mac[:]
	}

	justTheSig := bytes.TrimPrefix(signature, outputPrefix)
	return ed25519.Verify(pubKey, signedMessage, justTheSig)
}
