package metafeed_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/ssb-ngi-pointer/go-metafeed"
	"github.com/ssb-ngi-pointer/go-metafeed/metakeys"
	"github.com/ssb-ngi-pointer/go-metafeed/metamngmt"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/bencode"
	refs "go.mindeco.de/ssb-refs"
)

func TestEncodeManagmentMessage(t *testing.T) {
	r := require.New(t)

	// create a new meta feed
	metaSeed, err := metakeys.GenerateSeed()
	r.NoError(err)

	metaKey, err := metakeys.DeriveFromSeed(metaSeed, metakeys.RootLabel)
	r.NoError(err)

	// create seed for first subfeed
	var nonce = make([]byte, 32)
	io.ReadFull(rand.Reader, nonce)

	seededLabel := "ssb-meta-feed-seed-v1:" + base64.StdEncoding.EncodeToString(nonce)
	subKey, err := metakeys.DeriveFromSeed(metaSeed, seededLabel)
	r.NoError(err)

	// create encoder for meta-feed entries
	enc := metafeed.NewEncoder(metaKey.Pair.Secret)

	addSubFeedMsg := metamngmt.NewAddMessage(metaKey.Feed, subKey.Feed, "boring-butt", "experiment", nonce)
	addSubFeedMsg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// now sign the add content
	signedAddContent, err := metafeed.SubSignContent(subKey.Pair.Secret, addSubFeedMsg)
	r.NoError(err)

	var tv []bencode.RawMessage
	err = bencode.DecodeBytes(signedAddContent, &tv)
	r.NoError(err)

	// strip of the length prefix to get the pure bytes
	var sigBytes []byte
	err = bencode.NewDecoder(bytes.NewReader(tv[1])).Decode(&sigBytes)
	r.NoError(err)

	// manually check the signature
	verified := ed25519.Verify(subKey.Pair.Public, tv[0], sigBytes)
	r.True(verified)

	fmt.Fprintln(os.Stderr, "encoded content:")
	fmt.Fprintln(os.Stderr, hex.Dump(tv[0]))

	var addMsg metamngmt.Add
	err = addMsg.UnmarshalBencode(tv[0])
	r.NoError(err)

	// now encode the message onto the feed
	signedAddMessage, msgKey, err := enc.Encode(1, refs.MessageRef{}, signedAddContent)
	r.NoError(err)

	t.Log(msgKey.Ref())

	valid := signedAddMessage.Verify(nil)
	r.True(valid)

	encodedAdd, err := signedAddMessage.MarshalBencode()
	r.NoError(err)

	fmt.Fprintln(os.Stderr, "encoded entry:")
	fmt.Fprintln(os.Stderr, hex.Dump(encodedAdd))
}
