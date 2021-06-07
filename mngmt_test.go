package metafeed

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ssb-ngi-pointer/go-metafeed/metakeys"
	"github.com/ssb-ngi-pointer/go-metafeed/metamngmt"
	"github.com/stretchr/testify/require"
	refs "go.mindeco.de/ssb-refs"
)

func TestEncodeManagmentMessage(t *testing.T) {
	r := require.New(t)

	metaSeed := bytes.Repeat([]byte("sec0"), 8)

	// create a new meta feed
	// metaSeed, err := metakeys.GenerateSeed()
	// r.NoError(err)

	metaKey, err := metakeys.DeriveFromSeed(metaSeed, metakeys.RootLabel)
	r.NoError(err)

	// create encoder for meta-feed entries
	enc := NewEncoder(metaKey.Pair.Secret)

	// fake timestamp
	enc.WithNowTimestamps(true)
	now = func() time.Time {
		return time.Unix(0, 0)
	}

	// create seed for first subfeed
	var nonce = bytes.Repeat([]byte{0xff}, 32)

	// var nonce = make([]byte, 32)
	// io.ReadFull(rand.Reader, nonce)

	seededLabel := "ssb-meta-feed-seed-v1:" + base64.StdEncoding.EncodeToString(nonce)
	subKey, err := metakeys.DeriveFromSeed(metaSeed, seededLabel)
	r.NoError(err)

	// Message 1: create add message
	addSubFeedMsg := metamngmt.NewAddMessage(metaKey.Feed, subKey.Feed, "boring-butt", "experiment", nonce)
	addSubFeedMsg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// now sign the add content
	signedAddContent, err := SubSignContent(subKey.Pair.Secret, addSubFeedMsg)
	r.NoError(err)

	// // make sure it's a signed add message
	var addMsg metamngmt.Add
	err = VerifySubSignedContent(signedAddContent, &addMsg)
	r.NoError(err)

	// now encode the message onto the feed
	signedAddMessage, msgKey, err := enc.Encode(1, refs.MessageRef{}, signedAddContent)
	r.NoError(err)

	t.Log(msgKey.Ref())

	valid := signedAddMessage.Verify(nil)
	r.True(valid)

	encoded, err := signedAddMessage.MarshalBencode()
	r.NoError(err)

	fmt.Fprintln(os.Stderr, "1st entry encoded. Len:", len(encoded))
	fmt.Fprintln(os.Stderr, hex.EncodeToString(encoded))

	// Message 2: now let's tombstone it
	tomb := metamngmt.NewTombstoneMessage(subKey.Feed)
	tomb.Tangles["metafeed"] = refs.TanglePoint{Root: &msgKey, Previous: refs.MessageRefs{msgKey}}

	signedTombstoneContent, err := SubSignContent(subKey.Pair.Secret, tomb)
	r.NoError(err)

	signedTombstoneMessage, msgKey, err := enc.Encode(2, msgKey, signedTombstoneContent)
	r.NoError(err)

	t.Log(msgKey.Ref())

	valid = signedTombstoneMessage.Verify(nil)
	r.True(valid)

	encoded, err = signedTombstoneMessage.MarshalBencode()
	r.NoError(err)

	fmt.Fprintln(os.Stderr, "2nd entry encoded. Len:", len(encoded))
	fmt.Fprintln(os.Stderr, hex.EncodeToString(encoded))

	err = VerifySubSignedContent(signedAddContent, &addMsg)
	r.NoError(err)

	var p2 Payload
	err = p2.UnmarshalBencode(signedTombstoneMessage.data)
	r.NoError(err)

	var tombstone metamngmt.Tombstone
	err = VerifySubSignedContent(p2.Content, &tombstone)
	r.NoError(err)
}
