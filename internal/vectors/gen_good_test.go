// SPDX-FileCopyrightText: 2021 The go-metafeed Authors
//
// SPDX-License-Identifier: MIT

package vectors_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ssb-ngi-pointer/go-metafeed"
	"github.com/ssb-ngi-pointer/go-metafeed/internal/vectors"
	"github.com/ssb-ngi-pointer/go-metafeed/metakeys"
	"github.com/ssb-ngi-pointer/go-metafeed/metamngmt"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/bencode"
	refs "go.mindeco.de/ssb-refs"
)

func TestGenerateMetaFeedManagment(t *testing.T) {
	r := require.New(t)

	// the vectors for other implementations
	var tv vectors.Good
	tv.Description = "A bunch of metafeed related messages with double signed posts. Two feeds get added and one of them gets revoked/tombstoned"

	// create a new meta feed
	// usually you would do this: but then the test vectors are not deterministic
	// metaSeed, err := metakeys.GenerateSeed()
	// r.NoError(err)
	metaSeed := bytes.Repeat([]byte("sec0"), 8)
	tv.Metadata = append(tv.Metadata,
		vectors.HexMetadata{"Seed for Metafeed KeyPair", metaSeed},
	)

	metaKey, err := metakeys.DeriveFromSeed(metaSeed, "testfeed", refs.RefAlgoFeedBendyButt)
	r.NoError(err)

	// create encoder for meta-feed entries
	enc := metafeed.NewEncoder(metaKey.Secret())

	// fake timestamp
	enc.WithNowTimestamps(true)
	zeroTime := time.Unix(0, 0)
	metafeed.SetNow(func() time.Time {
		return zeroTime
	})

	// create seed for first subfeed
	// usually you would do this: but then the test vectors are not deterministic
	// var nonce = make([]byte, 32)
	// io.ReadFull(rand.Reader, nonce)
	var nonce = bytes.Repeat([]byte{0x23}, 32)
	tv.Metadata = append(tv.Metadata,
		vectors.HexMetadata{"subfeed1 nonce", nonce},
	)

	// create the subfeed keypair
	seededLabel := base64.StdEncoding.EncodeToString(nonce)
	subKey, err := metakeys.DeriveFromSeed(metaSeed, seededLabel, refs.RefAlgoFeedSSB1)
	r.NoError(err)
	tv.Metadata = append(tv.Metadata, vectors.SubfeedAuthor{
		Name: "subfeed1 author", Feed: subKey.Feed,
	})

	// Message 1: create add message
	// ==========
	addSubFeed1Msg := metamngmt.NewAddMessage(metaKey.Feed, subKey.Feed, "main default", nonce)
	addSubFeed1Msg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// now sign the add content
	signedAddContent, err := metafeed.SubSignContent(subKey.Secret(), addSubFeed1Msg)
	r.NoError(err)

	// make sure it's a signed add message
	var addMsg metamngmt.Add
	err = metafeed.VerifySubSignedContent(signedAddContent, &addMsg)
	r.NoError(err)

	// start building the first entry for the test vector file
	var tvEntry vectors.EntryGood
	tvEntry.Author = metaKey.Feed
	tvEntry.Sequence = 1
	tvEntry.Previous = nil
	tvEntry.Timestamp = 0
	tvEntry.HighlevelContent = []interface{}{
		addSubFeed1Msg,
		vectors.HexMetadata{
			Name:      "subfeed signature",
			HexString: assertSubsignedAndGetSignatureBytes(t, signedAddContent),
		},
	}

	// now encode and sign the message
	signedAddMessage, msg1Key, err := enc.Encode(1, zeroPrevious, signedAddContent)
	r.NoError(err)
	tvEntry.Key = msg1Key
	addFirstSubfeedMsg := msg1Key

	tvEntry.Signature = signedAddMessage.Signature

	// make sure it's signature checks out
	valid := signedAddMessage.Verify(nil)
	r.True(valid)
	// encode and append entry one to the test vectors
	encoded, err := signedAddMessage.MarshalBencode()
	r.NoError(err)
	tvEntry.EncodedData = encoded
	tv.Entries = append(tv.Entries, tvEntry)

	// Message 2: create a gabby grove subfeed
	// ==========
	var nonce2 = bytes.Repeat([]byte{0x42}, 32)
	tv.Metadata = append(tv.Metadata,
		vectors.HexMetadata{"subfeed2 nonce", nonce2},
	)

	// create the subfeed keypair
	seededLabel = base64.StdEncoding.EncodeToString(nonce2)
	subKey2, err := metakeys.DeriveFromSeed(metaSeed, seededLabel, refs.RefAlgoFeedGabby)
	r.NoError(err)
	tv.Metadata = append(tv.Metadata, vectors.SubfeedAuthor{
		Name: "subfeed2 author", Feed: subKey2.Feed,
	})

	addSubFeed2Msg := metamngmt.NewAddMessage(metaKey.Feed, subKey2.Feed, "experimental", nonce2)
	addSubFeed2Msg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// now sign the add content
	signedAdd2Content, err := metafeed.SubSignContent(subKey2.Secret(), addSubFeed2Msg)
	r.NoError(err)

	var tvEntry2 vectors.EntryGood
	tvEntry2.Author = metaKey.Feed
	tvEntry2.Previous = &msg1Key
	tvEntry2.Sequence = 2
	tvEntry2.Timestamp = 0
	tvEntry2.HighlevelContent = []interface{}{
		addSubFeed2Msg,
		vectors.HexMetadata{
			Name:      "subfeed2 signature",
			HexString: assertSubsignedAndGetSignatureBytes(t, signedAdd2Content),
		},
	}

	// now encode and sign the 2nd message
	signedAdd2Message, msg2Key, err := enc.Encode(2, msg1Key, signedAdd2Content)
	r.NoError(err)
	tvEntry2.Key = msg2Key
	tvEntry2.Signature = signedAdd2Message.Signature

	// encode and append entry two to the test vectors
	encoded, err = signedAdd2Message.MarshalBencode()
	r.NoError(err)
	tvEntry2.EncodedData = encoded
	tv.Entries = append(tv.Entries, tvEntry2)

	// Message 3: now let's tombstone the first subfeed
	// ==========
	tomb := metamngmt.NewTombstoneMessage(subKey.Feed, metaKey.Feed)
	tomb.Tangles["metafeed"] = refs.TanglePoint{Root: &addFirstSubfeedMsg, Previous: refs.MessageRefs{addFirstSubfeedMsg}}

	signedTombstoneContent, err := metafeed.SubSignContent(subKey.Secret(), tomb)
	r.NoError(err)

	var tvEntry3 vectors.EntryGood
	tvEntry3.Author = metaKey.Feed
	tvEntry3.Previous = &msg2Key
	tvEntry3.Sequence = 3
	tvEntry3.Timestamp = 0
	tvEntry3.HighlevelContent = []interface{}{
		tomb,
		vectors.HexMetadata{
			Name:      "subfeed1 signature",
			HexString: assertSubsignedAndGetSignatureBytes(t, signedTombstoneContent),
		},
	}

	// encode and sign the entry
	signedTombstoneMessage, msg3Key, err := enc.Encode(3, msg2Key, signedTombstoneContent)
	r.NoError(err)
	tvEntry3.Key = msg3Key
	tvEntry3.Signature = signedTombstoneMessage.Signature

	// assert the signed content is signed correctly
	valid = signedTombstoneMessage.Verify(nil)
	r.True(valid)

	// that it contains a payload
	var p2 metafeed.Payload
	err = p2.UnmarshalBencode(signedTombstoneMessage.Data)
	r.NoError(err)

	// and that the content is a tombstone
	var tombstone metamngmt.Tombstone
	err = metafeed.VerifySubSignedContent(p2.Content, &tombstone)
	r.NoError(err)

	// encode and append entry three to the test vectors
	encoded, err = signedTombstoneMessage.MarshalBencode()
	r.NoError(err)
	tvEntry3.EncodedData = encoded
	tv.Entries = append(tv.Entries, tvEntry3)

	// finally, create the test vector file
	vectorFile, err := os.OpenFile("../../testvector-metafeed-managment.json", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	r.NoError(err)

	err = json.NewEncoder(vectorFile).Encode(tv)
	r.NoError(err)
	r.NoError(vectorFile.Close())

}

func assertSubsignedAndGetSignatureBytes(t *testing.T, msg bencode.RawMessage) []byte {
	r := require.New(t)

	// assert it's an array with two parts
	var decodedSignedAddContent []bencode.RawMessage
	err := bencode.DecodeBytes(msg, &decodedSignedAddContent)
	r.NoError(err)
	r.Len(decodedSignedAddContent, 2)

	// extract the signature from part2
	var justTheSig []byte
	err = bencode.DecodeBytes(decodedSignedAddContent[1], &justTheSig)
	r.NoError(err)

	return justTheSig
}
