// SPDX-License-Identifier: MIT

package vectors_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeebo/bencode"
	refs "go.mindeco.de/ssb-refs"

	"github.com/ssb-ngi-pointer/go-metafeed"
	"github.com/ssb-ngi-pointer/go-metafeed/internal/sign"
	"github.com/ssb-ngi-pointer/go-metafeed/internal/vectors"
	"github.com/ssb-ngi-pointer/go-metafeed/metakeys"
	"github.com/ssb-ngi-pointer/go-metafeed/metamngmt"
)

// This generates the "bad content" vector file.
// See the part about content in https://github.com/ssb-ngi-pointer/bendy-butt-spec/#validation for more
func TestGenerateTestVectorBWithInvalidContent(t *testing.T) {
	r := require.New(t)

	// the vectors for other implementations
	var tv vectors.Bad
	tv.Description = "Some metafeed messages with invalid content"

	badCase := []struct {
		descr   string
		genCase func(t *testing.T) vectors.BadCase
	}{
		{"1.1: bad type value", badContentType},

		{"2.1: broken subfeed TFK", badContentSubfeedTFK},
		{"2.2: broken metafeed TFK", badContentMetafeedTFK},

		// {"3.1: broken b64 nonce value", badContentNonceBroken},
		{"3.2: bad nonce length (short)", badContentNonceShort},
		{"3.3: bad nonce length (long)", badContentNonceLonger},

		{"4.1: bad content signature", badContentSignature},
	}

	for _, c := range badCase {
		bc := c.genCase(t)
		bc.Description = c.descr
		tv.Cases = append(tv.Cases, bc)
	}

	// make sure each entry is valid bencode data at least
	for ci, c := range tv.Cases {
		for ei, e := range c.Entries {
			if !assertValidBencode(t, e.EncodedData) {
				t.Logf("invalid bencode data in case %d - entry %d: %s", ci, ei, e.Reason)
				t.Logf("\n%s", hex.Dump(e.EncodedData))
				t.Log(hex.EncodeToString(e.EncodedData))
			}
		}
	}

	// finally, create the test vector file
	vectorFile, err := os.OpenFile("../../testvector-metafeed-bad-content.json", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	r.NoError(err)

	err = json.NewEncoder(vectorFile).Encode(tv)
	r.NoError(err)

	r.NoError(vectorFile.Close())
}

func badContentType(t *testing.T) vectors.BadCase {
	var bc vectors.BadCase
	r := require.New(t)

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	var nonce = bytes.Repeat([]byte{0x23}, 32)
	bc.Metadata = append(bc.Metadata,
		vectors.HexMetadata{"subfeed1 nonce", nonce},
	)

	// create the subfeed keypair
	seededLabel := "ssb-meta-feed-seed-v1:" + base64.StdEncoding.EncodeToString(nonce)
	subKey, err := metakeys.DeriveFromSeed(kp.Seed, seededLabel, refs.RefAlgoFeedSSB1)
	r.NoError(err)
	bc.Metadata = append(bc.Metadata, vectors.SubfeedAuthor{
		Name: "subfeed1 author", Feed: subKey.Feed,
	})

	addSubFeed1Msg := metamngmt.NewAddMessage(kp.Feed, subKey.Feed, "main default", nonce)
	addSubFeed1Msg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// invalidate the content type
	addSubFeed1Msg.Type = "nope-nope-nope"

	// now sign the add content
	signedAddContent, err := metafeed.SubSignContent(subKey.Secret(), addSubFeed1Msg)
	r.NoError(err)

	signedMsg, _, err := enc.Encode(1, zeroPrevious, signedAddContent)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "Bad Content Type"
	entry.Invalid = true

	entry.EncodedData, err = signedMsg.MarshalBencode()
	r.NoError(err)

	bc.Entries = append(bc.Entries, entry)
	return bc
}

func badContentSubfeedTFK(t *testing.T) vectors.BadCase {
	var bc vectors.BadCase
	r := require.New(t)

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	var nonce = bytes.Repeat([]byte{0x23}, 32)
	bc.Metadata = append(bc.Metadata,
		vectors.HexMetadata{"subfeed1 nonce", nonce},
	)

	// create the subfeed keypair
	seededLabel := "ssb-meta-feed-seed-v1:" + base64.StdEncoding.EncodeToString(nonce)
	subKey, err := metakeys.DeriveFromSeed(kp.Seed, seededLabel, refs.RefAlgoFeedSSB1)
	r.NoError(err)
	bc.Metadata = append(bc.Metadata, vectors.SubfeedAuthor{
		Name: "subfeed1 author", Feed: subKey.Feed,
	})

	addSubFeed1Msg := metamngmt.NewAddMessage(kp.Feed, subKey.Feed, "main default", nonce)
	addSubFeed1Msg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// now sign the add content
	signedAddContent, err := metafeed.SubSignContent(subKey.Secret(), addSubFeed1Msg)
	r.NoError(err)

	signedMsg, _, err := enc.Encode(1, zeroPrevious, signedAddContent)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "Bad subfeed"
	entry.Invalid = true

	entry.EncodedData = fiddleWithContent(t, signedMsg, kp.PrivateKey, subKey.PrivateKey, func(content bencode.RawMessage) bencode.RawMessage {

		var m map[string]bencode.RawMessage
		err := bencode.DecodeBytes(content, &m)
		r.NoError(err)

		// invalid tfk
		m["subfeed"][3] = 0xff
		m["subfeed"][4] = 0xff

		changed, err := bencode.EncodeBytes(m)
		r.NoError(err)

		return changed
	})

	bc.Entries = append(bc.Entries, entry)
	return bc
}

func badContentMetafeedTFK(t *testing.T) vectors.BadCase {
	var bc vectors.BadCase
	r := require.New(t)

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	var nonce = bytes.Repeat([]byte{0x23}, 32)
	bc.Metadata = append(bc.Metadata,
		vectors.HexMetadata{"subfeed1 nonce", nonce},
	)

	// create the subfeed keypair
	seededLabel := "ssb-meta-feed-seed-v1:" + base64.StdEncoding.EncodeToString(nonce)
	subKey, err := metakeys.DeriveFromSeed(kp.Seed, seededLabel, refs.RefAlgoFeedSSB1)
	r.NoError(err)
	bc.Metadata = append(bc.Metadata, vectors.SubfeedAuthor{
		Name: "subfeed1 author", Feed: subKey.Feed,
	})

	addSubFeed1Msg := metamngmt.NewAddMessage(kp.Feed, subKey.Feed, "main default", nonce)
	addSubFeed1Msg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// now sign the add content
	signedAddContent, err := metafeed.SubSignContent(subKey.Secret(), addSubFeed1Msg)
	r.NoError(err)

	signedMsg, _, err := enc.Encode(1, zeroPrevious, signedAddContent)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "Bad subfeed"
	entry.Invalid = true

	entry.EncodedData = fiddleWithContent(t, signedMsg, kp.PrivateKey, subKey.PrivateKey, func(content bencode.RawMessage) bencode.RawMessage {

		var m map[string]bencode.RawMessage
		err := bencode.DecodeBytes(content, &m)
		r.NoError(err)

		// invalid tfk
		m["metafeed"][3] = 0xff
		m["metafeed"][4] = 0xff

		changed, err := bencode.EncodeBytes(m)
		r.NoError(err)

		return changed
	})

	bc.Entries = append(bc.Entries, entry)
	return bc
}

// TODO: really base64? https://github.com/ssb-ngi-pointer/bendy-butt-spec/issues/14
func badContentNonceBroken(t *testing.T) vectors.BadCase {
	var bc vectors.BadCase
	r := require.New(t)

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	var nonce = make([]byte, 32)
	copy(nonce, []byte("some actual bytes"))
	bc.Metadata = append(bc.Metadata,
		vectors.HexMetadata{"subfeed1 nonce", nonce},
	)

	// create the subfeed keypair
	seededLabel := "ssb-meta-feed-seed-v1:" + base64.StdEncoding.EncodeToString(nonce)
	subKey, err := metakeys.DeriveFromSeed(kp.Seed, seededLabel, refs.RefAlgoFeedSSB1)
	r.NoError(err)
	bc.Metadata = append(bc.Metadata, vectors.SubfeedAuthor{
		Name: "subfeed1 author", Feed: subKey.Feed,
	})

	addSubFeed1Msg := metamngmt.NewAddMessage(kp.Feed, subKey.Feed, "main default", nonce)
	addSubFeed1Msg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// now sign the add content
	signedAddContent, err := metafeed.SubSignContent(subKey.Secret(), addSubFeed1Msg)
	r.NoError(err)

	signedMsg, _, err := enc.Encode(1, zeroPrevious, signedAddContent)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "Bad subfeed"
	entry.Invalid = true

	entry.EncodedData = fiddleWithContent(t, signedMsg, kp.PrivateKey, subKey.PrivateKey, func(content bencode.RawMessage) bencode.RawMessage {

		var m map[string]bencode.RawMessage
		err := bencode.DecodeBytes(content, &m)
		r.NoError(err)

		// invalid nonce base64
		for i := 3; i < 35; i++ {
			m["nonce"][i] = 0xff
		}

		changed, err := bencode.EncodeBytes(m)
		r.NoError(err)

		return changed
	})

	bc.Entries = append(bc.Entries, entry)
	return bc
}

func badContentNonceShort(t *testing.T) vectors.BadCase {
	var bc vectors.BadCase
	r := require.New(t)

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	var nonce = bytes.Repeat([]byte{0x23}, 32)
	bc.Metadata = append(bc.Metadata,
		vectors.HexMetadata{"subfeed1 nonce", nonce},
	)

	// create the subfeed keypair
	seededLabel := "ssb-meta-feed-seed-v1:" + base64.StdEncoding.EncodeToString(nonce)
	subKey, err := metakeys.DeriveFromSeed(kp.Seed, seededLabel, refs.RefAlgoFeedSSB1)
	r.NoError(err)
	bc.Metadata = append(bc.Metadata, vectors.SubfeedAuthor{
		Name: "subfeed1 author", Feed: subKey.Feed,
	})

	addSubFeed1Msg := metamngmt.NewAddMessage(kp.Feed, subKey.Feed, "main default", nonce)
	addSubFeed1Msg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// now sign the add content
	signedAddContent, err := metafeed.SubSignContent(subKey.Secret(), addSubFeed1Msg)
	r.NoError(err)

	signedMsg, _, err := enc.Encode(1, zeroPrevious, signedAddContent)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "Bad subfeed"
	entry.Invalid = true

	entry.EncodedData = fiddleWithContent(t, signedMsg, kp.PrivateKey, subKey.PrivateKey, func(content bencode.RawMessage) bencode.RawMessage {

		var m map[string]bencode.RawMessage
		err := bencode.DecodeBytes(content, &m)
		r.NoError(err)

		// chop of one byte and fix the length
		m["nonce"] = m["nonce"][:34]
		m["nonce"][1] = 0x31

		changed, err := bencode.EncodeBytes(m)
		r.NoError(err)

		return changed
	})

	bc.Entries = append(bc.Entries, entry)
	return bc
}

func badContentNonceLonger(t *testing.T) vectors.BadCase {
	var bc vectors.BadCase
	r := require.New(t)

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	var nonce = bytes.Repeat([]byte{0xff}, 32)
	bc.Metadata = append(bc.Metadata,
		vectors.HexMetadata{"subfeed1 nonce", nonce},
	)

	// create the subfeed keypair
	seededLabel := "ssb-meta-feed-seed-v1:" + base64.StdEncoding.EncodeToString(nonce)
	subKey, err := metakeys.DeriveFromSeed(kp.Seed, seededLabel, refs.RefAlgoFeedSSB1)
	r.NoError(err)
	bc.Metadata = append(bc.Metadata, vectors.SubfeedAuthor{
		Name: "subfeed1 author", Feed: subKey.Feed,
	})

	addSubFeed1Msg := metamngmt.NewAddMessage(kp.Feed, subKey.Feed, "main default", nonce)
	addSubFeed1Msg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// now sign the add content
	signedAddContent, err := metafeed.SubSignContent(subKey.Secret(), addSubFeed1Msg)
	r.NoError(err)

	signedMsg, _, err := enc.Encode(1, zeroPrevious, signedAddContent)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "Bad subfeed"
	entry.Invalid = true

	entry.EncodedData = fiddleWithContent(t, signedMsg, kp.PrivateKey, subKey.PrivateKey, func(content bencode.RawMessage) bencode.RawMessage {

		var m map[string]bencode.RawMessage
		err := bencode.DecodeBytes(content, &m)
		r.NoError(err)

		// add two bytes and fix the length
		m["nonce"] = append(m["nonce"], byte(0x01), byte(0x02))
		m["nonce"][1] = 0x34

		changed, err := bencode.EncodeBytes(m)
		r.NoError(err)

		return changed
	})

	bc.Entries = append(bc.Entries, entry)
	return bc
}

func badContentSignature(t *testing.T) vectors.BadCase {
	var bc vectors.BadCase
	r := require.New(t)

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	var nonce = bytes.Repeat([]byte{0x23}, 32)
	bc.Metadata = append(bc.Metadata,
		vectors.HexMetadata{"subfeed1 nonce", nonce},
	)

	// create the subfeed keypair
	seededLabel := "ssb-meta-feed-seed-v1:" + base64.StdEncoding.EncodeToString(nonce)
	subKey, err := metakeys.DeriveFromSeed(kp.Seed, seededLabel, refs.RefAlgoFeedSSB1)
	r.NoError(err)
	bc.Metadata = append(bc.Metadata, vectors.SubfeedAuthor{
		Name: "subfeed1 author", Feed: subKey.Feed,
	})

	addSubFeed1Msg := metamngmt.NewAddMessage(kp.Feed, subKey.Feed, "main default", nonce)
	addSubFeed1Msg.Tangles["metafeed"] = refs.TanglePoint{Root: nil, Previous: nil} // initial

	// now sign the add content
	signedAddContent, err := metafeed.SubSignContent(subKey.Secret(), addSubFeed1Msg)
	r.NoError(err)

	signedMsg, _, err := enc.Encode(1, zeroPrevious, signedAddContent)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "Bad Content Type"
	entry.Invalid = true

	entry.EncodedData = fiddleWithMessage(t, signedMsg, kp.PrivateKey, func(msgFields []bencode.RawMessage) {
		// decode the data
		var contentAndSig []bencode.RawMessage
		err := bencode.DecodeBytes(msgFields[4], &contentAndSig)
		r.NoError(err)
		r.Len(contentAndSig, 2)

		// skip length and BFE marker (0x0400)
		// and overwrite some bytes
		copy(contentAndSig[1][5:9], []byte("ohai"))

		// rencode the object
		msgFields[4], err = bencode.EncodeBytes(contentAndSig)
		r.NoError(err)
	})

	bc.Entries = append(bc.Entries, entry)
	return bc
}

// utilities

// get's passed the content portion and should return a new content portion that will be re-signed witht he passed subkey
type contentFiddleFn func(bencode.RawMessage) bencode.RawMessage

// encodes a message and then unpacks it again, hands it to the passed function for mallace and then reencodes and signs it
func fiddleWithContent(t *testing.T, input *metafeed.Message, metaKey, subKey ed25519.PrivateKey, fn contentFiddleFn) []byte {
	r := require.New(t)

	// get the bencode data
	encoded, err := input.MarshalBencode()
	r.NoError(err)

	// fiddle with the encoded data
	var signedArr []bencode.RawMessage
	err = bencode.DecodeBytes(encoded, &signedArr)
	r.NoError(err)
	r.Len(signedArr, 2)

	var msgFields []bencode.RawMessage
	err = bencode.DecodeBytes(signedArr[0], &msgFields)
	r.NoError(err)
	r.Len(msgFields, 5)

	var contentFields []bencode.RawMessage
	err = bencode.DecodeBytes(msgFields[4], &contentFields)
	r.NoError(err)
	r.Len(contentFields, 2)

	changedContent := fn(contentFields[0])

	// re-create the signed content
	contentAndSig, err := bencode.EncodeBytes([]interface{}{
		bencode.RawMessage(changedContent),
		sign.Create(changedContent, subKey, nil), // TODO: pass hmac secret
	})
	r.NoError(err)

	// update the changed content
	msgFields[4] = contentAndSig

	// reencode it
	reencoded, err := bencode.EncodeBytes(msgFields)
	r.NoError(err)

	// re-sign it
	var changedData = []interface{}{
		bencode.RawMessage(reencoded),
		sign.Create(reencoded, metaKey, nil),
	}

	resigned, err := bencode.EncodeBytes(changedData)
	r.NoError(err)

	return resigned
}
