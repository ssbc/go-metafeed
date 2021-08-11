// SPDX-License-Identifier: MIT

package vectors_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/bencode"

	"github.com/ssb-ngi-pointer/go-metafeed"
	"github.com/ssb-ngi-pointer/go-metafeed/internal/sign"
	"github.com/ssb-ngi-pointer/go-metafeed/internal/vectors"
	"github.com/ssb-ngi-pointer/go-metafeed/metakeys"
	refs "go.mindeco.de/ssb-refs"
)

var zeroPrevious refs.MessageRef

// This generates the "bad messages" vector file.
// See https://github.com/ssb-ngi-pointer/bendy-butt-spec/#validation for more
func TestGenerateTestVectorAWithInvalidMessages(t *testing.T) {
	r := require.New(t)

	// the vectors for other implementations
	var tv vectors.Bad
	tv.Description = "Some invalid message metafeed"

	badCase := []struct {
		descr   string
		genCase func(t *testing.T) vectors.BadCase
	}{
		{"1.1: Author with bad TFK type", badAuthorType},
		{"1.2: Author with bad TFK format", badAuthorFormat},
		{"1.3: Author with bad TFK length", badAuthorLength},

		{"2.1: previous with bad TFK type", badPreviousType},
		{"2.2: previous with bad TFK format", badPreviousFormat},
		{"2.3: previous with bad TFK length", badPreviousLength},

		{"3.1: bad first NULL previous", badPreviousNull},
		{"3.2: 2nd message has wrong previous", badPreviousInvalid},

		{"4.1: invalid signature marker, first two bytes", invalidSignatureMarkers},
		{"4.2: broken signature (bits flipped)", brokenSignature},

		{"5.1: two messages with bad sequences (1 and 3)", badSequence},

		{"6.1: message too long", tooLongMessage},
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
	vectorFile, err := os.OpenFile("../../testvector-metafeed-bad-messages.json", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	r.NoError(err)

	err = json.NewEncoder(vectorFile).Encode(tv)
	r.NoError(err)

	r.NoError(vectorFile.Close())
}

func badAuthorType(t *testing.T) vectors.BadCase {
	var bc vectors.BadCase
	r := require.New(t)

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := map[string]interface{}{"type": "test"}

	signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "Bad Author TFK Type"
	entry.Invalid = true

	entry.EncodedData = fiddleWithMessage(t, signedMsg, kp.PrivateKey, func(msgFields []bencode.RawMessage) {
		// set TFK type from 0 to 255
		r.Equal(uint8(0), msgFields[0][3])
		msgFields[0][3] = 0xff
	})

	bc.Entries = append(bc.Entries, entry)
	return bc
}

func badAuthorFormat(t *testing.T) vectors.BadCase {
	var bc vectors.BadCase
	r := require.New(t)

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := map[string]interface{}{"type": "test"}

	signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "Bad Author TFK format"
	entry.Invalid = true

	entry.EncodedData = fiddleWithMessage(t, signedMsg, kp.PrivateKey, func(msgFields []bencode.RawMessage) {
		// set TFK format to 255
		r.Equal(uint8(3), msgFields[0][4])
		msgFields[0][4] = 0xff
	})

	bc.Entries = append(bc.Entries, entry)

	return bc
}

func badAuthorLength(t *testing.T) vectors.BadCase {
	r := require.New(t)

	var bc vectors.BadCase

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := map[string]interface{}{"type": "test"}

	signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "Bad Author TFK Length"
	entry.Invalid = true

	entry.EncodedData = fiddleWithMessage(t, signedMsg, kp.PrivateKey, func(msgFields []bencode.RawMessage) {
		// decode to splice of the length
		var data []byte
		err := bencode.DecodeBytes(msgFields[0], &data)
		r.NoError(err)

		// add a few bytes to the public key
		more := bytes.Repeat([]byte{0xff}, 16)
		data = append(data, more...)

		// rencode to create the right length
		msgFields[0], err = bencode.EncodeBytes(data)
		r.NoError(err)
	})

	bc.Entries = append(bc.Entries, entry)

	return bc
}

func badPreviousNull(t *testing.T) vectors.BadCase {
	r := require.New(t)

	var bc vectors.BadCase

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := newTestMessage(1)

	signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "bad previous null"
	entry.Invalid = true

	entry.EncodedData = fiddleWithMessage(t, signedMsg, kp.PrivateKey, func(msgFields []bencode.RawMessage) {
		msgFields[2] = []byte("4:1234")
	})

	bc.Entries = append(bc.Entries, entry)
	return bc
}

func badPreviousType(t *testing.T) vectors.BadCase {
	r := require.New(t)

	var bc vectors.BadCase

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := newTestMessage(1)

	signedMsg, msg1key, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry1 vectors.EntryBad
	entry1.Reason = "okay genesis msg"
	entry1.Invalid = false

	entry1.EncodedData, err = signedMsg.MarshalBencode()
	r.NoError(err)

	bc.Entries = append(bc.Entries, entry1)

	// now create the offending 2nd msg
	exMsg = newTestMessage(2)
	signedMsg2, _, err := enc.Encode(2, msg1key, exMsg)
	r.NoError(err)

	var entry2 vectors.EntryBad
	entry2.Reason = "bad previous type"
	entry2.Invalid = true

	entry2.EncodedData = fiddleWithMessage(t, signedMsg2, kp.PrivateKey, func(msgFields []bencode.RawMessage) {
		// set TFK type from 1 to 255
		r.Equal(uint8(1), msgFields[2][3])
		msgFields[2][3] = 0xff
	})

	bc.Entries = append(bc.Entries, entry2)
	return bc
}

func badPreviousFormat(t *testing.T) vectors.BadCase {
	r := require.New(t)

	var bc vectors.BadCase

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := newTestMessage(1)

	signedMsg, msg1key, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry1 vectors.EntryBad
	entry1.Reason = "okay genesis msg"
	entry1.Invalid = false

	entry1.EncodedData, err = signedMsg.MarshalBencode()
	r.NoError(err)

	bc.Entries = append(bc.Entries, entry1)

	// now create the offending 2nd msg
	exMsg = newTestMessage(2)
	signedMsg2, _, err := enc.Encode(2, msg1key, exMsg)
	r.NoError(err)

	var entry2 vectors.EntryBad
	entry2.Reason = "bad previous format"
	entry2.Invalid = true

	entry2.EncodedData = fiddleWithMessage(t, signedMsg2, kp.PrivateKey, func(msgFields []bencode.RawMessage) {
		// set TFK format to 255
		r.Equal(uint8(4), msgFields[2][4])
		msgFields[2][4] = 0xff
	})

	bc.Entries = append(bc.Entries, entry2)

	return bc
}

func badPreviousLength(t *testing.T) vectors.BadCase {
	r := require.New(t)

	var bc vectors.BadCase

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})
	// the content is not important for this case
	exMsg := newTestMessage(1)

	signedMsg, msg1key, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry1 vectors.EntryBad
	entry1.Reason = "okay genesis msg"
	entry1.Invalid = false

	entry1.EncodedData, err = signedMsg.MarshalBencode()
	r.NoError(err)

	bc.Entries = append(bc.Entries, entry1)

	// now create the offending 2nd msg
	exMsg = newTestMessage(2)
	signedMsg2, _, err := enc.Encode(2, msg1key, exMsg)
	r.NoError(err)

	var entry2 vectors.EntryBad
	entry2.Reason = "bad previous length"
	entry2.Invalid = true

	entry2.EncodedData = fiddleWithMessage(t, signedMsg2, kp.PrivateKey, func(msgFields []bencode.RawMessage) {
		// decode to splice of the length
		var data []byte
		err := bencode.DecodeBytes(msgFields[2], &data)
		r.NoError(err)

		// add a few bytes to the previous msg hash
		more := bytes.Repeat([]byte{0xff}, 16)
		data = append(data, more...)

		// rencode to create the right length
		msgFields[2], err = bencode.EncodeBytes(data)
		r.NoError(err)

	})

	bc.Entries = append(bc.Entries, entry2)

	return bc
}

func badPreviousInvalid(t *testing.T) vectors.BadCase {
	r := require.New(t)

	var bc vectors.BadCase

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := newTestMessage(1)

	signedMsg, msg1key, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry1 vectors.EntryBad
	entry1.Reason = "okay genesis msg"
	entry1.Invalid = false

	entry1.EncodedData, err = signedMsg.MarshalBencode()
	r.NoError(err)

	bc.Entries = append(bc.Entries, entry1)

	// now create the offending 2nd msg
	exMsg = newTestMessage(2)
	signedMsg2, _, err := enc.Encode(2, msg1key, exMsg)
	r.NoError(err)

	var entry2 vectors.EntryBad
	entry2.Reason = "wrong previous"
	entry2.Invalid = true

	entry2.EncodedData = fiddleWithMessage(t, signedMsg2, kp.PrivateKey, func(msgFields []bencode.RawMessage) {
		// overwrite previous with ff's
		ffs := bytes.Repeat([]byte{0xff}, 32)
		copy(msgFields[2][5:], ffs)
	})

	bc.Entries = append(bc.Entries, entry2)

	return bc
}

func invalidSignatureMarkers(t *testing.T) vectors.BadCase {
	r := require.New(t)

	var bc vectors.BadCase

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := map[string]interface{}{"type": "test"}

	signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "invalid signature"
	entry.Invalid = true

	// break the signature
	copy(signedMsg.Signature[:2], []byte{0xac, 0xab})

	encoded, err := signedMsg.MarshalBencode()
	r.NoError(err)

	entry.EncodedData = encoded

	bc.Entries = append(bc.Entries, entry)

	return bc
}

func brokenSignature(t *testing.T) vectors.BadCase {
	r := require.New(t)

	var bc vectors.BadCase

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := map[string]interface{}{"type": "test"}

	signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "invalid signature"
	entry.Invalid = true

	// break the signature
	for i, s := range signedMsg.Signature[2:] {
		signedMsg.Signature[i+2] = s ^ 0xff
	}

	encoded, err := signedMsg.MarshalBencode()
	r.NoError(err)

	entry.EncodedData = encoded

	bc.Entries = append(bc.Entries, entry)

	return bc
}

func badSequence(t *testing.T) vectors.BadCase {
	r := require.New(t)

	var bc vectors.BadCase

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := newTestMessage(1)

	signedMsg, msg1key, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry1 vectors.EntryBad
	entry1.Reason = "okay genesis msg"
	entry1.Invalid = false

	entry1.EncodedData, err = signedMsg.MarshalBencode()
	r.NoError(err)

	bc.Entries = append(bc.Entries, entry1)

	// now create the offending 2nd msg
	exMsg = newTestMessage(2)
	signedMsg2, _, err := enc.Encode(3, msg1key, exMsg)
	r.NoError(err)

	var entry2 vectors.EntryBad
	entry2.Reason = "wrong sequence"
	entry2.Invalid = true

	entry2.EncodedData, err = signedMsg2.MarshalBencode()
	r.NoError(err)

	bc.Entries = append(bc.Entries, entry2)

	return bc
}

func tooLongMessage(t *testing.T) vectors.BadCase {
	r := require.New(t)

	var bc vectors.BadCase

	enc, kp := makeEncoder(t)
	bc.Metadata = append(bc.Metadata, vectors.HexMetadata{"KeyPair Seed", kp.Seed})

	// the content is not important for this case
	exMsg := map[string]interface{}{"type": "test"}

	signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
	r.NoError(err)

	var entry vectors.EntryBad
	entry.Reason = "invalid signature"
	entry.Invalid = true

	origMessage, err := signedMsg.MarshalBinary()
	r.NoError(err)
	origSize := len(origMessage)

	entry.EncodedData = fiddleWithMessage(t, signedMsg, kp.PrivateKey, func(msgFields []bencode.RawMessage) {
		// decode the data
		var data map[string]interface{}
		err := bencode.DecodeBytes(msgFields[4], &data)
		r.NoError(err)

		// add one byte too much
		data["moar"] = strings.Repeat("A", 8*1024-origSize+1)

		// rencode the object
		msgFields[4], err = bencode.EncodeBytes(data)
		r.NoError(err)
	})
	r.Greater(len(entry.EncodedData), 8*1024)

	bc.Entries = append(bc.Entries, entry)

	return bc
}

// utilities

// encodes a message and then unpacks it again, hands it to the passed function for mallace and then reencodes and signs it
func fiddleWithMessage(t *testing.T, input *metafeed.Message, key ed25519.PrivateKey, fn func([]bencode.RawMessage)) []byte {
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

	fn(msgFields)

	reencoded, err := bencode.EncodeBytes(msgFields)
	r.NoError(err)

	var changedData = []interface{}{
		bencode.RawMessage(reencoded),
		sign.Create(reencoded, key, nil),
	}

	resigned, err := bencode.EncodeBytes(changedData)
	r.NoError(err)

	return resigned
}

var keyPairCounter = byte(0)

func makeEncoder(t *testing.T) (*metafeed.Encoder, metakeys.KeyPair) {
	r := require.New(t)

	// create a keypair seed
	seed := bytes.Repeat([]byte{'s', 'e', 'c', keyPairCounter}, 8)
	keyPairCounter++

	// derive the key
	badAuthor, err := metakeys.DeriveFromSeed(seed, "badfeed", refs.RefAlgoFeedBendyButt)
	r.NoError(err)

	// create encoder for meta-feed entries
	enc := metafeed.NewEncoder(badAuthor.Secret())

	// fake timestamp
	enc.WithNowTimestamps(true)
	zeroTime := time.Unix(0, 0)
	metafeed.SetNow(func() time.Time {
		return zeroTime
	})

	return enc, badAuthor
}

func assertValidBencode(t *testing.T, data []byte) bool {
	a := assert.New(t)
	var v interface{}
	err := bencode.DecodeBytes(data, &v)
	return a.NoError(err)
}

// not actually a proper metafeed message, it just needs to look like one
// see https://github.com/ssb-ngi-pointer/go-metafeed/issues/18#issuecomment-896670827
func newTestMessage(i int) []interface{} {
	return []interface{}{
		map[string]interface{}{"type": "test", "i": i},
		append([]byte{0x04, 0x00}, bytes.Repeat([]byte("test-content-signature"), 5)[:64]...),
	}
}
