// SPDX-License-Identifier: MIT

package vectors_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
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

// TODO: refactor a lot of this stuff into badSession creator to shoten the code

/*
1. invalid author formatting (type, length, ...)
2. invalid previous formatting (type, length, ...)
3. wrong previous hashes
4. broken signature(s)
5. wrong sequence numbers
6. too long messages
7. given that this format is supposed to be just for _metafeed_ managment, broken content
*/
func TestGenerateTestVectorWithInvalidMessages(t *testing.T) {
	r := require.New(t)

	// the vectors for other implementations
	var tv vectors.Bad
	tv.Description = "Some metafeed messages with invalid content (to help with validation)"

	t.Run("bad author type", badAuthorType(&tv.Cases))
	t.Run("bad author length", badAuthorLength(&tv.Cases))

	t.Run("bad previous type", badPreviousType(&tv.Cases))
	t.Run("bad previous length", badPreviousLength(&tv.Cases))

	t.Run("non zero previous on first message", badPreviousNonZero(&tv.Cases))
	t.Run("wrong previous on 2nd message", badPreviousInvalid(&tv.Cases))

	t.Run("invalid signature marker", invalidSignatureMarkers(&tv.Cases))
	t.Run("broken signature (bits flipped)", brokenSignature(&tv.Cases))

	t.Run("bad sequences", badSequence(&tv.Cases))

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
	vectorFile, err := os.OpenFile("../../testvector-metafeed-bad.json", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	r.NoError(err)

	err = json.NewEncoder(vectorFile).Encode(tv)
	r.NoError(err)
	r.NoError(vectorFile.Close())
}

func badAuthorType(cases *[]vectors.BadCase) func(t *testing.T) {
	return func(t *testing.T) {
		r := require.New(t)

		var bc vectors.BadCase
		bc.Description = "1.1: Author with bad TFK type (just one message)"

		// create a a keypair for an invalid formatted author
		seed := bytes.Repeat([]byte("sec0"), 8)
		bc.Metadata = append(bc.Metadata,
			vectors.HexMetadata{" KeyPair Seed", seed},
		)

		badAuthor, err := metakeys.DeriveFromSeed(seed, metakeys.RootLabel, refs.RefAlgoFeedBendyButt)
		r.NoError(err)

		// create encoder for meta-feed entries
		enc := metafeed.NewEncoder(badAuthor.Secret())

		// fake timestamp
		enc.WithNowTimestamps(true)
		zeroTime := time.Unix(0, 0)
		metafeed.SetNow(func() time.Time {
			return zeroTime
		})

		// zero previous for the first entry
		zeroPrevious, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
		r.NoError(err)

		// the content is not important for this case
		exMsg := map[string]interface{}{"type": "test"}

		signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
		r.NoError(err)

		var entry vectors.EntryBad
		entry.Reason = "Bad Author TFK Type"
		entry.Invalid = true

		resigned := fiddleWithMessage(t, signedMsg, badAuthor.PrivateKey, func(msgFields []bencode.RawMessage) {
			// set TFK type from 0 to 255
			r.Equal(uint8(0), msgFields[0][3])
			msgFields[0][3] = 0xff
		})

		entry.EncodedData = resigned

		bc.Entries = append(bc.Entries, entry)

		// add the case to the vector file
		*cases = append(*cases, bc)
	}
}

func badAuthorLength(cases *[]vectors.BadCase) func(t *testing.T) {
	return func(t *testing.T) {
		r := require.New(t)

		var bc vectors.BadCase
		bc.Description = "1.2: Author with bad TFK formatting (just one message)"

		// create a a keypair for an invalid formatted author
		seed := bytes.Repeat([]byte("sec1"), 8)
		bc.Metadata = append(bc.Metadata,
			vectors.HexMetadata{" KeyPair Seed", seed},
		)

		badAuthor, err := metakeys.DeriveFromSeed(seed, metakeys.RootLabel, refs.RefAlgoFeedBendyButt)
		r.NoError(err)

		// create encoder for meta-feed entries
		enc := metafeed.NewEncoder(badAuthor.Secret())

		// fake timestamp
		enc.WithNowTimestamps(true)
		zeroTime := time.Unix(0, 0)
		metafeed.SetNow(func() time.Time {
			return zeroTime
		})

		// zero previous for the first entry
		zeroPrevious, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
		r.NoError(err)

		// the content is not important for this case
		exMsg := map[string]interface{}{"type": "test"}

		signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
		r.NoError(err)

		var entry vectors.EntryBad
		entry.Reason = "Bad Author TFK Length"
		entry.Invalid = true

		resigned := fiddleWithMessage(t, signedMsg, badAuthor.PrivateKey, func(msgFields []bencode.RawMessage) {
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

		entry.EncodedData = resigned

		bc.Entries = append(bc.Entries, entry)

		// add the case to the vector file
		*cases = append(*cases, bc)
	}
}

func badPreviousType(cases *[]vectors.BadCase) func(t *testing.T) {
	return func(t *testing.T) {
		r := require.New(t)

		var bc vectors.BadCase
		bc.Description = "2.1: previous with bad TFK type (just one message)"

		// create a a keypair for an invalid formatted author
		seed := bytes.Repeat([]byte("sec2"), 8)
		bc.Metadata = append(bc.Metadata,
			vectors.HexMetadata{" KeyPair Seed", seed},
		)

		badAuthor, err := metakeys.DeriveFromSeed(seed, metakeys.RootLabel, refs.RefAlgoFeedBendyButt)
		r.NoError(err)

		// create encoder for meta-feed entries
		enc := metafeed.NewEncoder(badAuthor.Secret())

		// fake timestamp
		enc.WithNowTimestamps(true)
		zeroTime := time.Unix(0, 0)
		metafeed.SetNow(func() time.Time {
			return zeroTime
		})

		// zero previous for the first entry
		zeroPrevious, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
		r.NoError(err)

		// the content is not important for this case
		exMsg := map[string]interface{}{"type": "test", "i": 1}

		signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
		r.NoError(err)

		var entry vectors.EntryBad
		entry.Reason = "bad previous type"
		entry.Invalid = true

		resigned := fiddleWithMessage(t, signedMsg, badAuthor.PrivateKey, func(msgFields []bencode.RawMessage) {
			// set TFK type from 1 to 255
			r.Equal(uint8(1), msgFields[2][3])
			msgFields[2][3] = 0xff
		})

		entry.EncodedData = resigned

		bc.Entries = append(bc.Entries, entry)

		// add the case to the vector file
		*cases = append(*cases, bc)
	}
}

func badPreviousLength(cases *[]vectors.BadCase) func(t *testing.T) {
	return func(t *testing.T) {
		r := require.New(t)

		var bc vectors.BadCase
		bc.Description = "2.2: previous with bad TFK length (just one message)"

		// create a a keypair for an invalid formatted author
		seed := bytes.Repeat([]byte("sec3"), 8)
		bc.Metadata = append(bc.Metadata,
			vectors.HexMetadata{" KeyPair Seed", seed},
		)

		badAuthor, err := metakeys.DeriveFromSeed(seed, metakeys.RootLabel, refs.RefAlgoFeedBendyButt)
		r.NoError(err)

		// create encoder for meta-feed entries
		enc := metafeed.NewEncoder(badAuthor.Secret())

		// fake timestamp
		enc.WithNowTimestamps(true)
		zeroTime := time.Unix(0, 0)
		metafeed.SetNow(func() time.Time {
			return zeroTime
		})

		// zero previous for the first entry
		zeroPrevious, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
		r.NoError(err)

		// the content is not important for this case
		exMsg := map[string]interface{}{"type": "test", "i": 1}

		signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
		r.NoError(err)

		var entry vectors.EntryBad
		entry.Reason = "bad previous length"
		entry.Invalid = true

		resigned := fiddleWithMessage(t, signedMsg, badAuthor.PrivateKey, func(msgFields []bencode.RawMessage) {
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

		entry.EncodedData = resigned

		bc.Entries = append(bc.Entries, entry)

		// add the case to the vector file
		*cases = append(*cases, bc)
	}
}

func badPreviousNonZero(cases *[]vectors.BadCase) func(t *testing.T) {
	return func(t *testing.T) {
		r := require.New(t)

		var bc vectors.BadCase
		bc.Description = "3.1: non-zero previous on first message (just one message)"

		// create a a keypair for an invalid formatted author
		seed := bytes.Repeat([]byte("sec4"), 8)
		bc.Metadata = append(bc.Metadata,
			vectors.HexMetadata{" KeyPair Seed", seed},
		)

		badAuthor, err := metakeys.DeriveFromSeed(seed, metakeys.RootLabel, refs.RefAlgoFeedBendyButt)
		r.NoError(err)

		// create encoder for meta-feed entries
		enc := metafeed.NewEncoder(badAuthor.Secret())

		// fake timestamp
		enc.WithNowTimestamps(true)
		zeroTime := time.Unix(0, 0)
		metafeed.SetNow(func() time.Time {
			return zeroTime
		})

		// zero previous for the first entry
		zeroPrevious, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
		r.NoError(err)

		// the content is not important for this case
		exMsg := map[string]interface{}{"type": "test", "i": 1}

		signedMsg, _, err := enc.Encode(1, zeroPrevious, exMsg)
		r.NoError(err)

		var entry vectors.EntryBad
		entry.Reason = "bad previous length"
		entry.Invalid = true

		resigned := fiddleWithMessage(t, signedMsg, badAuthor.PrivateKey, func(msgFields []bencode.RawMessage) {
			// overwrite zero bytes with ff's
			ffs := bytes.Repeat([]byte{0xff}, 32)
			copy(msgFields[2][5:], ffs)
		})

		entry.EncodedData = resigned

		bc.Entries = append(bc.Entries, entry)

		// add the case to the vector file
		*cases = append(*cases, bc)
	}
}

func badPreviousInvalid(cases *[]vectors.BadCase) func(t *testing.T) {
	return func(t *testing.T) {
		r := require.New(t)

		var bc vectors.BadCase
		bc.Description = "3.2: 2nd message has wrong previous"

		// create a a keypair for an invalid formatted author
		seed := bytes.Repeat([]byte("sec4"), 8)
		bc.Metadata = append(bc.Metadata,
			vectors.HexMetadata{" KeyPair Seed", seed},
		)

		author, err := metakeys.DeriveFromSeed(seed, metakeys.RootLabel, refs.RefAlgoFeedBendyButt)
		r.NoError(err)

		// create encoder for meta-feed entries
		enc := metafeed.NewEncoder(author.Secret())

		// fake timestamp
		enc.WithNowTimestamps(true)
		zeroTime := time.Unix(0, 0)
		metafeed.SetNow(func() time.Time {
			return zeroTime
		})

		// zero previous for the first entry
		zeroPrevious, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
		r.NoError(err)

		// the content is not important for this case
		exMsg := map[string]interface{}{"type": "test", "i": 1}

		signedMsg, msg1key, err := enc.Encode(1, zeroPrevious, exMsg)
		r.NoError(err)

		var entry1 vectors.EntryBad
		entry1.Reason = "okay genesis msg"
		entry1.Invalid = false

		entry1.EncodedData, err = signedMsg.MarshalBencode()
		r.NoError(err)

		bc.Entries = append(bc.Entries, entry1)

		// now create the offending 2nd msg
		exMsg["i"] = 2
		signedMsg2, _, err := enc.Encode(2, msg1key, exMsg)
		r.NoError(err)

		var entry2 vectors.EntryBad
		entry2.Reason = "wrong previous"
		entry2.Invalid = true

		entry2.EncodedData = fiddleWithMessage(t, signedMsg2, author.PrivateKey, func(msgFields []bencode.RawMessage) {
			// overwrite previous with ff's
			ffs := bytes.Repeat([]byte{0xff}, 32)
			copy(msgFields[2][5:], ffs)
		})

		bc.Entries = append(bc.Entries, entry2)

		// add the case to the vector file
		*cases = append(*cases, bc)
	}
}

func invalidSignatureMarkers(cases *[]vectors.BadCase) func(t *testing.T) {
	return func(t *testing.T) {
		r := require.New(t)

		var bc vectors.BadCase
		bc.Description = "4.1: invalid signature marker, first two bytes (just one message)"

		// create a a keypair for an invalid formatted author
		seed := bytes.Repeat([]byte("sec5"), 8)
		bc.Metadata = append(bc.Metadata,
			vectors.HexMetadata{" KeyPair Seed", seed},
		)

		badAuthor, err := metakeys.DeriveFromSeed(seed, metakeys.RootLabel, refs.RefAlgoFeedBendyButt)
		r.NoError(err)

		// create encoder for meta-feed entries
		enc := metafeed.NewEncoder(badAuthor.Secret())

		// fake timestamp
		enc.WithNowTimestamps(true)
		zeroTime := time.Unix(0, 0)
		metafeed.SetNow(func() time.Time {
			return zeroTime
		})

		// zero previous for the first entry
		zeroPrevious, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
		r.NoError(err)

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

		// add the case to the vector file
		*cases = append(*cases, bc)
	}
}

func brokenSignature(cases *[]vectors.BadCase) func(t *testing.T) {
	return func(t *testing.T) {
		r := require.New(t)

		var bc vectors.BadCase
		bc.Description = "4.2: invalid signature (just one message)"

		// create a a keypair for an invalid formatted author
		seed := bytes.Repeat([]byte("sec5"), 8)
		bc.Metadata = append(bc.Metadata,
			vectors.HexMetadata{" KeyPair Seed", seed},
		)

		badAuthor, err := metakeys.DeriveFromSeed(seed, metakeys.RootLabel, refs.RefAlgoFeedBendyButt)
		r.NoError(err)

		// create encoder for meta-feed entries
		enc := metafeed.NewEncoder(badAuthor.Secret())

		// fake timestamp
		enc.WithNowTimestamps(true)
		zeroTime := time.Unix(0, 0)
		metafeed.SetNow(func() time.Time {
			return zeroTime
		})

		// zero previous for the first entry
		zeroPrevious, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
		r.NoError(err)

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

		// add the case to the vector file
		*cases = append(*cases, bc)
	}
}

func badSequence(cases *[]vectors.BadCase) func(t *testing.T) {
	return func(t *testing.T) {
		r := require.New(t)

		var bc vectors.BadCase
		bc.Description = "5.1: two messages with bad sequences (1 and 3)"

		// create a a keypair for an invalid formatted author
		seed := bytes.Repeat([]byte("sec6"), 8)
		bc.Metadata = append(bc.Metadata,
			vectors.HexMetadata{" KeyPair Seed", seed},
		)

		author, err := metakeys.DeriveFromSeed(seed, metakeys.RootLabel, refs.RefAlgoFeedBendyButt)
		r.NoError(err)

		// create encoder for meta-feed entries
		enc := metafeed.NewEncoder(author.Secret())

		// fake timestamp
		enc.WithNowTimestamps(true)
		zeroTime := time.Unix(0, 0)
		metafeed.SetNow(func() time.Time {
			return zeroTime
		})

		// zero previous for the first entry
		zeroPrevious, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
		r.NoError(err)

		// the content is not important for this case
		exMsg := map[string]interface{}{"type": "test", "i": 1}

		signedMsg, msg1key, err := enc.Encode(1, zeroPrevious, exMsg)
		r.NoError(err)

		var entry1 vectors.EntryBad
		entry1.Reason = "okay genesis msg"
		entry1.Invalid = false

		entry1.EncodedData, err = signedMsg.MarshalBencode()
		r.NoError(err)

		bc.Entries = append(bc.Entries, entry1)

		// now create the offending 2nd msg
		exMsg["i"] = 2
		signedMsg2, _, err := enc.Encode(3, msg1key, exMsg)
		r.NoError(err)

		var entry2 vectors.EntryBad
		entry2.Reason = "wrong sequence"
		entry2.Invalid = true

		entry2.EncodedData, err = signedMsg2.MarshalBencode()
		r.NoError(err)

		bc.Entries = append(bc.Entries, entry2)

		// add the case to the vector file
		*cases = append(*cases, bc)
	}
}

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

func assertValidBencode(t *testing.T, data []byte) bool {
	a := assert.New(t)
	var v interface{}
	err := bencode.DecodeBytes(data, &v)
	return a.NoError(err)
}
