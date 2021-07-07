// SPDX-License-Identifier: MIT

package vectors_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ssb-ngi-pointer/go-metafeed"
	"github.com/ssb-ngi-pointer/go-metafeed/internal/sign"
	"github.com/ssb-ngi-pointer/go-metafeed/internal/vectors"
	"github.com/ssb-ngi-pointer/go-metafeed/metakeys"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/bencode"
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
		entry.MessageFields = map[string]interface{}{
			"Sequence": 1,
		}

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
		entry.MessageFields = map[string]interface{}{
			"Sequence": 1,
		}

		resigned := fiddleWithMessage(t, signedMsg, badAuthor.PrivateKey, func(msgFields []bencode.RawMessage) {
			// add a few bytes to the public key
			more := bytes.Repeat([]byte{0xff}, 16)
			msgFields[0] = append(msgFields[0], more...)
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
		entry.MessageFields = map[string]interface{}{
			"Sequence": 1,
		}

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
		entry.MessageFields = map[string]interface{}{
			"Sequence": 1,
		}

		resigned := fiddleWithMessage(t, signedMsg, badAuthor.PrivateKey, func(msgFields []bencode.RawMessage) {
			// set TFK type from 1 to 255
			more := bytes.Repeat([]byte{0xff}, 16)
			msgFields[2] = append(msgFields[2], more...)
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
		entry.MessageFields = map[string]interface{}{
			"Sequence": 1,
		}

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
		entry1.MessageFields = map[string]interface{}{
			"Sequence": 1,
			"Author":   author.ID().Ref(),
			"Key":      msg1key.Ref(),
		}

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
		entry2.MessageFields = map[string]interface{}{
			"Sequence": 2,
			"Author":   author.ID().Ref(),
		}

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

	signedArr[0] = reencoded
	signedArr[1] = sign.Create(reencoded, key, nil)

	resigned, err := bencode.EncodeBytes(signedArr)
	r.NoError(err)

	return resigned
}
