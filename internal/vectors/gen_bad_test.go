// SPDX-License-Identifier: MIT

package vectors_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ssb-ngi-pointer/go-metafeed/internal/vectors"
	"github.com/ssb-ngi-pointer/go-metafeed/metakeys"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/bencode"
	refs "go.mindeco.de/ssb-refs"
)

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

	// 1
	var caseBadAuthor vectors.BadCase
	caseBadAuthor.Description = "1.1: Author with bad TFK formatting (just one message)"

	// create a a keypair for an invalid formatted author
	badAuthorSeed := bytes.Repeat([]byte("sec0"), 8)
	caseBadAuthor.Metadata = append(caseBadAuthor.Metadata,
		tvHexMetadata{" KeyPair Seed", badAuthorSeed},
	)

	badAuthor, err := metakeys.DeriveFromSeed(badAuthorSeed, metakeys.RootLabel, refs.RefAlgoFeedBendyButt)
	r.NoError(err)

	// create encoder for meta-feed entries
	badAuthorEnc := NewEncoder(badAuthor.Secret())

	// fake timestamp
	badAuthorEnc.WithNowTimestamps(true)
	zeroTime := time.Unix(0, 0)
	now = func() time.Time {
		return zeroTime
	}

	// zero previous for the first entry
	zeroPrevious, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
	r.NoError(err)

	badAuthorMsg, _, err := badAuthorEnc.Encode(1, zeroPrevious, refs.NewPost("bad author"))
	r.NoError(err)

	var entryBadAuthorType testVectorEntryBad
	entryBadAuthorType.Reason = "Bad Author TFK Type"
	entryBadAuthorType.Invalid = true
	entryBadAuthorType.MessageFields = map[string]interface{}{
		"Sequence": 1,
	}

	// get the bencode data
	encoded, err := badAuthorMsg.MarshalBencode()
	r.NoError(err)

	fmt.Printf("pure msg:\n%s\n", hex.Dump(encoded))

	// fiddle with the encoded data
	var signedArr []bencode.RawMessage
	err = bencode.DecodeBytes(encoded, &signedArr)
	r.NoError(err)
	r.Len(signedArr, 2)

	var msgFields []bencode.RawMessage
	err = bencode.DecodeBytes(signedArr[0], &msgFields)
	r.NoError(err)
	r.Len(msgFields, 5)

	fmt.Printf("before:\n%s\n", hex.Dump(msgFields[0]))

	msgFields[0][3] = 0xff // set type from 0 to 255

	fmt.Printf("after:\n%s\n", hex.Dump(msgFields[0]))

	// fmt.Printf("reassembled msg:\n%s\n", hex.Dump(reencoded))

	entryBadAuthorType.EncodedData = encoded

	caseBadAuthor.Entries = append(caseBadAuthor.Entries, entryBadAuthorType)

	// add the case to the vector file
	tv.Cases = append(tv.Cases, caseBadAuthor)

	// finally, create the test vector file
	vectorFile, err := os.OpenFile("testvector-metafeed-bad.json", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	r.NoError(err)

	err = json.NewEncoder(vectorFile).Encode(tv)
	r.NoError(err)
	r.NoError(vectorFile.Close())

}
