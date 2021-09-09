package metamngmt

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	// "github.com/zeebo/bencode"
	refs "go.mindeco.de/ssb-refs"
)

func TestAddDerivedWithoutMetadata(t *testing.T) {
	r := require.New(t)

	pubkey1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	mf, err := refs.NewFeedRefFromBytes(pubkey1, refs.RefAlgoFeedBendyButt)
	r.NoError(err)

	pubkey2 := bytes.Repeat([]byte{0xff}, 32)
	feed, err := refs.NewFeedRefFromBytes(pubkey2, refs.RefAlgoFeedSSB1)
	r.NoError(err)

	addMsg := NewAddDerivedMessage(mf, feed, "test", []byte("asdasdasd"))

	want := []byte{0x64, 0x31, 0x31, 0x3a, 0x66, 0x65, 0x65, 0x64, 0x70, 0x75, 0x72, 0x70, 0x6f, 0x73, 0x65, 0x36, 0x3a, 0x6, 0x0, 0x74, 0x65, 0x73, 0x74, 0x38, 0x3a, 0x6d, 0x65, 0x74, 0x61, 0x66, 0x65, 0x65, 0x64, 0x33, 0x34, 0x3a, 0x0, 0x3, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x35, 0x3a, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x31, 0x31, 0x3a, 0x6, 0x3, 0x61, 0x73, 0x64, 0x61, 0x73, 0x64, 0x61, 0x73, 0x64, 0x37, 0x3a, 0x73, 0x75, 0x62, 0x66, 0x65, 0x65, 0x64, 0x33, 0x34, 0x3a, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x37, 0x3a, 0x74, 0x61, 0x6e, 0x67, 0x6c, 0x65, 0x73, 0x64, 0x65, 0x34, 0x3a, 0x74, 0x79, 0x70, 0x65, 0x32, 0x32, 0x3a, 0x6, 0x0, 0x6d, 0x65, 0x74, 0x61, 0x66, 0x65, 0x65, 0x64, 0x2f, 0x61, 0x64, 0x64, 0x2f, 0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64, 0x65}
	got, err := addMsg.MarshalBencode()
	r.NoError(err)

	r.Equal(want, got)
}

func TestAddDerivedWithMetadata(t *testing.T) {
	r := require.New(t)
	var err error

	pubkey1 := bytes.Repeat([]byte{0x01}, 32)
	mf, err := refs.NewFeedRefFromBytes(pubkey1, refs.RefAlgoFeedBendyButt)
	r.NoError(err)

	pubkey2 := bytes.Repeat([]byte{0x02}, 32)
	feed, err := refs.NewFeedRefFromBytes(pubkey2, refs.RefAlgoFeedSSB1)
	r.NoError(err)

	feedpurpose := "test"
	// create an metafeed/add/derived message that contains query metadata
	addMsg := NewAddDerivedMessage(mf, feed, feedpurpose, []byte("asdasdasd"))
	metadata := map[string]string{
		"querylang": "ql-0",
		"query":     "somejson",
	}
	err = addMsg.InsertMetadata(metadata)
	r.NoError(err)

	// // TODO: update want with actual ouput
	want := []byte{0x64, 0x31, 0x31, 0x3a, 0x66, 0x65, 0x65, 0x64, 0x70, 0x75, 0x72, 0x70, 0x6f, 0x73, 0x65, 0x36, 0x3a, 0x6, 0x0, 0x74, 0x65, 0x73, 0x74, 0x38, 0x3a, 0x6d, 0x65, 0x74, 0x61, 0x66, 0x65, 0x65, 0x64, 0x33, 0x34, 0x3a, 0x0, 0x3, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x35, 0x3a, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x31, 0x31, 0x3a, 0x6, 0x3, 0x61, 0x73, 0x64, 0x61, 0x73, 0x64, 0x61, 0x73, 0x64, 0x35, 0x3a, 0x71, 0x75, 0x65, 0x72, 0x79, 0x31, 0x30, 0x3a, 0x6, 0x0, 0x73, 0x6f, 0x6d, 0x65, 0x6a, 0x73, 0x6f, 0x6e, 0x39, 0x3a, 0x71, 0x75, 0x65, 0x72, 0x79, 0x6c, 0x61, 0x6e, 0x67, 0x36, 0x3a, 0x6, 0x0, 0x71, 0x6c, 0x2d, 0x30, 0x37, 0x3a, 0x73, 0x75, 0x62, 0x66, 0x65, 0x65, 0x64, 0x33, 0x34, 0x3a, 0x0, 0x0, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x37, 0x3a, 0x74, 0x61, 0x6e, 0x67, 0x6c, 0x65, 0x73, 0x64, 0x65, 0x34, 0x3a, 0x74, 0x79, 0x70, 0x65, 0x32, 0x32, 0x3a, 0x6, 0x0, 0x6d, 0x65, 0x74, 0x61, 0x66, 0x65, 0x65, 0x64, 0x2f, 0x61, 0x64, 0x64, 0x2f, 0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64, 0x65}

	got, err := addMsg.MarshalBencode()
	r.NoError(err)
	r.Equal(want, got)

	// unmarshal back to struct/map value to make sure the values are intact
	var decodedAddMsg AddDerived
	err = decodedAddMsg.UnmarshalBencode(want)
	r.NoError(err)

	r.Equal(feedpurpose, decodedAddMsg.FeedPurpose, "error when decoding derived.purpose")
	r.Equal(metadata["query"], decodedAddMsg.Query, "error when decoding derived.query")
	r.Equal(metadata["querylang"], decodedAddMsg.QueryLang, "error when decoding derived.querylang")
}
