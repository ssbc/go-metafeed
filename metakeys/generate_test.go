package metakeys_test

import (
	"encoding/hex"
	"testing"

	"github.com/ssb-ngi-pointer/go-metafeed/metakeys"
	"github.com/stretchr/testify/require"
)

func TestGenSeed(t *testing.T) {
	r := require.New(t)

	r.Equal(64, metakeys.SeedLength)

	s, err := metakeys.GenerateSeed()
	r.NoError(err)
	r.Len(s, metakeys.SeedLength)
}

func TestDeriveFromSeed(t *testing.T) {
	r := require.New(t)

	testSeed, err := hex.DecodeString("4e2ce5ca70cd12cc0cee0a5285b61fbc3b5f4042287858e613f9a8bf98a70d39")
	r.NoError(err)

	testLabel := ""
	_, err = metakeys.DeriveFromSeed(testSeed, testLabel)
	r.Error(err, "label can't be empty")

	testLabel = metakeys.RootLabel
	kp, err := metakeys.DeriveFromSeed(testSeed, testLabel)
	r.NoError(err)

	// the metafeed impl has "@+Io5SIzFW+BvLV246CW05g6jLkTvLilp7IW+9irQkfU=.ed25519" here
	// but it's using npm:derive-key which uses blake2b instead of hkdf
	// TODO: we also probably want to change the suffix?!
	wantRef := "@Ric0l8cqa9eqDdnOyaCwvCnnkTIdAMGADSQF8VpZa70=.bbfeed-v1"
	r.Equal(kp.Feed.Ref(), wantRef)
}