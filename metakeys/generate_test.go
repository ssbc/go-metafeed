// SPDX-FileCopyrightText: 2021 The go-metafeed Authors
//
// SPDX-License-Identifier: MIT

package metakeys_test

import (
	"encoding/hex"
	"testing"

	"github.com/ssbc/go-metafeed/metakeys"
	refs "github.com/ssbc/go-ssb-refs"
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

	algo := refs.RefAlgoFeedBendyButt

	testSeed, err := hex.DecodeString("4e2ce5ca70cd12cc0cee0a5285b61fbc3b5f4042287858e613f9a8bf98a70d39")
	r.NoError(err)

	t.Run("no label", func(t *testing.T) {
		r := require.New(t)

		testLabel := ""
		_, err = metakeys.DeriveFromSeed(testSeed, testLabel, algo)
		r.Error(err, "label can't be empty")
	})

	t.Run("default label", func(t *testing.T) {
		r := require.New(t)

		testLabel := "metafeed"
		kp, err := metakeys.DeriveFromSeed(testSeed, testLabel, algo)
		r.NoError(err)

		wantRef := "@0hyf48bX1JcGxGvwiMXzmEWodZvJZvDXxPiKhq3QlSw=.bendybutt-v1"
		r.Equal(kp.Feed.Sigil(), wantRef)
	})

	t.Run("some nonce", func(t *testing.T) {
		r := require.New(t)

		testLabel := "aumEXI0cdPx1sfX1nx5Y9Pl2GmwocYiFhv9o6K9BIhA="
		kp, err := metakeys.DeriveFromSeed(testSeed, testLabel, refs.RefAlgoFeedSSB1)
		r.NoError(err)

		wantRef := "@nFiLP62RZCGHCtmXScWERRxAJyTdWudAgPXODHATTgE=.ed25519"
		r.Equal(kp.Feed.Sigil(), wantRef)
	})
}
