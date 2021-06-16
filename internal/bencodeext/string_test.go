// SPDX-License-Identifier: MIT

package bencodeext

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestString(t *testing.T) {
	r := require.New(t)

	val := "foo"

	wrapedVal := String(val)

	encoded, err := wrapedVal.MarshalBencode()
	r.NoError(err)

	var unwrapped String
	err = unwrapped.UnmarshalBencode(encoded)
	r.NoError(err)

	r.Equal(val, string(unwrapped))
}

func TestStringWithColons(t *testing.T) {
	r := require.New(t)

	val := "marry:has:a:little:lamb"

	wrapedVal := String(val)

	encoded, err := wrapedVal.MarshalBencode()
	r.NoError(err)

	var unwrapped String
	err = unwrapped.UnmarshalBencode(encoded)
	r.NoError(err)

	r.Equal(val, string(unwrapped))
}
