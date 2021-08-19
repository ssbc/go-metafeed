// SPDX-FileCopyrightText: 2021 The go-metafeed Authors
//
// SPDX-License-Identifier: MIT

package bencodeext

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBytes(t *testing.T) {
	r := require.New(t)

	val := []byte("foo")

	wrapedVal := Bytes(val)

	encoded, err := wrapedVal.MarshalBencode()
	r.NoError(err)

	var unwrapped Bytes
	err = unwrapped.UnmarshalBencode(encoded)
	r.NoError(err)

	r.Equal(val, []byte(unwrapped))
}
