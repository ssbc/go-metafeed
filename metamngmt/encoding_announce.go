// SPDX-FileCopyrightText: 2021 The go-metafeed Authors
//
// SPDX-License-Identifier: MIT

package metamngmt

// MarshalBencode packs an Announce message into bencode extended data.
func (a Announce) MarshalBencode() ([]byte, error) {
	panic("TODO:implement Announce")
}

// UnmarshalBencode unpacks bencode extended data into an Announce message.
func (a *Announce) UnmarshalBencode(input []byte) error {
	panic("TODO:implement Announce")
}
