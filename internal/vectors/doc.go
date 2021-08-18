// SPDX-FileCopyrightText: 2021 The go-metafeed Authors
//
// SPDX-License-Identifier: MIT

// Package vectors sists in internal because it also contains code to produce bad/invalid messages.
package vectors

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	refs "go.mindeco.de/ssb-refs"
)

// Good is the scaffolding for the whole vector file
// It's called good because all the entries are valid messages.
type Good struct {
	// Description describes what this vector file is about
	Description string

	// Metadata holds additional values that are needed to recreate the entries
	Metadata []interface{} `json:",omitempty"`

	// Entries are the single messages on a feed
	Entries []EntryGood
}

// EntryGood describes a single message
type EntryGood struct {
	// EncodedData holds the bencode data as a hex string
	EncodedData HexString

	Key refs.MessageRef

	Author           refs.FeedRef
	Sequence         int32
	Previous         *refs.MessageRef
	Timestamp        int64
	HighlevelContent interface{}
	Signature        HexString
}

// HexMetadata is a general purpose metadata field that hex encodes some data
type HexMetadata struct {
	Name      string
	HexString HexString
}

// SubfeedAuthor can be used as metadata to signal a feed reference (@abcdefg.something)
type SubfeedAuthor struct {
	Name string
	Feed refs.FeedRef
}

// Bad vector file has a bunch of different cases.
// each containing a list of entries of a single author feed.
type Bad struct {
	Description string

	Cases []BadCase
}

// BadCase describes a single case with a list of entries
type BadCase struct {
	Description string

	Metadata []interface{} `json:",omitempty"`
	Entries  []EntryBad
}

// EntryBad is a signle message in a case
// In the bad entries we just care if a message is broken or not.
// To cleanly check the contents of a message we have the Good vectors.
type EntryBad struct {
	// EncodedData holds the bencode data as a hex string
	EncodedData HexString

	// Invalid denotes if a message is valid ot not.
	// sometimes we need a valid message preceeding an invalid one.
	// if message:2 has an invalid previous, for example.
	Invalid bool

	// if invalid, why the data is bad
	Reason string
}

// utils for test vector encoding

// HexString can be used to turn a byteslice into a JSON hexadecimal string
type HexString []byte

// MarshalJSON turns the binary data into a hex string
func (s HexString) MarshalJSON() ([]byte, error) {
	str := hex.EncodeToString([]byte(s))
	return json.Marshal(str)
}

// UnmarshalJSON expects data to be a string with hexadecimal bytes inside
func (s *HexString) UnmarshalJSON(data []byte) error {
	var strData string
	err := json.Unmarshal(data, &strData)
	if err != nil {
		return fmt.Errorf("HexString: json decode of string failed: %w", err)
	}

	rawData, err := hex.DecodeString(strData)
	if err != nil {
		return fmt.Errorf("HexString: decoding hex to raw bytes failed: %w", err)
	}

	*s = rawData
	return nil
}
