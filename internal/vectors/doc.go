// SPDX-License-Identifier: MIT

// Package vectors sists in internal because it also contains code to produce bad/invalid messages.
package vectors

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	refs "go.mindeco.de/ssb-refs"
)

type Good struct {
	Description string

	Metadata []interface{} `json:",omitempty"`

	Entries []EntryGood
}

type EntryGood struct {
	EncodedData HexString

	Key refs.MessageRef

	Author           refs.FeedRef
	Sequence         int32
	Previous         refs.MessageRef
	Timestamp        int64
	HighlevelContent interface{}
	Signature        HexString
}

type HexMetadata struct {
	Name      string
	HexString HexString
}

type SubfeedAuthor struct {
	Name string
	Feed refs.FeedRef
}

// the bad vector file has a bunch of different cases.
// each containing a list of entries of a single author feed.
type Bad struct {
	Description string

	Cases []BadCase
}

type BadCase struct {
	Description string

	Metadata []interface{} `json:",omitempty"`
	Entries  []EntryBad
}

type EntryBad struct {
	EncodedData HexString

	// sometimes we need a valid message preceeding an invalid one.
	// if message:2 has an invalid previous, for example.
	Invalid bool

	// if invalid, why the data is bad
	Reason string

	// If we want to clearify some extra fields
	MessageFields map[string]interface{} `json:",omitempty"`
}

// utils for test vector encoding

type HexString []byte

func (s HexString) MarshalJSON() ([]byte, error) {
	str := hex.EncodeToString([]byte(s))
	return json.Marshal(str)
}

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
