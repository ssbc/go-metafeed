// Package metafeed implements the SSB metafeed spec to enable partial replication.
package metafeed

import (
	"bytes"
	"fmt"
	"time"

	"github.com/zeebo/bencode"
	refs "go.mindeco.de/ssb-refs"
	"go.mindeco.de/ssb-refs/tfk"
)

// Payload represents a single Payload on a metafeed.
type Payload struct {
	Author    refs.FeedRef
	Sequence  int
	Previous  refs.MessageRef
	Timestamp time.Time
	Content   bencode.RawMessage
}

var (
	_ bencode.Marshaler   = (*Payload)(nil)
	_ bencode.Unmarshaler = (*Payload)(nil)
)

// MarshalBencode turns the payload into an array of 5 elements:
// author as tfk, sequence, previous as tfk, timestamp as unix ts and content as a bencode entity (usually object or byte string for box2)
func (p *Payload) MarshalBencode() ([]byte, error) {
	authorAsTFK, err := tfk.FeedFromRef(p.Author)
	if err != nil {
		return nil, err
	}

	autherAsBytes, err := authorAsTFK.MarshalBinary()
	if err != nil {
		return nil, err
	}

	prevMsg, err := tfk.MessageFromRef(p.Previous)
	if err != nil {
		return nil, err
	}

	prevAsBytes, err := prevMsg.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return bencode.EncodeBytes([]interface{}{
		autherAsBytes,
		int32(p.Sequence),
		prevAsBytes,
		p.Timestamp.Unix(),
		p.Content,
	})
}

// UnmarshalBencode does the reverse of MarshalBencode. It expects the input to be a bencoded array of 5 entries.
func (p *Payload) UnmarshalBencode(input []byte) error {
	// first, split up the array in raw parts (decodeing to []interface{} is annoying if we know the types anyhow)
	var raw []bencode.RawMessage

	err := bencode.NewDecoder(bytes.NewReader(input)).Decode(&raw)
	if err != nil {
		return err
	}

	if n := len(raw); n != 5 {
		return fmt.Errorf("beMeta: expected at least 5 parts, got %d", n)
	}

	// elem 1: author
	var authorBytes []byte
	err = bencode.NewDecoder(bytes.NewReader(raw[0])).Decode(&authorBytes)
	if err != nil {
		return err
	}

	var author tfk.Feed
	err = author.UnmarshalBinary(authorBytes)
	if err != nil {
		return err
	}

	p.Author, err = author.Feed()
	if err != nil {
		return err
	}

	// elem 2: author
	err = bencode.NewDecoder(bytes.NewReader(raw[1])).Decode(&p.Sequence)
	if err != nil {
		return err
	}

	// elem 3: previous
	var previousBytes []byte
	err = bencode.NewDecoder(bytes.NewReader(raw[2])).Decode(&previousBytes)
	if err != nil {
		return err
	}

	var prev tfk.Message
	err = prev.UnmarshalBinary(previousBytes)
	if err != nil {
		return err
	}

	p.Previous, err = prev.Message()
	if err != nil {
		return err
	}

	// elem 4: timestamp
	var tsInSeconds int64
	err = bencode.NewDecoder(bytes.NewReader(raw[3])).Decode(&tsInSeconds)
	if err != nil {
		return err
	}
	p.Timestamp = time.Unix(tsInSeconds, 0)

	// elem 5: content
	p.Content = raw[4]

	return nil
}
