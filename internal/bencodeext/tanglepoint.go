package bencodeext

import (
	"bytes"
	"fmt"

	"github.com/zeebo/bencode"
	refs "go.mindeco.de/ssb-refs"
	"go.mindeco.de/ssb-refs/tfk"
)

type TanglePoint refs.TanglePoint

var (
	_ bencode.Marshaler   = (*TanglePoint)(nil)
	_ bencode.Unmarshaler = (*TanglePoint)(nil)
)

func (tp TanglePoint) MarshalBencode() ([]byte, error) {
	var m = make(map[string]interface{}, 2)

	if tp.Root == nil {
		m["root"] = Null
	} else {
		tfkRoot, err := tfk.MessageFromRef(*tp.Root)
		if err != nil {
			return nil, fmt.Errorf("bencext/tanglePoint: failed to make tfk reference for root message: %w", err)
		}

		m["root"], err = tfkRoot.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("bencext/tanglePoint: failed to encode tfk root: %w", err)
		}
	}

	if n := len(tp.Previous); n == 0 {
		m["previous"] = Null
	} else {
		var prevs = make([][]byte, n)

		for i, p := range tp.Previous {
			pTfk, err := tfk.MessageFromRef(p)
			if err != nil {
				return nil, fmt.Errorf("bencext/tanglePoint: failed to make tfk reference for prev message no %d: %w", i, err)
			}

			prevs[i], err = pTfk.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("bencext/tanglePoint: failed to encode tfk previous %d: %w", i, err)
			}
		}

		m["previous"] = Null
	}

	return bencode.EncodeBytes(m)
}

func (tp *TanglePoint) UnmarshalBencode(input []byte) error {
	var rawBytes struct {
		Root     []byte             `bencode:"root"`
		Previous bencode.RawMessage `bencode:"previous"`
	}

	err := bencode.NewDecoder(bytes.NewReader(input)).Decode(&rawBytes)
	if err != nil {
		return fmt.Errorf("bencext/tanglePoint: failed to decode raw bytes: %w", err)
	}

	var candidate refs.TanglePoint

	if bytes.Equal(rawBytes.Root, []byte{0x06, 0x02}) {
		candidate.Root = nil
	} else {
		var msg tfk.Message
		err = msg.UnmarshalBinary(rawBytes.Root)
		if err != nil {
			return fmt.Errorf("bencext/tanglePoint: failed to unpack root bytes: %w", err)
		}

		root, err := msg.Message()
		if err != nil {
			return fmt.Errorf("bencext/tanglePoint: failed to unpack message from decoded tfk: %w", err)
		}

		candidate.Root = &root
	}

	if bytes.Equal(rawBytes.Previous, Null) {
		candidate.Previous = nil
	} else {
		var byteSlices [][]byte
		err := bencode.NewDecoder(bytes.NewReader(rawBytes.Previous)).Decode(&byteSlices)
		if err != nil {
			return fmt.Errorf("bencext/tanglePoint: failed to decode byte array for previous hashes%w", err)
		}
		prevs := make(refs.MessageRefs, len(byteSlices))
		for i, p := range byteSlices {

			var msg tfk.Message
			err = msg.UnmarshalBinary(p)
			if err != nil {
				return fmt.Errorf("bencext/tanglePoint: slice entry %d is not tfk: %w", i, err)
			}

			prevs[i], err = msg.Message()
			if err != nil {
				return fmt.Errorf("bencext/tanglePoint: slice entry %d is not a message: %w", i, err)
			}
		}

		candidate.Previous = prevs
	}

	*tp = TanglePoint(candidate)
	return nil
}