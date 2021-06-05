package bencodeext

import (
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
			return nil, err
		}

		m["root"], err = tfkRoot.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}

	if n := len(tp.Previous); n == 0 {
		m["previous"] = Null
	} else {
		var prevs = make([][]byte, n)

		for i, p := range tp.Previous {
			pTfk, err := tfk.MessageFromRef(p)
			if err != nil {
				return nil, err
			}

			prevs[i], err = pTfk.MarshalBinary()
			if err != nil {
				return nil, err
			}
		}

		m["previous"] = Null
	}

	return bencode.EncodeBytes(m)
}

func (tp *TanglePoint) UnmarshalBencode(input []byte) error {
	return fmt.Errorf("TODO: UnmarshalBencode TanglePoint")
}
