// SPDX-FileCopyrightText: 2021 The go-metafeed Authors
//
// SPDX-License-Identifier: MIT

package metafeed_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ssb-ngi-pointer/go-metafeed"
	"github.com/ssb-ngi-pointer/go-metafeed/internal/vectors"
	"github.com/stretchr/testify/require"
)

func TestBadMessagesVector(t *testing.T) {
	r := require.New(t)

	var tv vectors.Bad

	f, err := os.Open("testvector-metafeed-bad-messages.json")
	r.NoError(err)

	err = json.NewDecoder(f).Decode(&tv)
	r.NoError(err)
	f.Close()

	// make sure each entry is valid bencode data at least
	for ci, c := range tv.Cases {
		var previous metafeed.Message
		for ei, e := range c.Entries {
			var msg metafeed.Message
			err := msg.UnmarshalBencode(e.EncodedData)

			if e.Invalid {
				// it decoded fine (valid bencode and not too big)
				if err == nil {
					verified := msg.Verify(nil)
					// all the fields and signature are okay?
					if verified {
						// it's not the first message
						if s := msg.Seq(); s > 1 {

							// should increment by 1
							seqCorrect := s-previous.Seq() == 1

							// should point to the right previous message
							prevCorrect := previous.Key().Equal(*msg.Previous())

							// since it's not valid, at least one of these has to be wrong
							r.True(!seqCorrect || !prevCorrect, "case%d entry%d (%s) validated!", ci, ei, c.Description)
						}
					} else {
						r.False(verified, "case%d entry%d (%s) verified!", ci, ei, c.Description)
					}
				}
			} else {
				r.NoError(err, "case%d entry%d passed on %s", ci, ei, c.Description)
				r.True(msg.Verify(nil), "case%d entry%d (%s) did not verify!", ci, ei, c.Description)
			}

			t.Logf("case%d entry%d (%s) checked", ci, ei, c.Description)
			previous = msg
		}
	}
}
