package metafeed_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ssb-ngi-pointer/go-metafeed"
	"github.com/ssb-ngi-pointer/go-metafeed/internal/vectors"
	"github.com/stretchr/testify/require"
)

func TestBadVector(t *testing.T) {
	r := require.New(t)

	var tv vectors.Bad

	f, err := os.Open("testvector-metafeed-bad.json")
	r.NoError(err)

	err = json.NewDecoder(f).Decode(&tv)
	r.NoError(err)
	f.Close()

	// make sure each entry is valid bencode data at least
cases:
	for ci, c := range tv.Cases {
		for ei, e := range c.Entries {
			var msg metafeed.Message
			err := msg.UnmarshalBencode(e.EncodedData)
			r.NoError(err, "case%d entry%d passed on %s", ci, ei, c.Description)

			if e.Invalid {
				r.False(msg.Verify(nil), "case%d entry%d (%s) verified!", ci, ei, c.Description)
				t.Logf("case%d entry%d (%s) checked", ci, ei, c.Description)
			} else {
				// TODO make a chain
				continue cases
			}

		}
	}

}
