package metamngmt

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ssb-ngi-pointer/go-metafeed/internal/bencodeext"
	"github.com/zeebo/bencode"
	refs "go.mindeco.de/ssb-refs"
	"go.mindeco.de/ssb-refs/tfk"
)

func (a Add) MarshalBencode() ([]byte, error) {
	// create TFK values for sub- and meta-feed
	subFeedTFK, err := tfk.FeedFromRef(a.SubFeed)
	if err != nil {
		return nil, err
	}
	sfBytes, err := subFeedTFK.MarshalBinary()
	if err != nil {
		return nil, err
	}

	metaFeedTFK, err := tfk.FeedFromRef(a.MetaFeed)
	if err != nil {
		return nil, err
	}
	mfBytes, err := metaFeedTFK.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// now create a map of all the values and let the bencode lib sort it
	value := map[string]interface{}{
		"type":        bencodeext.String(a.Type),
		"feedformat":  bencodeext.String(a.FeedFormat),
		"feedpurpose": bencodeext.String(a.FeedPurpose),
		"subfeed":     sfBytes,
		"metafeed":    mfBytes,
		"nonce":       []byte(a.Nonce),
	}

	if n := len(a.Tangles); n > 0 {
		wrappedTangles := make(map[string]bencodeext.TanglePoint, n)

		for name, tangle := range a.Tangles {
			wrappedTangles[name] = bencodeext.TanglePoint(tangle)
		}

		value["tangles"] = wrappedTangles
	}

	return bencode.EncodeBytes(value)
}

type wrappedAdd struct {
	Type        bencodeext.String `bencode:"type"`
	FeedFormat  bencodeext.String `bencode:"feedformat"`
	FeedPurpose bencodeext.String `bencode:"feedpurpose"`

	SubFeed  []byte `bencode:"subfeed"`
	MetaFeed []byte `bencode:"metafeed"`

	Nonce []byte `bencode:"nonce"`

	Tangles map[string]bencodeext.TanglePoint `bencode:"tangles"`
}

func (a *Add) UnmarshalBencode(input []byte) error {
	fmt.Fprintln(os.Stderr, hex.Dump(input))

	var wa wrappedAdd
	err := bencode.NewDecoder(bytes.NewReader(input)).Decode(&wa)
	if err != nil {
		return fmt.Errorf("metamgngmt: failed to unwrap bencode value: %w", err)
	}

	var subFeed, metaFeed tfk.Feed

	err = subFeed.UnmarshalBinary(wa.SubFeed)
	if err != nil {
		return err
	}

	err = metaFeed.UnmarshalBinary(wa.MetaFeed)
	if err != nil {
		return err
	}

	a.Type = string(wa.Type)
	a.FeedFormat = string(wa.FeedFormat)
	a.FeedPurpose = string(wa.FeedPurpose)

	a.SubFeed, err = subFeed.Feed()
	if err != nil {
		return err
	}

	a.MetaFeed, err = metaFeed.Feed()
	if err != nil {
		return err
	}

	a.Nonce = wa.Nonce

	a.Tangles = make(refs.Tangles, len(wa.Tangles))
	for name, tangle := range wa.Tangles {
		a.Tangles[name] = refs.TanglePoint(tangle)
	}

	return nil
}
