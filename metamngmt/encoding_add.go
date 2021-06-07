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
		return nil, fmt.Errorf("metafeed/add: failed to turn subfeed into tfk: %w", err)
	}
	sfBytes, err := subFeedTFK.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("metafeed/add: failed to encode tfk subfeed: %w", err)
	}

	metaFeedTFK, err := tfk.FeedFromRef(a.MetaFeed)
	if err != nil {
		return nil, fmt.Errorf("metafeed/add: failed to turn metafeed into tfk: %w", err)
	}
	mfBytes, err := metaFeedTFK.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("metafeed/add: failed to encode tfk metafeed: %w", err)
	}

	// now create a map of all the values and let the bencode lib sort it
	var value = wrappedAdd{
		Type:        bencodeext.String(a.Type),
		FeedFormat:  bencodeext.String(a.FeedFormat),
		FeedPurpose: bencodeext.String(a.FeedPurpose),
		SubFeed:     sfBytes,
		MetaFeed:    mfBytes,
		Nonce:       a.Nonce,
	}

	if n := len(a.Tangles); n > 0 {
		wrappedTangles := make(map[string]bencodeext.TanglePoint, n)

		for name, tangle := range a.Tangles {
			wrappedTangles[name] = bencodeext.TanglePoint(tangle)
		}

		value.Tangles = wrappedTangles
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