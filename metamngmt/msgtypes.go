// Package metamngmt contains all the managment types that one needs to have in order to work with metafeeds.
//
// This includes:
//  - 'metafeed/seed'
//  - 'metafeed/add'
//  - 'metafeed/announce'
//  - 'metafeed/tombstone'

package metamngmt

import (
	refs "go.mindeco.de/ssb-refs"
)

// Seed is used to encrypt the seed as a private message to the main feed.
// By doing this we allow the main feed to reconstruct the meta feed and all sub feeds from this seed.
type Seed struct {
	Type     string       `json:"type"`
	MetaFeed refs.FeedRef `json:"metafeed"`
	Seed     Base64String `json:"seed"`
}

// NewSeedMessage returns a new Seed with the type: alread set
func NewSeedMessage(meta refs.FeedRef, seed []byte) Seed {
	return Seed{
		Type:     "metafeed/seed",
		MetaFeed: meta,
		Seed:     seed,
	}
}

// Add links the new sub feed with the main (meta)feed using a new message on the meta feed signed by both the main feed and the meta feed.
type Add struct {
	Type string `json:"type"`

	FeedFormat  string `json:"feedformat"`
	FeedPurpose string `json:"feedpurpose"`

	SubFeed  refs.FeedRef `json:"subfeed"`
	MetaFeed refs.FeedRef `json:"metafeed"`

	Nonce Base64String `json:"nonce"`

	Tangles refs.Tangles `json:"tangles"`
}

// NewAddMessage just initializes type and the passed fields.
// Callers need to set the right tangle point themselves afterwards.
func NewAddMessage(meta, sub refs.FeedRef, format, purpose string, nonce []byte) Add {
	return Add{
		Type: "metafeed/add",

		SubFeed:  sub,
		MetaFeed: meta,

		FeedFormat:  format,
		FeedPurpose: purpose,

		Nonce: nonce,

		Tangles: make(refs.Tangles),
	}
}

// Announce is used in order for existing applications to know that a feed supports meta feeds.
// This message is created on the main feed.
type Announce struct {
	Type     string       `json:"type"`
	MetaFeed refs.FeedRef `json:"metafeed"`
	Tangles  refs.Tangles `json:"tangles"`
}

// NewAnnounceMessage returns a new Announce message.
// Callers need to set the right tangle point themselves afterwards.
func NewAnnounceMessage(f refs.FeedRef) Announce {
	return Announce{
		Type:     "metafeed/announce",
		MetaFeed: f,

		Tangles: make(refs.Tangles),
	}
}

type Tombstone struct {
	Type    string       `json:"type"`
	SubFeed refs.FeedRef `json:"subfeed"`

	Tangles refs.Tangles `json:"tangles"`
}

// NewTombstoneMessage returns a new Tombstone message.
// Callers need to set the right tangle point themselves afterwards.
func NewTombstoneMessage(f refs.FeedRef) Tombstone {
	return Tombstone{
		Type:    "metafeed/tombstone",
		SubFeed: f,

		Tangles: make(refs.Tangles),
	}
}
