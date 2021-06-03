module github.com/ssb-ngi-pointer/go-metafeed

go 1.16

require (
	github.com/kr/pretty v0.1.0 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/zeebo/bencode v1.0.0
	go.mindeco.de v1.12.0
	go.mindeco.de/ssb-refs v0.3.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

// just temporary for the new RefAlgos
replace go.mindeco.de/ssb-refs => /home/cryptix/go-repos/ssb-refs

// We need our internal/extra25519 since agl pulled his repo recently.
// Issue: https://github.com/cryptoscope/ssb/issues/44
// Ours uses a fork of x/crypto where edwards25519 is not an internal package,
// This seemed like the easiest change to port agl's extra25519 to use x/crypto
// Background: https://github.com/agl/ed25519/issues/27#issuecomment-591073699
// The branch in use: https://github.com/cryptix/golang_x_crypto/tree/non-internal-edwards
replace golang.org/x/crypto => github.com/cryptix/golang_x_crypto v0.0.0-20200924101112-886946aabeb8
