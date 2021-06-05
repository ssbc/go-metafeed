// Package bencodeext defines some extenstions for bencode to work better with the existing JavaScript type system.
// Mainly, it adds a way to encode bools, null/undefined and unicode values without ambiguity.
//
// The concrete encoding table is taken from https://github.com/ssb-ngi-pointer/ssb-binary-field-encodings-spec
package bencodeext

import "github.com/zeebo/bencode"

var Null = bencode.RawMessage{'2', ':', 0x06, 0x02}
