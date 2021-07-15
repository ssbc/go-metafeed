// SPDX-License-Identifier: MIT

package metafeed

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/ssb-ngi-pointer/go-metafeed/internal/vectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	refs "go.mindeco.de/ssb-refs"
	"golang.org/x/crypto/ed25519"
)

var startTime = time.Date(1969, 12, 31, 23, 59, 55, 0, time.UTC).Unix()

func fakeNow() time.Time {
	t := time.Unix(startTime, 0)
	startTime++
	return t
}

func generatePrivateKey(t testing.TB, r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		t.Fatal(err)
	}

	return pub, priv
}

func TestEncoder(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)

	// the vectors for other implementations
	var tv vectors.Good
	tv.Description = "3 messages, not even metafeed related. Simple, arbitrary entries."

	dead := bytes.Repeat([]byte("dead"), 8)
	pubKey, privKey := generatePrivateKey(t, bytes.NewReader(dead))
	tv.Metadata = append(tv.Metadata,
		vectors.HexMetadata{Name: "Seed for Metafeed KeyPair", HexString: dead},
	)

	authorRef, err := refFromPubKey(pubKey)
	r.NoError(err)

	startTime = time.Date(1969, 12, 31, 23, 59, 55, 0, time.UTC).Unix()
	now = fakeNow

	t.Log("kp:", authorRef.Ref())

	var msgs = []interface{}{
		append([]byte{0x03, 0x02}, []byte("s01mBytzLikeBox2")...),
		map[string]interface{}{
			"type": "test",
			"i":    1,
		},
		map[string]interface{}{
			"type":       "contact",
			"contact":    authorRef.Ref(),
			"spectating": true,
		},
	}

	tv.Entries = make([]vectors.EntryGood, len(msgs))

	// the wanted transfer objects as hex
	wantHex := []string{
		"6c6c33343a0003aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd693165323a0602692d356531383a03027330316d4279747a4c696b65426f78326536363a0400eeabb52d3225d82e2fe64ce0b4f00d3080dcb4fb4dea0e133edabbe677e0e0965cf58f4d27b2f9e08f542f4c01d6f8fcb5fd00d7f965f1a0d2ac8ba94f0de70265",
		"6c6c33343a0003aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69326533343a0104bd4b6366cd26e275f6c4ada10c8df594998cdce18aac3f722899529a3126ecf3692d346564313a69693165343a74797065343a74657374656536363a04002112e3ec3ea3100bbc8d5d2176577cc6a25e9f3f7073e0afcdde4c7ffa1005e15263b02558035d5449dc5244e61f98bd7081ad2dc6f4179524bf9b881ab6d50d65",
		"6c6c33343a0003aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69336533343a01043aa3fffebfd5587c4a39e6e3606d999c226b78cb98c09d65d6b5e030c9f39126692d336564373a636f6e7461637435353a4072745061746c7a70344e624644556238372f745649706274496262677454656d6f42684664633650584c303d2e6262666565642d763131303a73706563746174696e67693165343a74797065373a636f6e74616374656536363a0400f5c64cadeb470a601c31527c5486b0b16a81baccdb590025f1d0259443be187e250aafaf8e4a91464493c015fa62eaa5a6f016f38d46c731750dbd0c2a1e1a0465",
	}

	prevRef, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageBendyButt)
	r.NoError(err)

	e := NewEncoder(privKey)
	e.WithNowTimestamps(true)

	for msgidx, msg := range msgs {
		seq := int32(msgidx + 1)

		var tvEntry vectors.EntryGood
		tvEntry.HighlevelContent = msg
		tvEntry.Author = authorRef
		tvEntry.Sequence = seq

		signedMsg, msgRef, err := e.Encode(seq, prevRef, msg)
		r.NoError(err, "msg[%02d]Encode failed", msgidx)
		r.NotNil(msgRef)

		got, err := signedMsg.MarshalBencode()
		r.NoError(err, "msg[%02d]Marshal failed", msgidx)

		want, err := hex.DecodeString(wantHex[msgidx])
		r.NoError(err)

		a.Equal(len(want), len(got), "msg[%02d] wrong msg length", msgidx)
		if !a.Equal(want, got, "msg[%02d] compare failed", msgidx) {
			t.Log("got", hex.EncodeToString(got))
		}

		a.True(signedMsg.Verify(nil), "msg[%02d] did not verify", msgidx)

		tvEntry.Key = msgRef
		tvEntry.EncodedData = got

		prevRef = msgRef

		var msg2 Message
		err = msg2.UnmarshalBencode(got)
		r.NoError(err, "msg[%02d] test decode failed", msgidx)
		t.Logf("msg[%02d] Message decode of %d bytes", msgidx, len(got))
		r.True(len(msg2.Data) > 0)
		r.True(len(msg2.Signature) > 0)
		tvEntry.Signature = msg2.Signature

		t.Log("data bytes:", len(msg2.Data))
		t.Log(hex.EncodeToString(msg2.Data))

		var p Payload
		err = p.UnmarshalBencode(msg2.Data)
		r.NoError(err, "evt[%02d] unmarshal failed", msgidx)

		a.NotNil(p.Author, "evt[%02d] has author", msgidx)
		a.EqualValues(seq, p.Sequence)

		tvEntry.Previous = p.Previous

		gotTs := p.Timestamp.Unix()
		r.NotEqual(0, gotTs)
		a.EqualValues(-5+msgidx, gotTs)
		tvEntry.Timestamp = gotTs

		tv.Entries[msgidx] = tvEntry
	}

	vectorFile, err := os.OpenFile("testvector-simple.json", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	r.NoError(err)

	err = json.NewEncoder(vectorFile).Encode(tv)
	r.NoError(err)
	r.NoError(vectorFile.Close())
}
