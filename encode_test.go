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
		vectors.HexMetadata{"Seed for Metafeed KeyPair", dead},
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
		"6c6c33343a0003aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69316533343a01040000000000000000000000000000000000000000000000000000000000000000692d356531383a03027330316d4279747a4c696b65426f78326536363a0400eedc7663d3ae2c65ffc61bb6ca7063b8dc28931c299927f54200f07fbe31fa478652bf85fdb2069fbb8d6f07a19235ae09ff69903fffd9728e8d10bd1a33b70065",
		"6c6c33343a0003aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69326533343a0104aff93016d731dd5d46fda06ba27215e63fc8bc957f9f83818370712d96dd499f692d346564313a69693165343a74797065343a74657374656536363a0400d6e69c1478c538756a0625820cb38692c4d76fb03e71cbb4000077e339549955d45e1f531e53b3c581d7398cfb86c0b4e737b03ab3ca5b6392286ea98dd3df0265",
		"6c6c33343a0003aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69336533343a01045877d72b6f1657ff2e3751f44ea261bf8cdb9ce96e8da4a492b03765b2b98693692d336564373a636f6e7461637435353a4072745061746c7a70344e624644556238372f745649706274496262677454656d6f42684664633650584c303d2e6262666565642d763131303a73706563746174696e67693165343a74797065373a636f6e74616374656536363a04007041e71e23e7043c416ab4e6e4f28cd91d0c765beb5491be14545ddcd5d71b06ef4f744add510a3f0c006fd6dab88ac4540a672ce5bd6219fd3c6dfc809e060365",
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

		t.Log("event bytes:", len(msg2.Data))
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
