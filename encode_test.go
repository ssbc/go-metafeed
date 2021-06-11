// SPDX-License-Identifier: MIT

package metafeed

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

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

type testVector struct {
	Description string

	KeyPairSeed hexString
	Author      refs.FeedRef

	Metadata []interface{} `json:",omitempty"`

	Entries []testVectorEntry
}

type testVectorEntry struct {
	EncodedData hexString

	Key refs.MessageRef

	Sequence         int32
	Previous         refs.MessageRef
	Timestamp        int64
	HighlevelContent interface{}
}

type tvHexMetadata struct {
	Name      string
	HexString hexString
}

type tvSubfeedAuthor struct {
	Name string
	Feed refs.FeedRef
}

func TestEncoder(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)

	// the vectors for other implementations
	var tv testVector
	tv.Description = "3 messages, not even metafeed related. Simple, arbitrary entries."

	dead := bytes.Repeat([]byte("dead"), 8)
	pubKey, privKey := generatePrivateKey(t, bytes.NewReader(dead))
	tv.KeyPairSeed = dead

	authorRef, err := refFromPubKey(pubKey)
	r.NoError(err)

	startTime = time.Date(1969, 12, 31, 23, 59, 55, 0, time.UTC).Unix()
	now = fakeNow

	t.Log("kp:", authorRef.Ref())

	tv.Author = authorRef

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

	tv.Entries = make([]testVectorEntry, len(msgs))

	// the wanted transfer objects as hex
	wantHex := []string{
		"6c6c33343a0002aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69316533343a01020000000000000000000000000000000000000000000000000000000000000000692d356531383a03027330316d4279747a4c696b65426f78326536363a04004c76c63e6b464da4dcb735bb169139b01ad0971a6495f164f7b53b1b7407a390922f0573478144f1982a0d237d30ab8b9dcbe1f578b332cac012102d8f0e2a0e65",
		"6c6c33343a0002aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69326533343a01023ead9763b4aa1c5fd14e2ba94c13cfdb759ac3919bd12bb3c0477e2d9b633b20692d346564313a69693165343a74797065343a74657374656536363a0400b9623836cfe6df0b92bb59f6b8e0281e5c0f002732ba87ce1486f39f09f16f292b8b5e79ca18eb481393033dda07bd3f8deae350829efb304b3da56599de350b65",
		"6c6c33343a0002aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69336533343a010298fa1b1849f13235b9ec5a46784f47a678856e352254049d6ab7e76fb97d5ff5692d336564373a636f6e7461637435353a4072745061746c7a70344e624644556238372f745649706274496262677454656d6f42684664633650584c303d2e6262666565642d763131303a73706563746174696e67693165343a74797065373a636f6e74616374656536363a040055c5161d8a04f54daf0f37e8caea0952644355cf8a2d02ef1ebf482f113b4212ba66199cf354f55520c15ae4454fc2c4471e5fa2b50d9f8be78a45e57e0f6f0065",
	}

	prevRef, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageMetaBencode)
	r.NoError(err)

	e := NewEncoder(privKey)
	e.WithNowTimestamps(true)

	for msgidx, msg := range msgs {
		seq := int32(msgidx + 1)

		var tvEntry testVectorEntry
		tvEntry.HighlevelContent = msg
		tvEntry.Sequence = seq

		tr, msgRef, err := e.Encode(seq, prevRef, msg)
		r.NoError(err, "msg[%02d]Encode failed", msgidx)
		r.NotNil(msgRef)

		got, err := tr.MarshalBencode()
		r.NoError(err, "msg[%02d]Marshal failed", msgidx)

		want, err := hex.DecodeString(wantHex[msgidx])
		r.NoError(err)

		a.Equal(len(want), len(got), "msg[%02d] wrong msg length", msgidx)
		if !a.Equal(want, got, "msg[%02d] compare failed", msgidx) {
			t.Log("got", hex.EncodeToString(got))
		}

		a.True(tr.Verify(nil), "msg[%02d] did not verify", msgidx)

		tvEntry.Key = msgRef
		tvEntry.EncodedData = got

		prevRef = msgRef

		var msg2 Message
		err = msg2.UnmarshalBencode(got)
		r.NoError(err, "msg[%02d] test decode failed", msgidx)
		t.Logf("msg[%02d] Message decode of %d bytes", msgidx, len(got))
		r.True(len(msg2.data) > 0)
		r.True(len(msg2.signature) > 0)

		t.Log("event bytes:", len(msg2.data))
		t.Log(hex.EncodeToString(msg2.data))

		var p Payload
		err = p.UnmarshalBencode(msg2.data)
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

// utils for test vector encoding

type hexString []byte

func (s hexString) MarshalJSON() ([]byte, error) {
	str := hex.EncodeToString([]byte(s))
	return json.Marshal(str)
}

func (s *hexString) UnmarshalJSON(data []byte) error {
	var strData string
	err := json.Unmarshal(data, &strData)
	if err != nil {
		return fmt.Errorf("hexString: json decode of string failed: %w", err)
	}

	rawData, err := hex.DecodeString(strData)
	if err != nil {
		return fmt.Errorf("hexString: decoding hex to raw bytes failed: %w", err)
	}

	*s = rawData
	return nil
}
