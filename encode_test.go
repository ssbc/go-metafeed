// SPDX-FileCopyrightText: 2021 The go-metafeed Authors
//
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
		"6c6c33343a0003aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd693165323a0602692d356531383a03027330316d4279747a4c696b65426f78326536363a0400e03f54d05b29d53141e5f48814f3649bf8333ed0bcc8f352ccabd7c72c58f460c4046f0b7ae01b6477363e5a9259619350405d7705adf948110836d0f751f10765",
		"6c6c33343a0003aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69326533343a01046187ab63afa7ff5119098714304e3fb6424eb95d036ff85e86988c20c5eb8548692d346564313a69693165343a74797065343a74657374656536363a0400513066a5ef4d738ea6a632e4f6ed425fc366edccb42996a012cfc901f5267326481f45e671c336eb500732ecbdc30c674d17cd898dce2beaabd2bb97a1b7420865",
		"6c6c33343a0003aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69336533343a010452af038c34f4b833d6e01fb75fe7c323bbac69baae854338e23f9683aca6a567692d336564373a636f6e7461637435353a4072745061746c7a70344e624644556238372f745649706274496262677454656d6f42684664633650584c303d2e6262666565642d763131303a73706563746174696e67693165343a74797065373a636f6e74616374656536363a0400143aecaca1d7766a4bf6ecff2fdd484b20625147d1ae47f368a1a935aaae4aa008c292e1a260e62f925ebcb81d7d61d880302c1447885f3ff4f5b0601264c80365",
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

	jsonEncoder := json.NewEncoder(vectorFile)
	jsonEncoder.SetIndent("", "  ")
	err = jsonEncoder.Encode(tv)
	r.NoError(err)
	r.NoError(vectorFile.Close())
}
