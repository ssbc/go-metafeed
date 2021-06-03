package metafeed

import (
	"bytes"
	"encoding/hex"
	"io"
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

func TestEncoder(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	dead := bytes.Repeat([]byte("dead"), 8)
	pubKey, privKey := generatePrivateKey(t, bytes.NewReader(dead))

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

	// the wanted transfer objects as hex
	wantHex := []string{
		"6c6c33343a0002aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69316533343a01020000000000000000000000000000000000000000000000000000000000000000692d356531383a03027330316d4279747a4c696b65426f78326536343a648ca7cf3d768d9bf869370fb9946dfb94bd507e71b0bfedeb78f6baa1669d9b2a1e96095008471003f07993073eefd42f6b66fb3867b125c4521d8dc428190665",
		"6c6c33343a0002aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69326533343a0102ec91525798170050af5ed12364a8254d560e92fc93f278f1aa1939869a0fb76b692d346564313a69693165343a74797065343a74657374656536343ad1e6259e899d5bd7c2a7ee4939f7e39ff6f68ac78957be1445e476a7c0c12ec1273e8be6cd5ba89ad6bf67125151e9888469549d82625969eafd171bf90dd30b65",
		"6c6c33343a0002aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd69336533343a0102dcdb1c4a258d98b48bec5d04afee446cb76b689a497f7d25d6ad0f5f46bf80d8692d336564373a636f6e7461637435393a4072745061746c7a70344e624644556238372f745649706274496262677454656d6f42684664633650584c303d2e62656d657461666565642d763131303a73706563746174696e67693165343a74797065373a636f6e74616374656536343a03209d631bdc5a69f9e1390cfd3a9224da70e429e649648ad05121b6117e43a15903f7134c09398ea7d07bdaac724dd101dc6f4854a1ea473eb7609c6ecf170a65",
	}

	prevRef, err := refs.NewMessageRefFromBytes(bytes.Repeat([]byte{0}, 32), refs.RefAlgoMessageMetaBencode)
	r.NoError(err)

	e := NewEncoder(privKey)
	e.WithNowTimestamps(true)

	for msgidx, msg := range msgs {
		seq := int32(msgidx + 1)
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

		prevRef = msgRef

		var tr2 Transfer
		err = tr2.UnmarshalBencode(got)
		r.NoError(err, "msg[%02d] test decode failed", msgidx)
		t.Logf("msg[%02d] transfer decode of %d bytes", msgidx, len(got))
		r.True(len(tr2.data) > 0)
		r.True(len(tr2.signature) > 0)

		t.Log("event bytes:", len(tr2.data))
		t.Log(hex.EncodeToString(tr2.data))

		var p Payload
		err = p.UnmarshalBencode(tr2.data)
		r.NoError(err, "evt[%02d] unmarshal failed", msgidx)

		a.NotNil(p.Author, "evt[%02d] has author", msgidx)
		a.EqualValues(seq, p.Sequence)

		r.NotEqual(0, p.Timestamp.Unix())
		a.EqualValues(-5+msgidx, p.Timestamp.Unix())
	}
}
