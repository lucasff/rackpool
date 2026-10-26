package reach

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseXORMappedAddress(t *testing.T) {
	txid := []byte("abcdefghijkl")
	want := net.IPv4(203, 0, 113, 7).To4()
	b := make([]byte, 32)
	binary.BigEndian.PutUint16(b[0:], 0x0101)
	binary.BigEndian.PutUint16(b[2:], 12)
	binary.BigEndian.PutUint32(b[4:], stunCookie)
	copy(b[8:], txid)
	binary.BigEndian.PutUint16(b[20:], 0x0020)
	binary.BigEndian.PutUint16(b[22:], 8)
	b[25] = 0x01
	binary.BigEndian.PutUint16(b[26:], 7000^(stunCookie>>16))
	binary.BigEndian.PutUint32(b[28:], binary.BigEndian.Uint32(want)^stunCookie)
	ip, err := parseBindingResponse(b, txid)
	if err != nil || !ip.Equal(want) {
		t.Fatalf("got %v, %v; want %v", ip, err, want)
	}
	if _, err := parseBindingResponse(b, []byte("wrong-txid!!")); err == nil {
		t.Fatal("accepted a response to someone else's request")
	}
}

func TestNonPublic(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "192.168.1.1", "100.64.3.4", "127.0.0.1", "169.254.1.1"} {
		if !NonPublic(net.ParseIP(s)) {
			t.Errorf("%s should be non-public", s)
		}
	}
	if NonPublic(net.ParseIP("203.0.113.7")) {
		t.Error("public address flagged")
	}
}
