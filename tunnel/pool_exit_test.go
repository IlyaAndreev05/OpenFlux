package tunnel

import (
	"encoding/binary"
	"testing"
)

func TestPoolRewriteIPv4AddressRecalculatesChecksums(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8], pkt[9] = 64, 6
	oldSrc, oldDst := [4]byte{10, 64, 0, 1}, [4]byte{198, 51, 100, 9}
	copy(pkt[12:16], oldSrc[:])
	copy(pkt[16:20], oldDst[:])
	binary.BigEndian.PutUint16(pkt[20:22], 43000)
	binary.BigEndian.PutUint16(pkt[22:24], 443)
	pkt[32], pkt[33] = 0x50, 0x10
	newSrc := [4]byte{10, 10, 10, 2}
	out, ok := poolRewriteIPv4Address(pkt, 12, oldSrc, newSrc)
	if !ok {
		t.Fatal("valid IPv4 packet was rejected")
	}
	if string(out[12:16]) != string(newSrc[:]) || string(out[16:20]) != string(oldDst[:]) {
		t.Fatalf("wrong rewritten addresses: src=%v dst=%v", out[12:16], out[16:20])
	}
	if tunnelOnesComplement(out[:20]) != 0 {
		t.Fatal("IPv4 header checksum is invalid after address rewrite")
	}
	var src, dst [4]byte
	copy(src[:], out[12:16])
	copy(dst[:], out[16:20])
	if tunnelTCPChecksum(out[20:], src, dst) != 0 {
		t.Fatal("TCP checksum is invalid after address rewrite")
	}
	if _, ok := poolRewriteIPv4Address([]byte{1, 2, 3}, 12, oldSrc, newSrc); ok {
		t.Fatal("malformed IPv4 packet was accepted")
	}
	if _, ok := poolRewriteIPv4Address(pkt, 12, [4]byte{10, 64, 0, 2}, newSrc); ok {
		t.Fatal("packet with an unexpected source address was accepted")
	}
	fragment := append([]byte(nil), pkt...)
	binary.BigEndian.PutUint16(fragment[6:8], 0x2000)
	if _, ok := poolRewriteIPv4Address(fragment, 12, oldSrc, newSrc); ok {
		t.Fatal("fragmented TCP packet was accepted")
	}
}
