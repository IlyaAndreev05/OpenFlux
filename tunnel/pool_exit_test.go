package tunnel

import (
	"encoding/binary"
	"net/netip"
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

func TestPoolL4ForwardRouteAllowsOnlyConfiguredEndpoint(t *testing.T) {
	forward := &poolL4Forward{
		virtualEndpoint: netip.MustParseAddrPort("198.18.0.1:18443"),
		target:          netip.MustParseAddrPort("127.0.0.1:18443"),
	}
	got, ok := resolvePoolL4Destination("198.18.0.1:18443", forward)
	if !ok || got != "127.0.0.1:18443" {
		t.Fatalf("resolved=%q allowed=%v", got, ok)
	}
	for _, destination := range []string{"198.18.0.1:80", "198.18.0.2:18443", "127.0.0.1:18443", "invalid"} {
		if got, ok := resolvePoolL4Destination(destination, forward); ok {
			t.Fatalf("accepted destination %q as %q", destination, got)
		}
	}
	if got, ok := resolvePoolL4Destination("203.0.113.7:443", nil); !ok || got != "203.0.113.7:443" {
		t.Fatalf("legacy unrestricted mode changed: %q allowed=%v", got, ok)
	}
}

func TestPoolExitForwardRequiresLoopbackTargetAndL4(t *testing.T) {
	for _, tc := range []struct {
		mode   ExitMode
		target string
	}{
		{ExitModeL3, "127.0.0.1:18443"},
		{ExitModeL4, "203.0.113.1:18443"},
		{ExitModeL4, "[::1]:18443"},
	} {
		if _, err := NewPoolExitNodeWithForward(tc.mode, "198.18.0.1:18443", tc.target); err == nil {
			t.Fatalf("accepted mode=%s target=%q", tc.mode, tc.target)
		}
	}
	node, err := NewPoolExitNodeWithForward(ExitModeL4, "198.18.0.1:18443", "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	_ = node.Stop()
}
