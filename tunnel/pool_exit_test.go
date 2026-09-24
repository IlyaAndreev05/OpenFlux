package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"openflux/transport"
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

func TestPoolL4ForwardRoutesAndUnmatchedPolicies(t *testing.T) {
	forward := &poolL4Forward{
		routes: map[netip.AddrPort]string{
			netip.MustParseAddrPort("198.18.0.1:18443"): "127.0.0.1:18443",
			netip.MustParseAddrPort("198.18.0.2:443"):   "xray.example:443",
		},
		unmatched: PoolForwardUnmatchedDeny,
	}
	for destination, want := range map[string]string{
		"198.18.0.1:18443": "127.0.0.1:18443",
		"198.18.0.2:443":   "xray.example:443",
	} {
		got, ok := resolvePoolL4Destination(destination, forward)
		if !ok || got != want {
			t.Fatalf("resolve %q = %q, %v; want %q, true", destination, got, ok, want)
		}
	}
	for _, destination := range []string{"198.18.0.1:80", "198.18.0.3:443", "127.0.0.1:18443", "invalid"} {
		if got, ok := resolvePoolL4Destination(destination, forward); ok {
			t.Fatalf("deny policy accepted destination %q as %q", destination, got)
		}
	}
	direct := &poolL4Forward{routes: forward.routes, unmatched: PoolForwardUnmatchedDirect}
	if got, ok := resolvePoolL4Destination("203.0.113.7:443", direct); !ok || got != "203.0.113.7:443" {
		t.Fatalf("direct unmatched policy changed destination: %q allowed=%v", got, ok)
	}
	if got, ok := resolvePoolL4Destination("198.18.0.2:443", direct); !ok || got != "xray.example:443" {
		t.Fatalf("direct policy skipped configured mapping: %q allowed=%v", got, ok)
	}
	if got, ok := resolvePoolL4Destination("203.0.113.7:443", nil); !ok || got != "203.0.113.7:443" {
		t.Fatalf("legacy unrestricted mode changed: %q allowed=%v", got, ok)
	}
}

func TestPoolExitForwardRoutesValidateL4AndTargets(t *testing.T) {
	valid := []PoolForwardRoute{
		{VirtualEndpoint: "198.18.0.1:18443", Target: "127.0.0.1:18443"},
		{VirtualEndpoint: "198.18.0.2:443", Target: "xray.example:443"},
	}
	if _, err := NewPoolExitNodeWithRoutes(ExitModeL3, valid, "deny"); err == nil {
		t.Fatal("accepted forward routes in L3 mode")
	}
	for _, routes := range [][]PoolForwardRoute{
		{{VirtualEndpoint: "not-an-ip:18443", Target: "127.0.0.1:18443"}},
		{{VirtualEndpoint: "198.18.0.1:18443", Target: "127.0.0.1"}},
		{
			{VirtualEndpoint: "198.18.0.1:18443", Target: "127.0.0.1:18443"},
			{VirtualEndpoint: "198.18.0.1:18443", Target: "xray.example:443"},
		},
	} {
		if _, err := NewPoolExitNodeWithRoutes(ExitModeL4, routes, "deny"); err == nil {
			t.Fatalf("accepted invalid routes: %#v", routes)
		}
	}
	if _, err := NewPoolExitNodeWithRoutes(ExitModeL4, valid, "invalid-policy"); err == nil {
		t.Fatal("accepted unknown unmatched policy")
	}
	if _, err := NewPoolExitNodeWithRoutes(ExitModeL4, nil, "deny"); err == nil {
		t.Fatal("accepted unmatched policy without routes")
	}
	node, err := NewPoolExitNodeWithRoutes(ExitModeL4, valid, "deny")
	if err != nil {
		t.Fatal(err)
	}
	_ = node.Stop()
	if _, err := NewPoolExitNodeWithForward(ExitModeL3, "198.18.0.1:18443", "127.0.0.1:18443"); err == nil {
		t.Fatal("legacy single route was accepted in L3 mode")
	}
	node, err = NewPoolExitNodeWithForward(ExitModeL4, "198.18.0.1:18443", "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	_ = node.Stop()
}

type poolExitTestMemoryTransport struct {
	*transport.BaseTransport
	peer *poolExitTestMemoryTransport
}

func newPoolExitTestMemoryPair() (*poolExitTestMemoryTransport, *poolExitTestMemoryTransport) {
	a := &poolExitTestMemoryTransport{BaseTransport: transport.NewBaseTransport(transport.DefaultConfig())}
	b := &poolExitTestMemoryTransport{BaseTransport: transport.NewBaseTransport(transport.DefaultConfig())}
	a.peer, b.peer = b, a
	return a, b
}

func (m *poolExitTestMemoryTransport) Start() error {
	if err := m.BaseTransport.Start(); err != nil {
		return err
	}
	m.SetConnected(true)
	return nil
}

func (m *poolExitTestMemoryTransport) Send(data []byte) error {
	if !m.IsConnected() || m.peer == nil || !m.peer.IsConnected() {
		return net.ErrClosed
	}
	copyOfData := append([]byte(nil), data...)
	m.peer.CallReceive(copyOfData)
	return nil
}

func TestPoolExitDirectTCPWithoutForwardRouteOrXray(t *testing.T) {
	destinationIP := poolExitTestNonLoopbackIPv4(t)
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	destination := net.JoinHostPort(destinationIP.String(), strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	clientLink, exitLink := newPoolExitTestMemoryPair()
	if err := clientLink.Start(); err != nil {
		t.Fatal(err)
	}
	defer clientLink.Stop()
	if err := exitLink.Start(); err != nil {
		t.Fatal(err)
	}
	exit, err := NewPoolExitNode(ExitModeL4)
	if err != nil {
		t.Fatal(err)
	}
	if err := exit.Start(); err != nil {
		t.Fatal(err)
	}
	defer exit.Stop()
	if err := exit.AddClient("direct-client", exitLink); err != nil {
		t.Fatal(err)
	}
	clientTunnel := NewTCPTunnelMode(clientLink, false, ExitModeL4)
	defer clientTunnel.Close()

	conn, err := clientTunnel.DialTCP(destination)
	if err != nil {
		t.Fatalf("dial direct destination without Xray: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("ordinary OpenFlux direct egress")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo=%q want %q", got, payload)
	}
}

func poolExitTestNonLoopbackIPv4(t *testing.T) net.IP {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot inspect local interfaces: %v", err)
	}
	for _, address := range addresses {
		ipNet, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip != nil && !ip.IsLoopback() {
			return ip
		}
	}
	t.Skip("no non-loopback IPv4 address available for direct-egress test")
	return nil
}
