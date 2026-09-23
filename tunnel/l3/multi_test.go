package l3

import (
	"encoding/binary"
	"sync"
	"testing"

	"openflux/transport"
)

type testMultiBackend struct {
	mu     sync.Mutex
	egress [4]byte
	sent   [][]byte
	recv   func([]byte)
}

func (b *testMultiBackend) EgressIP() [4]byte { return b.egress }
func (b *testMultiBackend) Send(pkt []byte) error {
	b.mu.Lock()
	b.sent = append(b.sent, append([]byte(nil), pkt...))
	b.mu.Unlock()
	return nil
}
func (b *testMultiBackend) Recv(cb func([]byte)) { b.recv = cb }
func (b *testMultiBackend) Close() error         { return nil }
func (b *testMultiBackend) emitted() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]byte(nil), b.sent...)
}

type testMultiTransport struct {
	cb       func([]byte)
	mu       sync.Mutex
	received [][]byte
}

func (t *testMultiTransport) Start() error { return nil }
func (t *testMultiTransport) Stop() error  { return nil }
func (t *testMultiTransport) Send(p []byte) error {
	t.mu.Lock()
	t.received = append(t.received, append([]byte(nil), p...))
	t.mu.Unlock()
	return nil
}
func (t *testMultiTransport) Receive(cb func([]byte))         { t.cb = cb }
func (t *testMultiTransport) IsConnected() bool               { return true }
func (t *testMultiTransport) Stats() transport.TransportStats { return transport.TransportStats{} }
func (t *testMultiTransport) emit(p []byte)                   { t.cb(p) }
func (t *testMultiTransport) packets() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.received...)
}

func testTCPPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 64, 6
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:22], srcPort)
	binary.BigEndian.PutUint16(p[22:24], dstPort)
	p[32] = 0x50
	p[33] = 0x10
	fixChecksums(p)
	return p
}

func TestMultiClientExitSeparatesIdenticalFlowsAndRestoresReplies(t *testing.T) {
	backend := &testMultiBackend{egress: [4]byte{203, 0, 113, 10}}
	exit := newMultiClientExit(backend)
	if err := exit.Start(); err != nil {
		t.Fatal(err)
	}
	defer exit.Stop()
	one, two := &testMultiTransport{}, &testMultiTransport{}
	if err := exit.AddClient("one", one); err != nil {
		t.Fatal(err)
	}
	if err := exit.AddClient("two", two); err != nil {
		t.Fatal(err)
	}
	src := [4]byte{10, 10, 10, 2}
	dst := [4]byte{198, 51, 100, 7}
	const srcPort, dstPort = uint16(40000), uint16(443)
	packet := testTCPPacket(src, dst, srcPort, dstPort)
	one.emit(packet)
	two.emit(packet)
	sent := backend.emitted()
	if len(sent) != 2 {
		t.Fatalf("backend sent %d packets, want 2", len(sent))
	}
	translated := make(map[uint16]bool)
	for _, p := range sent {
		if string(p[12:16]) != string(backend.egress[:]) {
			t.Fatalf("bad SNAT source %v", p[12:16])
		}
		translated[binary.BigEndian.Uint16(p[20:22])] = true
	}
	if len(translated) != 2 {
		t.Fatalf("identical client flow keys collided on translated port: %v", translated)
	}
	for _, p := range sent {
		reply := testTCPPacket(dst, backend.egress, dstPort, binary.BigEndian.Uint16(p[20:22]))
		backend.recv(reply)
	}
	gotOne, gotTwo := one.packets(), two.packets()
	if len(gotOne) != 1 || len(gotTwo) != 1 {
		t.Fatalf("reply counts: client one=%d two=%d", len(gotOne), len(gotTwo))
	}
	for _, got := range [][]byte{gotOne[0], gotTwo[0]} {
		if string(got[16:20]) != string(src[:]) {
			t.Fatalf("reply destination was not restored: %v", got[16:20])
		}
		if binary.BigEndian.Uint16(got[22:24]) != srcPort {
			t.Fatalf("reply destination port was not restored: %d", binary.BigEndian.Uint16(got[22:24]))
		}
	}
}
