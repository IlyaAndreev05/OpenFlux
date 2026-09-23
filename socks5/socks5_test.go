package socks5

import (
	"io"
	"net"
	"testing"
	"time"
)

type testDialer struct {
	address string
	server  net.Conn
}

func (d *testDialer) DialTCP(address string) (net.Conn, error) {
	d.address = address
	client, server := net.Pipe()
	d.server = server
	go func() {
		_, _ = io.Copy(server, server)
		_ = server.Close()
	}()
	return client, nil
}

func TestSOCKS5ReadsFragmentedHandshakeAndRequest(t *testing.T) {
	dialer := &testDialer{}
	server := NewSOCKS5Server("127.0.0.1:0", dialer)
	client, proxy := net.Pipe()
	defer client.Close()
	go server.handleConnection(proxy)

	writeFragments(t, client, []byte{0x05, 0x01, 0x00})
	readExact(t, client, []byte{0x05, 0x00})

	request := []byte{0x05, 0x01, 0x00, 0x03, 0x0b}
	request = append(request, []byte("example.com")...)
	request = append(request, 0x01, 0xbb)
	writeFragments(t, client, request)
	readExact(t, client, []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if dialer.address != "example.com:443" {
		t.Fatalf("dialed %q, want example.com:443", dialer.address)
	}

	if _, err := client.Write([]byte("xray-stream")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("xray-stream"))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "xray-stream" {
		t.Fatalf("echo=%q", got)
	}
}

func TestSOCKS5RejectsUnsupportedAuthAndCommand(t *testing.T) {
	server := NewSOCKS5Server("127.0.0.1:0", &testDialer{})
	client, proxy := net.Pipe()
	go server.handleConnection(proxy)
	writeFragments(t, client, []byte{0x05, 0x01, 0x02})
	readExact(t, client, []byte{0x05, 0xff})
	_ = client.Close()

	client, proxy = net.Pipe()
	defer client.Close()
	go server.handleConnection(proxy)
	writeFragments(t, client, []byte{0x05, 0x01, 0x00})
	readExact(t, client, []byte{0x05, 0x00})
	writeFragments(t, client, []byte{0x05, 0x02, 0x00, 0x01})
	readExact(t, client, []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func writeFragments(t *testing.T, w io.Writer, data []byte) {
	t.Helper()
	for _, b := range data {
		if _, err := w.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
}

func readExact(t *testing.T, r io.Reader, want []byte) {
	t.Helper()
	_ = r.(net.Conn).SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
