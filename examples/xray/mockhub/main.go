// Command mockhub runs an offline Xray/OpenFlux TCP path for environments
// where Yandex Docs are unreachable. It exercises OpenFlux's SOCKS ingress,
// packet tunnel, and fixed-address pool-exit forwarding without the Yandex
// Docs WebSocket transport or its pool cipher.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"openflux/socks5"
	"openflux/transport"
	"openflux/tunnel"
	"openflux/utils"
)

type memoryTransport struct {
	*transport.BaseTransport
	peer *memoryTransport
}

func newMemoryPair() (*memoryTransport, *memoryTransport) {
	a := &memoryTransport{BaseTransport: transport.NewBaseTransport(transport.DefaultConfig())}
	b := &memoryTransport{BaseTransport: transport.NewBaseTransport(transport.DefaultConfig())}
	a.peer, b.peer = b, a
	return a, b
}

func (m *memoryTransport) Start() error {
	if err := m.BaseTransport.Start(); err != nil {
		return err
	}
	m.SetConnected(true)
	return nil
}

func (m *memoryTransport) Send(data []byte) error {
	if !m.IsConnected() || m.peer == nil || !m.peer.IsConnected() {
		return net.ErrClosed
	}
	m.RecordSend(len(data))
	cp := append([]byte(nil), data...)
	m.peer.RecordReceive(len(cp))
	m.peer.CallReceive(cp)
	return nil
}

var nextID atomic.Uint64

func attachEdge(exit *tunnel.PoolExitNode, listen string) (*socks5.SOCKS5Server, *tunnel.TCPTunnel, error) {
	clientLink, exitLink := newMemoryPair()
	id := fmt.Sprintf("mock-edge-%d", nextID.Add(1))
	if err := clientLink.Start(); err != nil {
		return nil, nil, err
	}
	if err := exitLink.Start(); err != nil {
		_ = clientLink.Stop()
		return nil, nil, err
	}
	if err := exit.AddClient(id, exitLink); err != nil {
		_ = clientLink.Stop()
		_ = exitLink.Stop()
		return nil, nil, err
	}
	clientTunnel := tunnel.NewTCPTunnelMode(clientLink, false, tunnel.ExitModeL4)
	server := socks5.NewSOCKS5Server(listen, clientTunnel)
	if err := server.Bind(); err != nil {
		_ = clientTunnel.Close()
		_ = clientLink.Stop()
		_ = exitLink.Stop()
		return nil, nil, err
	}
	go func() {
		if err := server.Start(); err != nil && err != net.ErrClosed {
			log.Printf("SOCKS5 %s stopped: %v", listen, err)
		}
	}()
	log.Printf("mock OpenFlux edge ready on %s", listen)
	return server, clientTunnel, nil
}

func main() {
	utils.EnableDebug()
	listenA := flag.String("listen-a", "127.0.0.1:1081", "first local OpenFlux SOCKS5 listener")
	listenB := flag.String("listen-b", "127.0.0.1:1082", "second local OpenFlux SOCKS5 listener")
	virtual := flag.String("virtual", "198.18.0.1:18443", "only allowed virtual destination")
	target := flag.String("target", "127.0.0.1:18443", "loopback Xray exit listener")
	flag.Parse()

	exit, err := tunnel.NewPoolExitNodeWithForward(tunnel.ExitModeL4, *virtual, *target)
	if err != nil {
		log.Fatal(err)
	}
	if err := exit.Start(); err != nil {
		log.Fatal(err)
	}
	serverA, tunnelA, err := attachEdge(exit, *listenA)
	if err != nil {
		log.Fatal(err)
	}
	serverB, tunnelB, err := attachEdge(exit, *listenB)
	if err != nil {
		_ = serverA.Close()
		_ = tunnelA.Close()
		_ = exit.Stop()
		log.Fatal(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = serverA.Close()
	_ = serverB.Close()
	_ = tunnelA.Close()
	_ = tunnelB.Close()
	_ = exit.Stop()
}
