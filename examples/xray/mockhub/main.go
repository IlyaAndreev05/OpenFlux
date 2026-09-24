// Command mockhub runs an offline Xray/OpenFlux TCP path for environments
// where Yandex Docs are unreachable. It exercises OpenFlux's SOCKS and raw TCP
// ingress, packet tunnel, and configured pool-exit forwarding without the Yandex
// Docs WebSocket transport or its pool cipher. Supply the virtual destination
// and mapped target explicitly with --virtual and --target.
package main

import (
	"flag"
	"fmt"
	"io"
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

type closer interface {
	Close() error
}

func attachEdge(exit *tunnel.PoolExitNode, listen, ingress, virtual string) (closer, *tunnel.TCPTunnel, error) {
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
	var listener closer
	switch ingress {
	case "socks5":
		server := socks5.NewSOCKS5Server(listen, clientTunnel)
		if err := server.Bind(); err != nil {
			_ = clientTunnel.Close()
			_ = clientLink.Stop()
			_ = exitLink.Stop()
			return nil, nil, err
		}
		listener = server
		go func() {
			if err := server.Start(); err != nil && err != net.ErrClosed {
				log.Printf("SOCKS5 %s stopped: %v", listen, err)
			}
		}()
	case "tcp":
		tcpListener, err := net.Listen("tcp", listen)
		if err != nil {
			_ = clientTunnel.Close()
			_ = clientLink.Stop()
			_ = exitLink.Stop()
			return nil, nil, err
		}
		listener = tcpListener
		go serveTCP(tcpListener, clientTunnel, virtual)
	default:
		_ = clientTunnel.Close()
		_ = clientLink.Stop()
		_ = exitLink.Stop()
		return nil, nil, fmt.Errorf("unknown ingress %q", ingress)
	}
	log.Printf("mock OpenFlux %s edge ready on %s", ingress, listen)
	return listener, clientTunnel, nil
}

func serveTCP(listener net.Listener, tun *tunnel.TCPTunnel, target string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(local net.Conn) {
			defer local.Close()
			remote, err := tun.DialTCP(target)
			if err != nil {
				log.Printf("mock TCP ingress dial: %v", err)
				return
			}
			defer remote.Close()
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(remote, local)
				if cw, ok := remote.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				close(done)
			}()
			_, _ = io.Copy(local, remote)
			if cw, ok := local.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			<-done
		}(conn)
	}
}

func main() {
	utils.EnableDebug()
	listenA := flag.String("listen-a", "127.0.0.1:1081", "first local OpenFlux SOCKS5 listener")
	listenB := flag.String("listen-b", "127.0.0.1:1082", "second local OpenFlux SOCKS5 listener")
	virtual := flag.String("virtual", "", "virtual destination for the Xray server (required)")
	target := flag.String("target", "", "destination to which the virtual address is mapped (required)")
	ingress := flag.String("ingress", "socks5", "socks5 or tcp")
	flag.Parse()
	if *virtual == "" || *target == "" {
		log.Fatal("--virtual and --target are required")
	}

	exit, err := tunnel.NewPoolExitNodeWithForward(tunnel.ExitModeL4, *virtual, *target)
	if err != nil {
		log.Fatal(err)
	}
	if err := exit.Start(); err != nil {
		log.Fatal(err)
	}
	serverA, tunnelA, err := attachEdge(exit, *listenA, *ingress, *virtual)
	if err != nil {
		log.Fatal(err)
	}
	serverB, tunnelB, err := attachEdge(exit, *listenB, *ingress, *virtual)
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
