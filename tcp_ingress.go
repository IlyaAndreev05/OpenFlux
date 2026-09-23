package main

import (
	"fmt"
	"io"
	"log"
	"net"

	"openflux/transport"
	"openflux/tunnel"
)

const poolVirtualXrayEndpoint = "198.18.0.1:18443"

// runTCPIngress forwards every local TCP stream to the one virtual Xray
// endpoint. It is intended for a local Xray client whose VLESS/TLS outbound
// already targets this OpenFlux listener, so Xray needs no dialerProxy.
func runTCPIngress(trans transport.Transport, listenAddr string) {
	if err := validateTCPIngressListenAddress(listenAddr); err != nil {
		log.Fatalf("TCP ingress: %v", err)
	}
	tun := tunnel.NewTCPTunnelMode(trans, false, tunnel.ExitModeL4)
	defer tun.Close()
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("TCP ingress listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("Running as CLIENT (TCP ingress on %s -> %s)", listenAddr, poolVirtualXrayEndpoint)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("TCP ingress accept: %v", err)
				continue
			}
			log.Printf("TCP ingress stopped: %v", err)
			return
		}
		go relayPoolTCP(tun, conn)
	}
}

func relayPoolTCP(tun *tunnel.TCPTunnel, local net.Conn) {
	defer local.Close()
	remote, err := tun.DialTCP(poolVirtualXrayEndpoint)
	if err != nil {
		log.Printf("TCP ingress dial %s: %v", poolVirtualXrayEndpoint, err)
		return
	}
	defer remote.Close()
	finished := make(chan struct{})
	go func() {
		_, _ = io.Copy(remote, local)
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(finished)
	}()
	_, _ = io.Copy(local, remote)
	if cw, ok := local.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	<-finished
}

func validateTCPIngressListenAddress(listenAddr string) error {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q must use a loopback IP", listenAddr)
	}
	return nil
}
