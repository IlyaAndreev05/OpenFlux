package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	"openflux/transport"
	"openflux/tunnel"
)

// runTCPIngress forwards each accepted TCP stream to the configured target.
// Since a raw TCP stream contains no destination metadata, the target must be
// supplied by the user (or loaded from the pool client config).
func runTCPIngress(trans transport.Transport, listenAddr, target string) {
	if err := validateTCPIngressListenAddress(listenAddr); err != nil {
		log.Fatalf("TCP ingress: %v", err)
	}
	if err := validateTCPIngressTarget(target); err != nil {
		log.Fatalf("TCP ingress target: %v", err)
	}
	target = strings.TrimSpace(target)
	tun := tunnel.NewTCPTunnelMode(trans, false, tunnel.ExitModeL4)
	defer tun.Close()
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("TCP ingress listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("Running as CLIENT (TCP ingress on %s -> %s)", listenAddr, target)
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
		go relayPoolTCP(tun, target, conn)
	}
}

func relayPoolTCP(tun *tunnel.TCPTunnel, target string, local net.Conn) {
	defer local.Close()
	remote, err := tun.DialTCP(target)
	if err != nil {
		log.Printf("TCP ingress dial %s: %v", target, err)
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

func validateTCPIngressTarget(target string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil || host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "\x00\r\n/?#") {
		return fmt.Errorf("target %q must be a host:port TCP destination", target)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return fmt.Errorf("target %q uses IPv6, but the pool TCP tunnel currently supports IPv4", target)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("target %q port must be between 1 and 65535", target)
	}
	return nil
}
