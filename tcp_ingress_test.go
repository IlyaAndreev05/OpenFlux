package main

import "testing"

func TestTCPIngressRequiresLoopbackListenAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:1081", "[::1]:1081"} {
		if err := validateTCPIngressListenAddress(address); err != nil {
			t.Errorf("rejected loopback address %q: %v", address, err)
		}
	}
	for _, address := range []string{":1081", "0.0.0.0:1081", "192.0.2.1:1081", "localhost:1081", "bad"} {
		if err := validateTCPIngressListenAddress(address); err == nil {
			t.Errorf("accepted non-loopback address %q", address)
		}
	}
}

func TestTCPIngressRequiresConfiguredIPv4Target(t *testing.T) {
	for _, target := range []string{"198.18.10.20:443", "xray.internal:18443", "127.0.0.1:1"} {
		if err := validateTCPIngressTarget(target); err != nil {
			t.Errorf("rejected valid target %q: %v", target, err)
		}
	}
	for _, target := range []string{"", "xray.internal", ":443", "127.0.0.1:0", "127.0.0.1:65536", "[::1]:443", "https://xray.internal:443"} {
		if err := validateTCPIngressTarget(target); err == nil {
			t.Errorf("accepted invalid target %q", target)
		}
	}
}
