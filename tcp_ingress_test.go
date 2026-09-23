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
