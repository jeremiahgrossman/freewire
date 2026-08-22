package main

import (
	"net"
	"testing"
)

// route resolves the gateway to a name unless told not to. On a network whose
// router answers reverse DNS the output reads "gateway: modem", and parsing
// that as an IP fails -- which silently removed HTTP CONNECT from the chain,
// since the path needs a gateway to probe.
func TestGatewayLookupAsksForNumericOutput(t *testing.T) {
	gw, err := getDefaultGateway()
	if err != nil {
		t.Skipf("no default route on this machine: %v", err)
	}
	if gw == "" {
		t.Fatal("empty gateway with no error")
	}
	// The whole point is that it parses as an address rather than a name.
	if net.ParseIP(gw) == nil {
		t.Errorf("gateway %q is not an IP; route was asked for names, not numbers", gw)
	}
}
