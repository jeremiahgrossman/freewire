package main

import (
	"net"
	"testing"
	"time"
)

// The carrier's real peer is not always the configured server address, and the
// gap is what makes a fronted carrier fail in a way that looks like a working
// tunnel carrying nothing: routing pins the configured address, the split-default
// route then captures the carrier's own packets, and they loop into the tunnel.
// These tests pin the address-derivation half of that fix (the route commands
// themselves need a routed test, not a unit test).

// A stream carrier hands back a real connection, and its remote address is what
// must be pinned -- including when it is an edge IP the config never names.
func TestCarrierPeerAddrReadsEstablishedConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got := carrierPeerAddr(conn)
	if got != "127.0.0.1" {
		t.Fatalf("carrierPeerAddr = %q, want the connection's remote host 127.0.0.1", got)
	}
	// It must be a bare IP: pinOutsideTunnel routes a host, and a host:port
	// string would fail to parse as one.
	if net.ParseIP(got) == nil {
		t.Fatalf("carrierPeerAddr returned %q, which is not a bare IP", got)
	}
}

// The DNS and ICMP carriers run their own bridge and hand back no connection.
// Empty is the correct answer for them -- they pin their resolvers separately --
// so this must not be mistaken for an error or produce a bogus pin.
func TestCarrierPeerAddrNilTransportIsEmpty(t *testing.T) {
	if got := carrierPeerAddr(nil); got != "" {
		t.Fatalf("carrierPeerAddr(nil) = %q, want empty", got)
	}
}

// A connection whose RemoteAddr is unusable must yield "" rather than something
// that would be handed to `route add -host`.
func TestCarrierPeerAddrRejectsUnparseableRemote(t *testing.T) {
	if got := carrierPeerAddr(&fakeRemoteConn{remote: "not-a-host-port"}); got != "" {
		t.Fatalf("carrierPeerAddr = %q, want empty for an unparseable remote", got)
	}
	if got := carrierPeerAddr(&fakeRemoteConn{remote: ""}); got != "" {
		t.Fatalf("carrierPeerAddr = %q, want empty for an empty remote", got)
	}
}

// fakeRemoteConn is a net.Conn that reports an arbitrary RemoteAddr string.
type fakeRemoteConn struct {
	net.Conn
	remote string
}

func (f *fakeRemoteConn) RemoteAddr() net.Addr { return fakeAddr(f.remote) }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }
