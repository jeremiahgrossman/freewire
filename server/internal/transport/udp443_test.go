package transport

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

// The UDP/443 carrier shares its port with the reachability probe, so the two
// must never be confused: a WireGuard packet (first byte 1..4) is relayed, a
// magic probe is echoed, and anything else is dropped. This drives all three
// through a real UDP/443 listener with a mock "WireGuard" that echoes.
func TestUDP443DispatchesRelayProbeAndDrop(t *testing.T) {
	// Mock local WireGuard: a UDP echo, standing in for wireguard-go on wgPort.
	wg, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	wgPort := wg.LocalAddr().(*net.UDPAddr).Port
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := wg.ReadFromUDP(b)
			if err != nil {
				return
			}
			wg.WriteToUDP(b[:n], from) //nolint:errcheck
		}
	}()

	port := freePortUDP(t)
	s := NewUDP443Server(wgPort, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx, port) //nolint:errcheck
	waitForUDP(t, port)

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	c, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 1. A WireGuard packet (type 4, transport data) must be relayed to the mock
	//    WireGuard and its echo returned to us.
	wgPkt := append([]byte{wgTransportData, 0, 0, 0}, []byte("wireguard-payload")...)
	c.Write(wgPkt)                                     //nolint:errcheck
	c.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("WireGuard packet was not relayed/echoed: %v", err)
	}
	if !bytes.Equal(buf[:n], wgPkt) {
		t.Fatalf("relayed packet corrupted: got %x", buf[:n])
	}

	// 2. A magic probe (padded to the floor) must be answered with magic+nonce,
	//    even on the port the carrier owns.
	nonce := bytes.Repeat([]byte{0xC3}, probeNonceLen)
	probe := append(append([]byte{}, probeMagic...), nonce...)
	for len(probe) < probeMinRequest {
		probe = append(probe, 0)
	}
	c.Write(probe)                                     //nolint:errcheck
	c.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	n, err = c.Read(buf)
	if err != nil {
		t.Fatalf("probe on the carrier port got no reply: %v", err)
	}
	want := append(append([]byte{}, probeMagic...), nonce...)
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("probe reply = %x, want magic+nonce %x", buf[:n], want)
	}

	// 3. A datagram that is neither (first byte 0x99) must be dropped: no reply.
	c.Write([]byte{0x99, 0x01, 0x02, 0x03})                   //nolint:errcheck
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)) //nolint:errcheck
	if _, err := c.Read(buf); err == nil {
		t.Fatal("a non-WireGuard, non-probe datagram was answered; the port is a reflector")
	}
}

// Two distinct clients must get their own relay session, so wireguard-go's reply
// to one never reaches the other. Without per-source sockets a single relay
// socket would send every peer's replies to whichever client spoke last.
func TestUDP443SeparatesClients(t *testing.T) {
	// Mock WireGuard that echoes the source port back, so each client can tell
	// whether it received its OWN reply.
	wg, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	wgPort := wg.LocalAddr().(*net.UDPAddr).Port
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := wg.ReadFromUDP(b)
			if err != nil {
				return
			}
			wg.WriteToUDP(b[:n], from) //nolint:errcheck
		}
	}()

	port := freePortUDP(t)
	s := NewUDP443Server(wgPort, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx, port) //nolint:errcheck
	waitForUDP(t, port)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}

	send := func(tag byte) []byte {
		c, err := net.DialUDP("udp4", nil, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		pkt := []byte{wgTransportData, 0, 0, 0, tag}
		c.Write(pkt)                                       //nolint:errcheck
		c.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("client %d got no reply: %v", tag, err)
		}
		return buf[:n]
	}

	if got := send(0xA1); got[len(got)-1] != 0xA1 {
		t.Fatalf("client A got the wrong reply tag: %x", got)
	}
	if got := send(0xB2); got[len(got)-1] != 0xB2 {
		t.Fatalf("client B got the wrong reply tag: %x", got)
	}
}
