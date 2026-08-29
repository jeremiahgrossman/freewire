package main

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWGBuildDNSQuery(t *testing.T) {
	q, id := wgBuildDNSQuery("captive.apple.com")
	if binary.BigEndian.Uint16(q[0:2]) != id {
		t.Error("returned id does not match the id in the message")
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		t.Error("QDCOUNT != 1")
	}
	// The name must round-trip through the parser the resolver uses, which is the
	// real check that the labels are encoded correctly.
	name, ok := essentialsQueryName(q)
	if !ok || name != "captive.apple.com" {
		t.Fatalf("parsed name = %q (ok=%v), want captive.apple.com", name, ok)
	}
	// Two queries must not share an id, or the reply check is meaningless.
	_, id2 := wgBuildDNSQuery("captive.apple.com")
	if id == id2 {
		t.Error("two queries got the same transaction id")
	}
}

// A portal that accepts TCP/53 and answers with anything must NOT count as
// permitted: the reply has to be to OUR query.
func TestWGDNSOverTCPRejectsMismatchedID(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Read the framed query, then reply with a valid-looking message
			// carrying a different id -- a portal's DNS responder.
			var lb [2]byte
			if _, err := readFull(c, lb[:]); err != nil {
				c.Close()
				continue
			}
			q := make([]byte, binary.BigEndian.Uint16(lb[:]))
			readFull(c, q) //nolint:errcheck
			reply := make([]byte, 12)
			binary.BigEndian.PutUint16(reply[0:2], ^binary.BigEndian.Uint16(q[0:2]))
			var out [2]byte
			binary.BigEndian.PutUint16(out[:], uint16(len(reply)))
			c.Write(out[:]) //nolint:errcheck
			c.Write(reply)  //nolint:errcheck
			c.Close()
		}
	}()

	res, ok := wgDNSOverTCP(ln.Addr().String())
	if ok {
		t.Fatalf("a mismatched-id reply counted as permitted (result %q)", res)
	}
	if res != "wrong id" {
		t.Errorf("result = %q, want %q", res, "wrong id")
	}
}

func TestWGDNSOverTCPAcceptsMatchingReply(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var lb [2]byte
			if _, err := readFull(c, lb[:]); err != nil {
				c.Close()
				continue
			}
			q := make([]byte, binary.BigEndian.Uint16(lb[:]))
			readFull(c, q) //nolint:errcheck
			reply := make([]byte, 12)
			copy(reply[0:2], q[0:2]) // echo the id
			var out [2]byte
			binary.BigEndian.PutUint16(out[:], uint16(len(reply)))
			c.Write(out[:]) //nolint:errcheck
			c.Write(reply)  //nolint:errcheck
			c.Close()
		}
	}()

	if _, ok := wgDNSOverTCP(ln.Addr().String()); !ok {
		t.Fatal("a correctly-echoed reply was not counted as permitted")
	}
}

// The whole point of the :80 rows: a portal answering with its login page must
// read as INTERCEPTED, not as a pass.
func TestWGHTTP80ClassifiesInterception(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer real.Close()
	host := strings.TrimPrefix(real.URL, "http://")

	if res := wgHTTP80(host, "/generate_204", 204, ""); !strings.HasPrefix(res, "OK") {
		t.Errorf("real origin: result = %q, want OK", res)
	}

	// A portal: answers 200 with a login page for every path, and 302s elsewhere.
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>Please sign in to continue</html>")) //nolint:errcheck
	}))
	defer portal.Close()
	phost := strings.TrimPrefix(portal.URL, "http://")

	if res := wgHTTP80(phost, "/generate_204", 204, ""); res != "intercepted" {
		t.Errorf("portal 200-for-204: result = %q, want intercepted", res)
	}
	if res := wgHTTP80(phost, "/hotspot-detect.html", 200, "Success"); res != "intercepted" {
		t.Errorf("portal wrong body: result = %q, want intercepted", res)
	}

	// A redirect must not be followed into a 200 that looks like a pass.
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, real.URL+"/generate_204", http.StatusFound)
	}))
	defer redir.Close()
	if res := wgHTTP80(strings.TrimPrefix(redir.URL, "http://"), "/generate_204", 204, ""); res != "intercepted" {
		t.Errorf("redirect: result = %q, want intercepted (redirects must not be followed)", res)
	}
}
