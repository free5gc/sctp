// Copyright 2019 Wataru Ishida. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sctp

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/errors"
)

type resolveSCTPAddrTest struct {
	network       string
	litAddrOrName string
	addr          *SCTPAddr
	err           error
}

type rtoTest struct {
	inputRto    RtoInfo
	expectedRto RtoInfo
}

type assocInfoTest struct {
	input    AssocInfo
	expected AssocInfo
}

var resolveSCTPAddrTests = []resolveSCTPAddrTest{
	{"sctp", "127.0.0.1:0", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 0}, nil},
	{
		"sctp4",
		"127.0.0.1:65535",
		&SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 65535},
		nil,
	},

	{"sctp", "[::1]:0", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::1")}}, Port: 0}, nil},
	{"sctp6", "[::1]:65535", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::1")}}, Port: 65535}, nil},

	{
		"sctp",
		"[fe80::1%eth0]:0",
		&SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("fe80::1"), Zone: "eth0"}}, Port: 0},
		nil,
	},
	{
		"sctp6",
		"[fe80::1%eth0]:65535",
		&SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("fe80::1"), Zone: "eth0"}}, Port: 65535},
		nil,
	},

	{"sctp", ":12345", &SCTPAddr{Port: 12345}, nil},

	{
		"sctp",
		"127.0.0.1/10.0.0.1:0",
		&SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}, {IP: net.IPv4(10, 0, 0, 1)}}, Port: 0},
		nil,
	},
	{
		"sctp4",
		"127.0.0.1/10.0.0.1:65535",
		&SCTPAddr{
			IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}, {IP: net.IPv4(10, 0, 0, 1)}},
			Port:    65535,
		},
		nil,
	},
}

var rtoTests = []rtoTest{
	{
		RtoInfo{SrtoInitial: 3000, SrtoMax: 60000, StroMin: 1000},
		RtoInfo{SrtoInitial: 3000, SrtoMax: 60000, StroMin: 1000},
	},
	{
		RtoInfo{SrtoInitial: 100, SrtoMax: 200, StroMin: 200},
		RtoInfo{SrtoInitial: 100, SrtoMax: 200, StroMin: 200},
	},
	{
		RtoInfo{SrtoInitial: 400, SrtoMax: 400, StroMin: 400},
		RtoInfo{SrtoInitial: 400, SrtoMax: 400, StroMin: 400},
	},
}

var assocInfoTests = []assocInfoTest{
	{
		AssocInfo{
			AssocID:                0,
			AsocMaxRxt:             2,
			NumberPeerDestinations: 0,
			PeerRwnd:               0,
			LocalRwnd:              0,
			CookieLife:             100,
		},
		AssocInfo{
			AssocID:                0,
			AsocMaxRxt:             2,
			NumberPeerDestinations: 0,
			PeerRwnd:               0,
			LocalRwnd:              0,
			CookieLife:             100,
		},
	},
	{
		AssocInfo{
			AssocID:                0,
			AsocMaxRxt:             5,
			NumberPeerDestinations: 0,
			PeerRwnd:               0,
			LocalRwnd:              0,
			CookieLife:             200,
		},
		AssocInfo{
			AssocID:                0,
			AsocMaxRxt:             5,
			NumberPeerDestinations: 0,
			PeerRwnd:               0,
			LocalRwnd:              0,
			CookieLife:             200,
		},
	},
}

func TestSCTPAddrString(t *testing.T) {
	for _, tt := range resolveSCTPAddrTests {
		s := tt.addr.String()
		if tt.litAddrOrName != s {
			t.Errorf("expected %q, got %q", tt.litAddrOrName, s)
		}
	}
}

func TestResolveSCTPAddr(t *testing.T) {
	for _, tt := range resolveSCTPAddrTests {
		addr, err := ResolveSCTPAddr(tt.network, tt.litAddrOrName)
		if !reflect.DeepEqual(addr, tt.addr) || !reflect.DeepEqual(err, tt.err) {
			t.Errorf(
				"ResolveSCTPAddr(%q, %q) = %#v, %v, want %#v, %v",
				tt.network,
				tt.litAddrOrName,
				addr,
				err,
				tt.addr,
				tt.err,
			)
			continue
		}
		if err == nil {
			addr2, err := ResolveSCTPAddr(addr.Network(), addr.String())
			if !reflect.DeepEqual(addr2, tt.addr) || err != tt.err {
				t.Errorf(
					"(%q, %q): ResolveSCTPAddr(%q, %q) = %#v, %v, want %#v, %v",
					tt.network,
					tt.litAddrOrName,
					addr.Network(),
					addr.String(),
					addr2,
					err,
					tt.addr,
					tt.err,
				)
			}
		}
	}
}

var sctpListenerNameTests = []struct {
	net   string
	laddr *SCTPAddr
}{
	{"sctp4", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}}},
	{"sctp4", &SCTPAddr{}},
	{"sctp4", nil},
	{"sctp", &SCTPAddr{Port: 7777}},
}

func TestSCTPListenerName(t *testing.T) {
	for _, tt := range sctpListenerNameTests {
		ln, err := ListenSCTP(tt.net, tt.laddr)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		la := ln.Addr()
		if a, ok := la.(*SCTPAddr); !ok || a.Port == 0 {
			t.Fatalf("got %v; expected a proper address with non-zero port number", la)
		}
	}
}

func TestSCTPConcurrentAccept(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const N = 100
	var serverWg sync.WaitGroup
	var clientWg sync.WaitGroup
	serverWg.Add(1)
	go func(t *testing.T) {
		defer serverWg.Done()
		for range N {
			c, err := ln.Accept(1000)
			if err != nil {
				t.Fatalf("err: %v", err)
				return
			}
			c.Close()
		}
	}(t)
	fails := 0
	for range N {
		clientWg.Add(1)
		go func() {
			defer clientWg.Done()
			for {
				c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
				if err == nil {
					c.Close()
					break
				} else {
					fmt.Printf("err: %v", err)
					fails++
				}
			}
		}()
	}
	serverWg.Wait()
	clientWg.Wait()
	if fails > 5 {
		t.Fatalf("# of failed Dials: %v", fails)
	}
}

func TestSCTPCloseRecv(t *testing.T) {
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var conn net.Conn
	var wg sync.WaitGroup
	connReady := make(chan struct{}, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var xerr error
		conn, xerr = ln.Accept(1000)
		if xerr != nil {
			t.Fatal(xerr)
		}
		connReady <- struct{}{}
		buf := make([]byte, 256)
		_, xerr = conn.Read(buf)
		t.Logf("got error while read: %v", xerr)
		// SCTPRead wraps errors with pkg/errors; use errors.Cause to unwrap before comparing.
		// EBADF occurs when Close() completes before Read() enters Recvmsg.
		if xerr != io.EOF && errors.Cause(xerr) != syscall.EBADF {
			t.Fatalf("read failed: %v", xerr)
		}
	}()

	_, err = DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}

	<-connReady
	err = conn.Close()
	if err != nil {
		t.Fatalf("close failed: %v", err)
	}
	wg.Wait()
}

var sctpListener *SCTPListener

func TestSCTPSetRto(t *testing.T) {
	initMsg := InitMsg{NumOstreams: 3, MaxInstreams: 5, MaxAttempts: 4, MaxInitTimeout: 8}
	fails := 0
	for _, tt := range rtoTests {
		addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
		if listener, err := ListenSCTPExt("sctp", addr, initMsg, &tt.inputRto, nil, 0); err != nil {
			t.Fatalf("close failed: %v", err)
			return
		} else {
			sctpListener = listener
		}
		defer sctpListener.Close()
		rtoInfo, err := getRtoInfo(sctpListener.fd)

		if err != nil {
			fails++
		} else {
			if !reflect.DeepEqual(*rtoInfo, tt.expectedRto) {
				t.Errorf("RTO[0x%x] \t ExpectedRTO[0x%x]\n", rtoInfo, tt.expectedRto)
			}
		}
	}
}

func TestSctpSetAssocInfo(t *testing.T) {
	initMsg := InitMsg{NumOstreams: 3, MaxInstreams: 5, MaxAttempts: 4, MaxInitTimeout: 8}
	fails := 0
	for _, tt := range assocInfoTests {
		addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
		if listener, err := ListenSCTPExt("sctp", addr, initMsg, nil, &tt.input, 0); err != nil {
			t.Fatalf("close failed: %v", err)
			return
		} else {
			sctpListener = listener
		}
		defer sctpListener.Close()
		assocInfo, err := getAssocInfo(sctpListener.fd)

		if err != nil {
			fails++
		} else {
			if !reflect.DeepEqual(*assocInfo, tt.expected) {
				t.Errorf("\nOutput:\t%+v\nExpected:%+v\n", assocInfo, tt.expected)
			}
		}
	}
}

func TestNoDelay(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const N = 10
	var serverWg sync.WaitGroup
	var clientWg sync.WaitGroup
	for range N {
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			c, err := ln.Accept(1000)
			if err != nil {
				fmt.Printf("err: %v", err)
				return
			}
			c.Close()
		}()
	}
	fails := 0
	for range N {
		clientWg.Add(1)
		go func() {
			defer clientWg.Done()
			c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
			if err != nil {
				fails++
			} else {
				nodelayTest := func(i int) {
					if err := c.SetNoDelay(i); err != nil {
						t.Fatalf("SetNoDelay() failed %s", err)
					}
					if b, err := c.GetNoDelay(); err != nil {
						t.Fatalf("GetNoDelay() failed")
					} else if b != i {
						t.Fatalf("GetNoDelay() not match what is set")
					}
				}
				nodelayTest(1)
				nodelayTest(0)
				c.Close()
			}
		}()
	}
	serverWg.Wait()
	clientWg.Wait()
	if fails > 5 {
		t.Fatalf("# of failed Dials: %v", fails)
	}
}

func TestAcceptCancel(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatal(err)
	}
	const N = 1
	var wg sync.WaitGroup
	wg.Add(1)
	fails := 0
	go func() {
		for {
			c, err := ln.Accept(1000)
			if err != nil {
				switch err {
				case syscall.EINTR, syscall.EAGAIN:
					fmt.Printf("AcceptSCTP: %+v", err)
				case syscall.EBADF:
					fails++
					return
				default:
					fmt.Printf("Failed to accept: %+v", err)
					fails++
				}
				continue
			}
			if c != nil {
				c.Close()
			}
			if ln.isStopped.Load() {
				wg.Done()
				break
			}
		}
	}()
	ln.Close()
	wg.Wait()
	// BUG Accept() doesn't return even if we closed ln
	if fails > 0 {
		t.Fatalf("# of failed Dials: %v", fails)
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test 1: Verify error from SCTPConnect with nil address contains context
	_, err := SCTPConnect(-1, nil)
	if err == nil {
		t.Error("expected error for nil address")
	} else {
		errMsg := err.Error()
		// Verify error contains function name
		if !strings.Contains(errMsg, "SCTPConnect") {
			t.Errorf("error should contain 'SCTPConnect': %v", err)
		}
		// Verify error mentions nil
		if !strings.Contains(errMsg, "nil") {
			t.Errorf("error should mention nil address: %v", err)
		}
	}

	// Test 2: Test that DialSCTP errors contain proper context
	// Try to dial an invalid network type
	_, err = DialSCTP("invalid-network", nil, &SCTPAddr{Port: 1234})
	if err == nil {
		t.Error("expected error for invalid network")
	} else {
		errMsg := err.Error()
		// The error should be about unknown network or similar
		if !strings.Contains(errMsg, "network") && !strings.Contains(errMsg, "invalid") {
			t.Logf("Got error (may be OK): %v", err)
		}
	}

	// Test 3: Test error wrapping preserves error chain
	ln, err := ListenSCTP("sctp", &SCTPAddr{Port: 0})
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	// Get a connection to test socket options on
	var testConn *SCTPConn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept(1000)
		if err == nil && c != nil {
			if sctpConn, ok := c.(*SCTPConn); ok {
				testConn = sctpConn
			}
		}
	}()

	// Connect to get a valid connection
	clientConn, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	wg.Wait()

	if testConn != nil {
		defer testConn.Close()

		// Test GetNoDelay - if it errors, verify context
		_, err := testConn.GetNoDelay()
		if err != nil {
			// If it fails, verify error contains context
			if !strings.Contains(err.Error(), "GetNoDelay") && !strings.Contains(err.Error(), "SCTP_NODELAY") {
				t.Errorf("GetNoDelay error should contain operation context: %v", err)
			}
		}
	}
}

func TestBindErrorContext(t *testing.T) {
	// Create a socket for bind testing
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("failed to create socket: %v", err)
	}
	defer syscall.Close(sock)

	// Test 1: Bind with invalid flags should return error with context
	addr := &SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}},
		Port:    0,
	}

	err = SCTPBind(sock, addr, 999) // Invalid flag
	if err == nil {
		t.Error("expected error for invalid bind flags")
	} else {
		errMsg := err.Error()
		// Verify error contains function name
		if !strings.Contains(errMsg, "SCTPBind") {
			t.Errorf("error should contain 'SCTPBind': %v", err)
		}
		// Verify error mentions invalid flags
		if !strings.Contains(errMsg, "invalid") && !strings.Contains(errMsg, "flags") {
			t.Errorf("error should mention invalid flags: %v", err)
		}
		// Verify we can extract the underlying EINVAL error
		cause := errors.Cause(err)
		if cause != syscall.EINVAL {
			t.Errorf("expected syscall.EINVAL, got %v", cause)
		}
	}

	// Test 2: Bind with nil address should return error with context
	err = SCTPBind(sock, nil, SCTP_BINDX_ADD_ADDR)
	if err == nil {
		t.Error("expected error for nil address")
	} else {
		errMsg := err.Error()
		// Verify error contains function name
		if !strings.Contains(errMsg, "SCTPBind") {
			t.Errorf("error should contain 'SCTPBind': %v", err)
		}
		// Verify error mentions nil address
		if !strings.Contains(errMsg, "nil") {
			t.Errorf("error should mention nil address: %v", err)
		}
	}

	// Test 3: Valid bind should work and subsequent operations should show context
	validAddr := &SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}},
		Port:    0,
	}

	err = SCTPBind(sock, validAddr, SCTP_BINDX_ADD_ADDR)
	if err != nil {
		// If bind fails, error should contain address info
		errMsg := err.Error()
		if !strings.Contains(errMsg, "127.0.0.1") {
			t.Errorf("bind error should contain address: %v", err)
		}
		if !strings.Contains(errMsg, "add") || !strings.Contains(errMsg, "binding") {
			t.Errorf("bind error should describe the operation: %v", err)
		}
	}
}

// TestCloseWaitsForInflightSCTPRead verifies that Close() does not release the
// file descriptor until all in-flight SCTPRead calls have returned. Without this
// guarantee, the OS may reassign the fd to a new connection while an old goroutine
// is still blocked in Recvmsg, causing it to read data belonging to the new
// connection (fd reuse race / TOCTOU).
func TestCloseWaitsForInflightSCTPRead(t *testing.T) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(pair[1])

	conn := NewSCTPConn(pair[0], nil)

	readerEntered := make(chan struct{})
	readerExited := make(chan struct{})
	go func() {
		defer close(readerExited)
		close(readerEntered)
		buf := make([]byte, 256)
		conn.SCTPRead(buf) // blocks until Shutdown or data arrives
	}()

	<-readerEntered
	time.Sleep(10 * time.Millisecond) // give reader enough time to enter Recvmsg

	conn.Close() // before fix: returns immediately; after fix: waits for reader to exit

	// Key assertion: when Close() returns, the reader goroutine must have already exited
	select {
	case <-readerExited:
		// PASS: reader has exited, fd can be safely released to the OS
	default:
		t.Error("Close() returned before SCTPRead goroutine exited — fd reuse race possible")
	}
}
