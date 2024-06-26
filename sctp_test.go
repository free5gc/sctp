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
	"sync"
	"syscall"
	"testing"
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
	const N = 10
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			for {
				c, err := ln.Accept(1000)
				if err != nil {
					fmt.Printf("err: %v", err)
					break
				}
				c.Close()
			}
			wg.Done()
		}()
	}
	attempts := 10 * N
	fails := 0
	for i := 0; i < attempts; i++ {
		c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
		if err != nil {
			fmt.Printf("err: %v", err)
			fails++
		} else {
			c.Close()
		}
	}
	ln.Close()
	// BUG Accept() doesn't return even if we closed ln
	//	wg.Wait()
	if fails > 5 {
		t.Fatalf("# of failed Dials: %v", fails)
	}
}

func TestSCTPCloseRecv(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
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
		if xerr != io.EOF && xerr != syscall.EBADF {
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
	const N = 10
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			for {
				c, err := ln.Accept(1000)
				if err != nil {
					fmt.Printf("err: %v", err)
					break
				}
				c.Close()
			}
			wg.Done()
		}()
	}
	attempts := 10 * N
	fails := 0
	for i := 0; i < attempts; i++ {
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
	}
	ln.Close()
	// BUG Accept() doesn't return even if we closed ln
	//	wg.Wait()
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
