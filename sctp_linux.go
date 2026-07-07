//go:build linux && !386
// +build linux,!386

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
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

func setsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	// NOTE: syscall.SYS_SETSOCKOPT is undefined on 386
	r0, r1, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		SOL_SCTP,
		optname,
		optval,
		optlen,
		0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

func getsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	if runtime.GOARCH == "s390x" {
		optlen = uintptr(unsafe.Pointer(&optlen)) // #nosec G103
	}
	// NOTE: syscall.SYS_GETSOCKOPT is undefined on 386
	r0, r1, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		SOL_SCTP,
		optname,
		optval,
		optlen,
		0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

type rawConn struct {
	sockfd int
}

func (r rawConn) Control(f func(fd uintptr)) error {
	f(uintptr(r.sockfd))
	return nil
}

func (r rawConn) Read(f func(fd uintptr) (done bool)) error {
	panic("not implemented")
}

func (r rawConn) Write(f func(fd uintptr) (done bool)) error {
	panic("not implemented")
}

func (c *SCTPConn) SCTPWrite(b []byte, info *SndRcvInfo) (int, error) {
	var cbuf []byte
	if info != nil {
		cmsgBuf := toBuf(info)
		hdr := &syscall.Cmsghdr{
			Level: syscall.IPPROTO_SCTP,
			Type:  SCTP_CMSG_SNDRCV,
		}

		// bitwidth of hdr.Len is platform-specific,
		// so we use hdr.SetLen() rather than directly setting hdr.Len
		hdr.SetLen(syscall.CmsgSpace(len(cmsgBuf)))
		cbuf = append(toBuf(hdr), cmsgBuf...)
	}
	c.ioMu.RLock()
	fd := c.fd()
	if fd < 0 {
		c.ioMu.RUnlock()
		stream := uint16(0)
		if info != nil {
			stream = info.Stream
		}
		return 0, errors.Wrapf(syscall.EBADF, "SCTPWrite: failed to send SCTP message (fd=%d, len=%d, stream=%d)",
			fd, len(b), stream)
	}
	n, err := syscall.SendmsgN(fd, b, cbuf, nil, 0)
	c.ioMu.RUnlock()
	if err != nil {
		stream := uint16(0)
		if info != nil {
			stream = info.Stream
		}
		return n, errors.Wrapf(err, "SCTPWrite: failed to send SCTP message (fd=%d, len=%d, stream=%d)",
			fd, len(b), stream)
	}
	return n, nil
}

func parseSndRcvInfo(b []byte) (*SndRcvInfo, error) {
	msgs, err := syscall.ParseSocketControlMessage(b)
	if err != nil {
		return nil, errors.Wrap(err, "parseSndRcvInfo: failed to parse SCTP control message")
	}
	for _, m := range msgs {
		if m.Header.Level == syscall.IPPROTO_SCTP {
			switch m.Header.Type {
			case SCTP_CMSG_SNDRCV:
				p := unsafe.Pointer(&m.Data[0]) // #nosec G103
				return (*SndRcvInfo)(p), nil
			}
		}
	}
	return nil, nil
}

func parseNotification(b []byte) Notification {
	snType := SCTPNotificationType(nativeEndian.Uint16(b[:2]))

	switch snType {
	case SCTP_SHUTDOWN_EVENT:
		notification := SCTPShutdownEvent{
			sseType:    nativeEndian.Uint16(b[:2]),
			sseFlags:   nativeEndian.Uint16(b[2:4]),
			sseLength:  nativeEndian.Uint32(b[4:8]),
			sseAssocID: SCTPAssocID(nativeEndian.Uint32(b[8:])),
		}
		return &notification
	case SCTP_ASSOC_CHANGE:
		notification := SCTPAssocChangeEvent{
			sacType:            nativeEndian.Uint16(b[:2]),
			sacFlags:           nativeEndian.Uint16(b[2:4]),
			sacLength:          nativeEndian.Uint32(b[4:8]),
			sacState:           SCTPState(nativeEndian.Uint16(b[8:10])),
			sacError:           nativeEndian.Uint16(b[10:12]),
			sacOutboundStreams: nativeEndian.Uint16(b[12:14]),
			sacInboundStreams:  nativeEndian.Uint16(b[14:16]),
			sacAssocID:         SCTPAssocID(nativeEndian.Uint32(b[16:20])),
			sacInfo:            b[20:],
		}
		return &notification
	default:
		return nil
	}
}

// SCTPRead use syscall.Recvmsg to receive SCTP message and return sctp sndrcvinfo/notification if need
func (c *SCTPConn) SCTPRead(b []byte) (int, *SndRcvInfo, Notification, error) {
	c.ioMu.RLock()
	fd := c.fd()
	if fd < 0 {
		c.ioMu.RUnlock()
		return 0, nil, nil, errors.Wrapf(syscall.EBADF,
			"SCTPRead: failed to receive SCTP message (fd=%d, bufsize=%d)", fd, len(b))
	}
	oob := make([]byte, 254)
	n, oobn, recvflags, _, err := syscall.Recvmsg(fd, b, oob, 0)
	c.ioMu.RUnlock()
	if err != nil {
		return n, nil, nil, errors.Wrapf(err, "SCTPRead: failed to receive SCTP message (fd=%d, bufsize=%d)",
			fd, len(b))
	}

	if n == 0 && oobn == 0 {
		return 0, nil, nil, io.EOF
	}

	if recvflags&MSG_NOTIFICATION > 0 {
		notification := parseNotification(b[:n])
		return n, nil, notification, nil
	} else {
		var info *SndRcvInfo
		if oobn > 0 {
			info, err = parseSndRcvInfo(oob[:oobn])
		}
		return n, info, nil, err
	}
}

func (c *SCTPConn) Close() error {
	if c == nil {
		return syscall.EBADF
	}
	fd := atomic.SwapInt32(&c._fd, -1)
	if fd <= 0 {
		return syscall.EBADF
	}
	var errs []error
	// Phase 1: interrupt all blocking Recvmsg/Sendmsg calls
	if err := syscall.Shutdown(int(fd), syscall.SHUT_RDWR); err != nil {
		// Best effort: shutdown can fail for already-closed or not-connected sockets.
		// We still close fd below to complete teardown.
		_ = err // to avoid empty branch error
	}
	// Phase 2: wait for all in-flight I/O goroutines holding RLock to exit, then release fd
	c.ioMu.Lock()
	// Phase 3: ensure kernel completes SCTP SHUTDOWN handshake before destroying association.
	// Without SO_LINGER, close(fd) may destroy the association before SHUTDOWN_ACK arrives
	// from the peer, causing peers to fall back to heartbeat timeout (~30s) for disconnect
	// detection. Linger=1s is a safety net; the handshake normally completes in <100µs.
	if err := syscall.SetsockoptLinger(
		int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 1},
	); err != nil {
		errs = append(errs, fmt.Errorf("SCTP: failed to set SO_LINGER: %w", err))
	}
	if err := syscall.Close(int(fd)); err != nil {
		errs = append(errs, fmt.Errorf("SCTP: failed to close fd: %w", err))
	}
	c.ioMu.Unlock()
	return stderrors.Join(errs...)
}

func (c *SCTPConn) SetWriteBuffer(bytes int) error {
	return syscall.SetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_SNDBUF, bytes)
}

func (c *SCTPConn) GetWriteBuffer() (int, error) {
	return syscall.GetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
}

func (c *SCTPConn) SetReadBuffer(bytes int) error {
	return syscall.SetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_RCVBUF, bytes)
}

func (c *SCTPConn) GetReadBuffer() (int, error) {
	return syscall.GetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
}

func (c *SCTPConn) SetWriteTimeout(tv syscall.Timeval) error {
	return syscall.SetsockoptTimeval(c.fd(), syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)
}

func (c *SCTPConn) SetReadTimeout(tv syscall.Timeval) error {
	return syscall.SetsockoptTimeval(c.fd(), syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

func (c *SCTPConn) SetNonBlock(nonBlock bool) error {
	return syscall.SetNonblock(c.fd(), nonBlock)
}

func (c *SCTPConn) GetRtoInfo() (*RtoInfo, error) {
	return getRtoInfo(c.fd())
}

func (c *SCTPConn) SetRtoInfo(rtoInfo RtoInfo) error {
	return setRtoInfo(c.fd(), rtoInfo)
}

func (c *SCTPConn) GetAssocInfo() (*AssocInfo, error) {
	return getAssocInfo(c.fd())
}

func (c *SCTPConn) SetAssocInfo(info AssocInfo) error {
	return setAssocInfo(c.fd(), info)
}

func (c *SCTPConn) GetMaxSegSize() (*int, error) {
	return getMaxSegSize(c.fd())
}

func (c *SCTPConn) SetMaxSegSize(size int) error {
	return setMaxSegSize(c.fd(), size)
}

// ListenSCTP - start listener on specified address/port
func ListenSCTP(net string, laddr *SCTPAddr) (*SCTPListener, error) {
	return ListenSCTPExt(net, laddr, InitMsg{NumOstreams: SCTP_MAX_STREAM}, nil, nil, SCTP_DEFAULT_MAXSEG)
}

// ListenSCTPExt - start listener on specified address/port with given SCTP options
func ListenSCTPExt(
	network string,
	laddr *SCTPAddr,
	options InitMsg,
	rtoInfo *RtoInfo,
	assocInfo *AssocInfo,
	maxSeg int,
) (*SCTPListener, error) {
	return listenSCTPExtConfig(network, laddr, options, rtoInfo, assocInfo, maxSeg, nil)
}

// listenSCTPExtConfig - start listener on specified address/port with given SCTP options and socket configuration
func listenSCTPExtConfig(
	network string,
	laddr *SCTPAddr,
	options InitMsg,
	rtoInfo *RtoInfo,
	assocInfo *AssocInfo,
	maxSeg int,
	control func(network, address string, c syscall.RawConn) error,
) (*SCTPListener, error) {
	af, ipv6only := favoriteAddrFamily(network, laddr, nil, "listen")
	sock, err := syscall.Socket(
		af,
		syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC,
		syscall.IPPROTO_SCTP,
	)
	if err != nil {
		return nil, errors.Wrapf(err,
			"listenSCTPExtConfig: failed to create SCTP listener socket (family=%d)", af)
	}

	// close socket on error
	defer func() {
		if err != nil {
			err2 := syscall.Close(sock)
			if err2 != nil {
				fmt.Printf("listenSCTPExtConfig: close sock failed %v", err2)
			}
		}
	}()
	if err = setDefaultSockopts(sock, af, ipv6only); err != nil {
		return nil, errors.Wrapf(err, "listenSCTPExtConfig: failed to set default socket options "+
			"(family=%d, ipv6only=%v)",
			af, ipv6only)
	}

	// enable REUSEADDR option
	if err = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, errors.Wrap(err, "listenSCTPExtConfig: failed to set SO_REUSEADDR on listener")
	}

	if control != nil {
		rc := rawConn{sockfd: sock}
		if err = control(network, laddr.String(), rc); err != nil {
			return nil, errors.Wrap(err,
				"listenSCTPExtConfig: failed to execute control callback for listener")
		}
	}

	// RTO
	if rtoInfo != nil {
		err = setRtoInfo(sock, *rtoInfo)
		if err != nil {
			return nil, errors.Wrapf(err,
				"listenSCTPExtConfig: failed to set SCTP RTO info (initial=%dms, max=%dms, min=%dms)",
				rtoInfo.SrtoInitial, rtoInfo.SrtoMax, rtoInfo.StroMin)
		}
	}

	// MAXSEG
	if maxSeg > 0 {
		if err = setMaxSegSize(sock, maxSeg); err != nil {
			return nil, errors.Wrapf(err,
				"listenSCTPExtConfig: failed to set SCTP max segment size to %d bytes", maxSeg)
		}
	}

	// set default association parameters (RFC 6458 8.1.2)
	if assocInfo != nil {
		err = setAssocInfo(sock, *assocInfo)
		if err != nil {
			return nil, errors.Wrapf(err,
				"listenSCTPExtConfig: failed to set SCTP association info (maxRxt=%d, cookieLife=%dms)",
				assocInfo.AsocMaxRxt, assocInfo.CookieLife)
		}
	}

	err = setInitOpts(sock, options)
	if err != nil {
		return nil, errors.Wrapf(err,
			"listenSCTPExtConfig: failed to set SCTP init options "+
				"(ostreams=%d, instreams=%d, attempts=%d, timeout=%dms)",
			options.NumOstreams, options.MaxInstreams, options.MaxAttempts, options.MaxInitTimeout)
	}

	if laddr != nil {
		// If IP address and/or port was not provided so far, let's use the unspecified IPv4 or IPv6 address
		if len(laddr.IPAddrs) == 0 {
			switch af {
			case syscall.AF_INET:
				laddr.IPAddrs = append(laddr.IPAddrs, net.IPAddr{IP: net.IPv4zero})
			case syscall.AF_INET6:
				laddr.IPAddrs = append(laddr.IPAddrs, net.IPAddr{IP: net.IPv6zero})
			}
		}
		err = SCTPBind(sock, laddr, SCTP_BINDX_ADD_ADDR)
		if err != nil {
			return nil, errors.Wrapf(err,
				"listenSCTPExtConfig: failed to bind SCTP listener to %s", laddr.String())
		}
	}
	err = syscall.Listen(sock, syscall.SOMAXCONN)
	if err != nil {
		return nil, errors.Wrapf(err,
			"listenSCTPExtConfig: failed to listen on SCTP socket %s (backlog=%d)",
			laddr.String(), syscall.SOMAXCONN)
	}

	// epoll will be used in Accept() to avoid busy waiting because of non-blocking socket
	epfd, err := createEpollForSock(sock)
	if err != nil {
		return nil, errors.Wrap(err,
			"listenSCTPExtConfig: failed to create epoll for SCTP listener")
	}

	return &SCTPListener{
		fd:     sock,
		epfd:   epfd,
		cancel: make(chan struct{}),
	}, nil
}

// createEpollForSock - create an epoll for sock; return an epoll fd if no error
func createEpollForSock(sock int) (int, error) {
	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return -1, errors.Wrap(err, "createEpollForSock: failed to create epoll instance for SCTP socket")
	}

	// close epfd on error
	defer func() {
		if err != nil {
			err2 := syscall.Close(epfd)
			if err2 != nil {
				fmt.Printf("listenSCTPExtConfig: close sock failed %v", err2)
			}
		}
	}()

	event := syscall.EpollEvent{
		Events: syscall.EPOLLIN,
		Fd:     int32(sock),
	}
	err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, sock, &event)
	if err != nil {
		return -1, errors.Wrapf(err, "createEpollForSock: failed to add socket %d to epoll", sock)
	}
	return epfd, nil
}

func (ln *SCTPListener) IsStopped() bool {
	return ln.isStopped.Load()
}

// AcceptSCTP waits for and returns the next SCTP connection to the listener.
// it will use EpollWait to wait for a incoming connection then call syscall.Accept4 to accept
// user can set timeout for cancel to be done if SCTPListener.Close() is execulated
func (ln *SCTPListener) AcceptSCTP(timeout int) (*SCTPConn, error) {
	var events [1]syscall.EpollEvent
	for {
		select {
		case <-ln.cancel:
			ln.isStopped.Store(true)
			return nil, nil // Exit signal received, return with no error.
		default:
			n, err := syscall.EpollWait(ln.epfd, events[:], timeout)
			if err != nil {
				if err == syscall.EBADF {
					ln.isStopped.Store(true)
					return nil, nil // EpollWait() was canceled, return with no error.
				}
				// Other error occurred, return the error.
				return nil, errors.Wrap(err,
					"AcceptSCTP: epoll wait failed on SCTP listener")
			}

			if n == 0 {
				continue
			}

			if events[0].Fd == int32(ln.fd) {
				fd, _, err := syscall.Accept4(ln.fd, 0)
				if err != nil {
					return nil, errors.Wrap(err, "AcceptSCTP: failed to accept SCTP connection")
				}
				return NewSCTPConn(fd, nil), nil
			}
		}
	}
}

// Accept waits for and returns the next connection connection to the listener.
func (ln *SCTPListener) Accept(timeout int) (net.Conn, error) {
	return ln.AcceptSCTP(timeout)
}

func (ln *SCTPListener) Close() error {
	var errs []error

	if err := syscall.Shutdown(ln.fd, syscall.SHUT_RDWR); err != nil {
		errs = append(errs, fmt.Errorf("SCTP: failed to shutdown fd: %w", err))
	}
	if err := syscall.Close(ln.epfd); err != nil {
		errs = append(errs, fmt.Errorf("SCTP: failed to close epfd: %w", err))
	}
	if err := syscall.Close(ln.fd); err != nil {
		errs = append(errs, fmt.Errorf("SCTP: failed to close fd: %w", err))
	}

	select {
	case ln.cancel <- struct{}{}:
	default:
	}

	return stderrors.Join(errs...)
}

// DialSCTP - bind socket to laddr (if given) and connect to raddr
func DialSCTP(net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	return DialSCTPExt(
		net,
		laddr,
		raddr,
		InitMsg{NumOstreams: SCTP_MAX_STREAM},
		nil,
		nil,
		SCTP_DEFAULT_MAXSEG,
	)
}

// DialSCTPExt - same as DialSCTP but with given SCTP options
func DialSCTPExt(
	network string,
	laddr, raddr *SCTPAddr,
	options InitMsg,
	rtoInfo *RtoInfo,
	assocInfo *AssocInfo,
	maxSeg int,
) (*SCTPConn, error) {
	return dialSCTPExtConfig(network, laddr, raddr, options, rtoInfo, assocInfo, maxSeg, nil)
}

// dialSCTPExtConfig - same as DialSCTP but with given SCTP options and socket configuration
func dialSCTPExtConfig(
	network string,
	laddr, raddr *SCTPAddr,
	options InitMsg,
	rtoInfo *RtoInfo,
	assocInfo *AssocInfo,
	maxSeg int,
	control func(network, address string, c syscall.RawConn) error,
) (*SCTPConn, error) {
	af, ipv6only := favoriteAddrFamily(network, laddr, raddr, "dial")
	sock, err := syscall.Socket(
		af,
		syscall.SOCK_STREAM,
		syscall.IPPROTO_SCTP,
	)
	if err != nil {
		return nil, errors.Wrapf(err,
			"dialSCTPExtConfig: failed to create SCTP socket (family=%d)", af)
	}

	// close socket on error
	defer func() {
		if err != nil {
			err2 := syscall.Close(sock)
			if err2 != nil {
				fmt.Printf("listenSCTPExtConfig: close sock failed %v", err2)
			}
		}
	}()
	if err = setDefaultSockopts(sock, af, ipv6only); err != nil {
		return nil, errors.Wrapf(err,
			"dialSCTPExtConfig: failed to set default SCTP socket options (family=%d, ipv6only=%v)",
			af, ipv6only)
	}
	if control != nil {
		rc := rawConn{sockfd: sock}
		if err = control(network, laddr.String(), rc); err != nil {
			return nil, errors.Wrap(err,
				"dialSCTPExtConfig: failed to execute socket control callback")
		}
	}

	// RTO
	if rtoInfo != nil {
		err = setRtoInfo(sock, *rtoInfo)
		if err != nil {
			return nil, errors.Wrapf(err,
				"dialSCTPExtConfig: failed to set SCTP RTO info (initial=%dms, max=%dms, min=%dms)",
				rtoInfo.SrtoInitial, rtoInfo.SrtoMax, rtoInfo.StroMin)
		}
	}

	// AssocInfo
	if assocInfo != nil {
		err = setAssocInfo(sock, *assocInfo)
		if err != nil {
			return nil, errors.Wrapf(err,
				"dialSCTPExtConfig: failed to set SCTP association info (maxRxt=%d, cookieLife=%dms)",
				assocInfo.AsocMaxRxt, assocInfo.CookieLife)
		}
	}

	// MAXSEG
	if maxSeg > 0 {
		if err = setMaxSegSize(sock, maxSeg); err != nil {
			return nil, errors.Wrapf(err,
				"dialSCTPExtConfig: failed to set SCTP max segment size to %d bytes", maxSeg)
		}
	}

	err = setInitOpts(sock, options)
	if err != nil {
		return nil, errors.Wrapf(err,
			"dialSCTPExtConfig: failed to set SCTP init options "+
				"(ostreams=%d, instreams=%d, attempts=%d, timeout=%dms)",
			options.NumOstreams, options.MaxInstreams, options.MaxAttempts, options.MaxInitTimeout)
	}
	if laddr != nil {
		// If IP address and/or port was not provided so far, let's use the unspecified IPv4 or IPv6 address
		if len(laddr.IPAddrs) == 0 {
			switch af {
			case syscall.AF_INET:
				laddr.IPAddrs = append(laddr.IPAddrs, net.IPAddr{IP: net.IPv4zero})
			case syscall.AF_INET6:
				laddr.IPAddrs = append(laddr.IPAddrs, net.IPAddr{IP: net.IPv6zero})
			}
		}
		err = SCTPBind(sock, laddr, SCTP_BINDX_ADD_ADDR)
		if err != nil {
			return nil, errors.Wrapf(err,
				"dialSCTPExtConfig: failed to bind SCTP socket to local address %s", laddr.String())
		}
	}
	_, err = SCTPConnect(sock, raddr)
	switch err {
	/* Asynchronous preemption introduced in go1.14 can allow syscalls to be preempted with EINTR errors.
	 * Upon preemption, SA_RESTART may lead getsockopt to execute twice, which leads to
	 * the return of EISCONN, EALREADY, or EINPROGRESS on the previously connected socket.
	 * We still return the socket fd, but preserve the error and let the client-side decide
	 * whether these errors should be deemed as error or not.
	 */
	case syscall.EISCONN, syscall.EALREADY, syscall.EINPROGRESS:
		retErr := errors.Wrapf(err,
			"dialSCTPExtConfig: SCTP connect to %s returned async preemption error",
			raddr.String())
		err = nil // Prevent socket close by defer function on these errors
		return NewSCTPConn(sock, nil), retErr
	case nil:
		return NewSCTPConn(sock, nil), nil
	default:
		return nil, errors.Wrapf(err,
			"dialSCTPExtConfig: failed to connect SCTP socket to remote address %s", raddr.String())
	}
}
