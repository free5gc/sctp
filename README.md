# SCTP - Stream Control Transmission Protocol for Go

A Go library implementing Stream Control Transmission Protocol (SCTP) for Linux systems, providing network connection primitives similar to Go's standard `net` package.

## What is SCTP?

SCTP is a transport protocol that combines the best features of TCP and UDP:
- **Multi-homing**: Support for multiple IP addresses per connection for redundancy
- **Multi-streaming**: Multiple independent message streams within a single connection  
- **Message-oriented**: Preserves message boundaries unlike TCP's byte-stream
- **Reliable delivery**: Built-in congestion control and reliable transmission

## When to Choose SCTP?

Choose SCTP over TCP/UDP when you need:

**SCTP vs TCP:**
- ✅ **Multi-homing**: Automatic failover between network paths
- ✅ **Message boundaries**: Send/receive complete messages, not byte streams
- ✅ **Multiple streams**: Parallel data flows without head-of-line blocking
- ✅ **Better congestion control**: More responsive than TCP in lossy networks

**SCTP vs UDP:**
- ✅ **Reliable delivery**: Guaranteed message delivery with retransmission
- ✅ **Congestion control**: Built-in network-friendly flow control
- ✅ **Connection-oriented**: Established sessions with state management
- ✅ **Ordered delivery**: In-order message delivery per stream (optional)

**Common Use Cases:**
- **Telecommunications**: SS7, Diameter, and 5G signaling protocols
- **Real-time applications**: VoIP, video streaming with multiple quality streams
- **Financial systems**: High-availability trading platforms with redundant connections
- **IoT/M2M**: Device communication requiring reliable message delivery
- **Load balancing**: Applications needing path diversity for performance

## Platform Requirements

- **Operating System**: Linux (kernel 2.6+)
- **Architecture**: All except 386
- **Kernel Module**: `sctp` module must be loaded (`modprobe sctp`)
- **System Packages**: `lksctp-tools` and `libsctp-dev`

```bash
# Ubuntu/Debian
sudo apt-get install lksctp-tools libsctp-dev
sudo modprobe sctp

# RHEL/CentOS
sudo yum install lksctp-tools lksctp-tools-devel
sudo modprobe sctp
```

## Quick Start

### Simple Client

```go
package main

import (
    "fmt"
    "github.com/free5gc/sctp"
)

func main() {
    // Resolve server address
    raddr, _ := sctp.ResolveSCTPAddr("sctp", "127.0.0.1:9999")
    
    // Connect to server
    conn, err := sctp.DialSCTP("sctp", nil, raddr)
    if err != nil {
        panic(err)
    }
    defer conn.Close()
    
    // Send message (uses default stream 0)
    _, err = conn.Write([]byte("Hello SCTP!"))
    if err != nil {
        panic(err)
    }
    
    // Read response
    buffer := make([]byte, 1024)
    n, err := conn.Read(buffer)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Received: %s\n", string(buffer[:n]))
}
```

### Simple Server

```go
package main

import (
    "fmt"
    "github.com/free5gc/sctp"
)

func main() {
    // Resolve listen address
    laddr, _ := sctp.ResolveSCTPAddr("sctp", ":9999")
    
    // Start listening
    listener, err := sctp.ListenSCTP("sctp", laddr)
    if err != nil {
        panic(err)
    }
    defer listener.Close()
    
    fmt.Println("SCTP server listening on :9999")
    
    for {
        // Accept connection
        conn, err := listener.AcceptSCTP()
        if err != nil {
            continue
        }
        
        // Handle connection in goroutine
        go func() {
            defer conn.Close()
            
            buffer := make([]byte, 1024)
            n, err := conn.Read(buffer)
            if err != nil {
                return
            }
            
            fmt.Printf("Received: %s\n", string(buffer[:n]))
            conn.Write([]byte("Echo: " + string(buffer[:n])))
        }()
    }
}
```

## Multi-homing Example

SCTP supports multiple IP addresses for redundancy and load balancing:

```go
// Server binds to multiple IP addresses
serverAddrs := "192.168.1.10/10.0.0.10:9999"
laddr, _ := sctp.ResolveSCTPAddr("sctp", serverAddrs)
listener, _ := sctp.ListenSCTP("sctp", laddr)
// SCTP automatically handles path selection and failover
```

**Complete example:** See [Multi-homed Server](docs/examples.md#multi-homed-server)

## Multi-streaming Support

SCTP supports multiple independent data streams within a single connection, allowing parallel message flows without blocking:

```go
// Enable stream metadata
conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)

// Send on specific stream with PPID
sendInfo := &sctp.SndRcvInfo{Stream: 1, PPID: 100}
conn.SCTPWrite([]byte("Message on stream 1"), sendInfo)

// Read receives stream information
n, rcvInfo, _, _ := conn.SCTPRead(buffer)
fmt.Printf("Stream %d: %s\n", rcvInfo.Stream, buffer[:n])
```

**Complete examples:** See [Stream-based Communication](docs/examples.md#stream-based-communication)

## Key Features

- **Simple API**: Similar to Go's `net` package (`Dial`, `Listen`, `Accept`)
- **Multi-homing Support**: Multiple IP addresses per connection
- **Advanced Configuration**: Retransmission timeouts, association parameters, stream settings
- **Cross-platform**: Full support on Linux, graceful degradation on other platforms
- **Thread-safe**: Safe for concurrent use

## Testing

```bash
# Run tests with race detection
go test ./... -race -cover

# Build example
cd example && go build

# Run server
./example -server -port 1000 -ip 10.10.0.1,10.20.0.1

# Run client
./example -port 1000 -ip 10.10.0.1,10.20.0.1
```

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.
