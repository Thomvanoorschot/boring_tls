# BoringTLS

## Overview

BoringTLS is a comprehensive TLS/SSL library for the Zig programming language, providing both client and server implementations. Built on Google's BoringSSL cryptographic library, it offers a robust foundation for secure communication applications. The library provides a high-level, memory-safe Zig interface to TLS functionality while leveraging the battle-tested security of BoringSSL underneath.

## Features

### Core TLS Support
*   **Full TLS Protocol Support:** Complete implementation supporting TLS 1.2
*   **Strong Security:** Built on Google's BoringSSL for proven cryptographic security
*   **Memory Safety:** Zig-native interface with proper error handling and resource management
*   **Certificate Verification:** Configurable certificate validation for clients

## Getting Started

### Example
The package is probably to be used for some sort of network traffic protocol. An example implementation can be found
in another project of mine; https://github.com/Thomvanoorschot/async_zocket.
This project show the TLS server/client being used in a Websocket server/client.

### Installation

Use fetch:
```
zig fetch --save https://github.com/Thomvanoorschot/boring_tls/archive/main.tar.gz
```

Add BoringTLS to your `build.zig.zon`:

```zig
.dependencies = .{
    .boring_tls = .{
        .url = "https://github.com/Thomvanoorschot/boring_tls/archive/main.tar.gz",
        .hash = "...", // Update with actual hash
    },
},
```

### Basic Client Usage

```zig
const std = @import("std");
const BoringTLS = @import("boring_tls");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create TLS client
    var client = try BoringTLS.tls_client.TlsClient.init("example.com", .{
        .verify_certificate = true,
    });
    defer client.deinit();

    // Start TLS handshake
    if (try client.startHandshake()) |handshake_data| {
        // Send handshake_data to server over your transport
        std.log.info("Handshake data: {} bytes", .{handshake_data.len});
    }

    // Process server response (example)
    const server_response = "..."; // Data received from server
    if (try client.processIncoming(server_response)) |decrypted_data| {
        std.log.info("Received: {s}", .{decrypted_data});
    }

    // Send encrypted data
    const message = "Hello, secure world!";
    if (try client.processOutgoing(message)) |encrypted_data| {
        // Send encrypted_data to server over your transport
        std.log.info("Sending {} encrypted bytes", .{encrypted_data.len});
    }
}
```

### Basic Server Usage

```zig
const std = @import("std");
const BoringTLS = @import("boring_tls");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create TLS server with certificate and key files
    var server = try BoringTLS.tls_server.TlsServer.init(
        "server.crt",  // Path to certificate file
        "server.key"   // Path to private key file
    );
    defer server.deinit();

    // Process client connection (example)
    const client_data = "..."; // Data received from client
    if (try server.processIncoming(client_data)) |decrypted_data| {
        std.log.info("Client sent: {s}", .{decrypted_data});
        
        // Send response
        const response = "Hello, client!";
        if (try server.processOutgoing(response)) |encrypted_response| {
            // Send encrypted_response back to client
            std.log.info("Sending {} encrypted bytes", .{encrypted_response.len});
        }
    }
}
```

## API Reference

### TLS Client

**TlsClient**
- `TlsClient.init(hostname, options)` - Initialize a new TLS client
- `client.startHandshake()` - Begin TLS handshake, returns initial handshake data
- `client.processIncoming(data)` - Process encrypted data from server, returns decrypted data
- `client.processOutgoing(data)` - Encrypt data for sending, returns encrypted data
- `client.isHandshakeComplete()` - Check if TLS handshake is complete
- `client.deinit()` - Clean up client resources

**TlsClientOptions**
- `verify_certificate: bool` - Enable/disable certificate verification (default: true)

### TLS Server

**TlsServer**
- `TlsServer.init(cert_file, key_file)` - Initialize server with certificate and key files
- `server.processIncoming(data)` - Process encrypted data from client, returns decrypted data
- `server.processOutgoing(data)` - Encrypt data for sending, returns encrypted data
- `server.isHandshakeComplete()` - Check if TLS handshake is complete
- `server.deinit()` - Clean up server resources



## Project Status

**Production Ready** - The library provides complete TLS client and server functionality.

## Requirements

- **Zig 0.15.0-dev** or later
- **BoringSSL** (automatically built as dependency)

## Building

The project uses Zig's build system and automatically compiles BoringSSL as a static library:

```bash
zig build
```

The build process:
1. Compiles BoringSSL crypto and SSL libraries
2. Creates the BoringTLS Zig module
3. Links everything together for easy integration

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest features.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on [BoringSSL](https://boringssl.googlesource.com/boringssl/) by Google
- Inspired by the need for memory-safe TLS in Zig applications