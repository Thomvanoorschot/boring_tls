const std = @import("std");
const builtin = @import("builtin");

pub const c = @cImport({
    @cDefine("OPENSSL_NO_ASM", "1");

    switch (builtin.cpu.arch) {
        .x86_64 => {
            @cDefine("__x86_64", "1");
            @cDefine("__x86_64__", "1");
        },
        .aarch64 => {
            @cDefine("__AARCH64EL__", "1");
            @cDefine("__aarch64__", "1");
        },
        .x86 => {
            @cDefine("__i386__", "1");
        },
        .arm => {
            @cDefine("__ARMEL__", "1");
        },
        else => {},
    }

    switch (builtin.os.tag) {
        .linux => @cDefine("__linux__", "1"),
        .macos => @cDefine("__APPLE__", "1"),
        .windows => @cDefine("_WIN32", "1"),
        else => {},
    }

    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/x509v3.h");
});

pub const TlsError = error{
    TlsContextFailed,
    TlsConnectionFailed,
    BioFailed,
    TlsHandshakeFailed,
    TlsReadFailed,
    TlsWriteFailed,
    TlsNotReady,
    CertificateLoadFailed,
    PrivateKeyLoadFailed,
    CertificateVerificationFailed,
    TlsConnectionClosed,
};

/// Buffer size for TLS operations - must be large enough to handle full TLS records
/// TLS records can be up to 16KB, and we may receive multiple records at once
pub const BUFFER_SIZE = 32 * 1024;  // 32KB

pub fn initOpenSsl() void {
    _ = c.OPENSSL_init_ssl(c.OPENSSL_INIT_LOAD_SSL_STRINGS | c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);
}

pub fn createBio() !*c.BIO {
    return c.BIO_new(c.BIO_s_mem()) orelse {
        std.log.err("Failed to create BIO", .{});
        return TlsError.BioFailed;
    };
}

pub fn createSslInstance(ctx: *c.SSL_CTX) !*c.SSL {
    return c.SSL_new(ctx) orelse {
        std.log.err("Failed to create SSL instance", .{});
        return TlsError.TlsConnectionFailed;
    };
}

pub fn writeToBio(bio: *c.BIO, data: []const u8) !void {
    const written = c.BIO_write(bio, data.ptr, @intCast(data.len));
    if (written <= 0) {
        std.log.err("Failed to write to BIO", .{});
        return TlsError.TlsReadFailed;
    }
}

pub fn readFromBio(bio: *c.BIO, buffer: []u8) !usize {
    var total_read: usize = 0;
    var temp_buf: [BUFFER_SIZE]u8 = undefined;

    while (total_read < buffer.len) {
        const remaining = buffer.len - total_read;
        const read_size = @min(temp_buf.len, remaining);

        const bytes_read = c.BIO_read(bio, &temp_buf, @intCast(read_size));
        if (bytes_read <= 0) break;

        const actual_read = @as(usize, @intCast(bytes_read));
        @memcpy(buffer[total_read .. total_read + actual_read], temp_buf[0..actual_read]);
        total_read += actual_read;
    }

    return total_read;
}

pub fn handleSslReadError(ssl: *c.SSL, bytes_read: c_int) !?[]const u8 {
    const ssl_error = c.SSL_get_error(ssl, bytes_read);

    return switch (ssl_error) {
        c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => null,
        c.SSL_ERROR_ZERO_RETURN => TlsError.TlsConnectionClosed,
        else => {
            std.log.err("SSL_read failed with error: {}", .{ssl_error});
            logOpenSslError();
            return TlsError.TlsReadFailed;
        },
    };
}

pub fn sslWantsMoreData(ssl: *c.SSL, result: c_int) bool {
    const ssl_error = c.SSL_get_error(ssl, result);
    return ssl_error == c.SSL_ERROR_WANT_READ or ssl_error == c.SSL_ERROR_WANT_WRITE;
}

pub fn logOpenSslError() void {
    const err_code = c.ERR_get_error();
    if (err_code == 0) return;

    var err_buf: [256]u8 = undefined;
    _ = c.ERR_error_string_n(err_code, &err_buf, err_buf.len);
    std.log.err("OpenSSL error: {s}", .{std.mem.sliceTo(&err_buf, 0)});
}

pub fn logDetailedSslError(ssl: *c.SSL) void {
    std.log.err("=== SSL Error Details ===", .{});

    var error_count: u32 = 0;
    while (true) {
        const err_code = c.ERR_get_error();
        if (err_code == 0) break;

        var err_buf: [256]u8 = undefined;
        _ = c.ERR_error_string_n(err_code, &err_buf, err_buf.len);
        std.log.err("Error {}: {s}", .{ error_count, std.mem.sliceTo(&err_buf, 0) });
        error_count += 1;
    }

    if (error_count == 0) {
        std.log.err("No errors in OpenSSL queue", .{});
    }

    const state = c.SSL_get_state(ssl);
    const state_string = c.SSL_state_string_long(ssl);
    std.log.err("SSL State: {} ({s})", .{ state, @as([*:0]const u8, @ptrCast(state_string)) });

    std.log.err("=== End SSL Error Details ===", .{});
}

pub const TlsBuffers = struct {
    encrypted_buffer: [BUFFER_SIZE * 2]u8 = undefined,
    encrypted_len: usize = 0,
    decrypted_buffer: [BUFFER_SIZE * 2]u8 = undefined,
    decrypted_len: usize = 0,

    pub fn resetEncrypted(self: *TlsBuffers) void {
        self.encrypted_len = 0;
    }

    pub fn resetDecrypted(self: *TlsBuffers) void {
        self.decrypted_len = 0;
    }

    pub fn getEncryptedSlice(self: *TlsBuffers) []const u8 {
        return self.encrypted_buffer[0..self.encrypted_len];
    }

    pub fn getDecryptedSlice(self: *TlsBuffers) []const u8 {
        return self.decrypted_buffer[0..self.decrypted_len];
    }
};
