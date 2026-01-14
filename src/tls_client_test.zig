const std = @import("std");
const testing = std.testing;
const tls = @import("tls.zig");

const c = tls.c;

// ============================================================================
// BIO Buffer Tests
// ============================================================================

test "BIO: write and read back" {
    tls.initOpenSsl();

    const bio = try tls.createBio();
    defer _ = c.BIO_free(bio);

    // Write some data
    const test_data = "Hello, TLS!";
    try tls.writeToBio(bio, test_data);

    // Check pending
    const pending = c.BIO_ctrl_pending(bio);
    try testing.expectEqual(@as(c_ulong, test_data.len), pending);

    // Read back
    var buffer: [256]u8 = undefined;
    const read_len = try tls.readFromBio(bio, &buffer);
    try testing.expectEqual(test_data.len, read_len);
    try testing.expectEqualStrings(test_data, buffer[0..read_len]);
}

test "BIO: multiple writes accumulate" {
    tls.initOpenSsl();

    const bio = try tls.createBio();
    defer _ = c.BIO_free(bio);

    // Write in multiple chunks
    try tls.writeToBio(bio, "Hello");
    try tls.writeToBio(bio, ", ");
    try tls.writeToBio(bio, "World!");

    const pending = c.BIO_ctrl_pending(bio);
    try testing.expectEqual(@as(c_ulong, 13), pending); // "Hello, World!" = 13

    var buffer: [256]u8 = undefined;
    const read_len = try tls.readFromBio(bio, &buffer);
    try testing.expectEqualStrings("Hello, World!", buffer[0..read_len]);
}

test "BIO: partial read leaves data" {
    tls.initOpenSsl();

    const bio = try tls.createBio();
    defer _ = c.BIO_free(bio);

    const test_data = "ABCDEFGHIJ"; // 10 bytes
    try tls.writeToBio(bio, test_data);

    // Read only 5 bytes using raw BIO_read
    var buffer: [5]u8 = undefined;
    const bytes_read = c.BIO_read(bio, &buffer, 5);
    try testing.expectEqual(@as(c_int, 5), bytes_read);
    try testing.expectEqualStrings("ABCDE", &buffer);

    // 5 bytes should remain
    const pending = c.BIO_ctrl_pending(bio);
    try testing.expectEqual(@as(c_ulong, 5), pending);
}

// ============================================================================
// TLS Record Structure Constants
// ============================================================================

const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_CONTENT_TYPE_ALERT: u8 = 0x15;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

const TLS_VERSION_1_0: [2]u8 = .{ 0x03, 0x01 };
const TLS_VERSION_1_1: [2]u8 = .{ 0x03, 0x02 };
const TLS_VERSION_1_2: [2]u8 = .{ 0x03, 0x03 };

/// Create a fake TLS record header
fn makeTlsRecordHeader(content_type: u8, version: [2]u8, length: u16) [5]u8 {
    return .{
        content_type,
        version[0],
        version[1],
        @intCast(length >> 8),
        @intCast(length & 0xFF),
    };
}

test "TLS record header construction" {
    const header = makeTlsRecordHeader(TLS_CONTENT_TYPE_APPLICATION_DATA, TLS_VERSION_1_2, 620);

    try testing.expectEqual(@as(u8, 0x17), header[0]);
    try testing.expectEqual(@as(u8, 0x03), header[1]);
    try testing.expectEqual(@as(u8, 0x03), header[2]);
    try testing.expectEqual(@as(u8, 0x02), header[3]);
    try testing.expectEqual(@as(u8, 0x6C), header[4]);
}

// ============================================================================
// TlsBuffers Tests
// ============================================================================

test "TlsBuffers: reset encrypted" {
    var buffers = tls.TlsBuffers{};

    // Simulate some data in buffer
    buffers.encrypted_len = 100;
    @memset(buffers.encrypted_buffer[0..100], 'X');

    // Reset
    buffers.resetEncrypted();
    try testing.expectEqual(@as(usize, 0), buffers.encrypted_len);
}

test "TlsBuffers: reset decrypted" {
    var buffers = tls.TlsBuffers{};

    buffers.decrypted_len = 50;
    buffers.resetDecrypted();
    try testing.expectEqual(@as(usize, 0), buffers.decrypted_len);
}

test "TlsBuffers: get slices" {
    var buffers = tls.TlsBuffers{};

    @memset(buffers.encrypted_buffer[0..10], 'E');
    buffers.encrypted_len = 10;

    @memset(buffers.decrypted_buffer[0..5], 'D');
    buffers.decrypted_len = 5;

    const enc_slice = buffers.getEncryptedSlice();
    try testing.expectEqual(@as(usize, 10), enc_slice.len);

    const dec_slice = buffers.getDecryptedSlice();
    try testing.expectEqual(@as(usize, 5), dec_slice.len);
}

test "TlsBuffers: buffer sizes" {
    var buffers = tls.TlsBuffers{};

    // Check buffer sizes (should be BUFFER_SIZE * 2 = 8192)
    try testing.expectEqual(@as(usize, tls.BUFFER_SIZE * 2), buffers.encrypted_buffer.len);
    try testing.expectEqual(@as(usize, tls.BUFFER_SIZE * 2), buffers.decrypted_buffer.len);
}

// ============================================================================
// Simulated Data Flow Tests
// ============================================================================

/// Simulate what happens when we receive fragmented TLS data
const FragmentedDataSimulator = struct {
    bio: *c.BIO,
    total_written: usize = 0,

    const Self = @This();

    pub fn init() !Self {
        tls.initOpenSsl();
        return .{
            .bio = try tls.createBio(),
        };
    }

    pub fn deinit(self: *Self) void {
        _ = c.BIO_free(self.bio);
    }

    pub fn writeData(self: *Self, data: []const u8) !void {
        try tls.writeToBio(self.bio, data);
        self.total_written += data.len;
    }

    pub fn getPending(self: *Self) usize {
        return @intCast(c.BIO_ctrl_pending(self.bio));
    }

    pub fn readAll(self: *Self, buffer: []u8) !usize {
        return try tls.readFromBio(self.bio, buffer);
    }
};

test "simulated fragmentation: single record in multiple chunks" {
    var sim = try FragmentedDataSimulator.init();
    defer sim.deinit();

    // A TLS record: 5 byte header + 100 byte payload
    const header = makeTlsRecordHeader(TLS_CONTENT_TYPE_APPLICATION_DATA, TLS_VERSION_1_2, 100);

    // Send header
    try sim.writeData(&header);
    try testing.expectEqual(@as(usize, 5), sim.getPending());

    // Send first 50 bytes of payload
    var payload1: [50]u8 = undefined;
    @memset(&payload1, 0xAA);
    try sim.writeData(&payload1);
    try testing.expectEqual(@as(usize, 55), sim.getPending());

    // Send remaining 50 bytes
    var payload2: [50]u8 = undefined;
    @memset(&payload2, 0xBB);
    try sim.writeData(&payload2);
    try testing.expectEqual(@as(usize, 105), sim.getPending());

    // Read all data back - should be complete record
    var buffer: [256]u8 = undefined;
    const len = try sim.readAll(&buffer);
    try testing.expectEqual(@as(usize, 105), len);

    // Verify header
    try testing.expectEqual(@as(u8, 0x17), buffer[0]);
    try testing.expectEqual(@as(u8, 0x03), buffer[1]);
    try testing.expectEqual(@as(u8, 0x03), buffer[2]);
}

test "simulated fragmentation: multiple records in one chunk" {
    var sim = try FragmentedDataSimulator.init();
    defer sim.deinit();

    // Create two back-to-back TLS records
    var data: [30]u8 = undefined;

    // First record: header + 5 bytes
    const header1 = makeTlsRecordHeader(TLS_CONTENT_TYPE_APPLICATION_DATA, TLS_VERSION_1_2, 5);
    @memcpy(data[0..5], &header1);
    @memset(data[5..10], 'A');

    // Second record: header + 5 bytes
    const header2 = makeTlsRecordHeader(TLS_CONTENT_TYPE_APPLICATION_DATA, TLS_VERSION_1_2, 5);
    @memcpy(data[10..15], &header2);
    @memset(data[15..20], 'B');

    // Partial third record (just header)
    const header3 = makeTlsRecordHeader(TLS_CONTENT_TYPE_APPLICATION_DATA, TLS_VERSION_1_2, 100);
    @memcpy(data[20..25], &header3);
    @memset(data[25..30], 'C');

    // Write all at once
    try sim.writeData(&data);
    try testing.expectEqual(@as(usize, 30), sim.getPending());
}

// ============================================================================
// Error Detection Tests
// ============================================================================

/// Check if data at given position looks like valid TLS record start
fn looksLikeTlsRecord(data: []const u8) bool {
    if (data.len < 5) return false;

    const content_type = data[0];
    const version_major = data[1];
    const version_minor = data[2];

    // Valid content types: 20-23
    if (content_type < 0x14 or content_type > 0x17) return false;

    // Version should be 0x03xx
    if (version_major != 0x03) return false;

    // Minor version should be 0x00-0x03
    if (version_minor > 0x03) return false;

    return true;
}

test "error detection: valid TLS record" {
    const valid_app_data = [_]u8{ 0x17, 0x03, 0x03, 0x02, 0x6f };
    try testing.expect(looksLikeTlsRecord(&valid_app_data));

    const valid_handshake = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x7a };
    try testing.expect(looksLikeTlsRecord(&valid_handshake));
}

test "error detection: invalid content type" {
    // These are the actual invalid bytes we saw in the bug
    const invalid1 = [_]u8{ 0x96, 0xaf, 0x21, 0xdb, 0x38 };
    try testing.expect(!looksLikeTlsRecord(&invalid1));

    const invalid2 = [_]u8{ 0xf2, 0x1c, 0x49, 0x5c, 0x3a };
    try testing.expect(!looksLikeTlsRecord(&invalid2));

    const invalid3 = [_]u8{ 0xb5, 0xbb, 0x05, 0x22, 0xd7 };
    try testing.expect(!looksLikeTlsRecord(&invalid3));

    const invalid4 = [_]u8{ 0x27, 0x14, 0x8f, 0x3b, 0x39 };
    try testing.expect(!looksLikeTlsRecord(&invalid4));
}

test "error detection: poison value" {
    const poison = [_]u8{ 0xDE, 0xDE, 0xDE, 0xDE, 0xDE };
    try testing.expect(!looksLikeTlsRecord(&poison));
}

test "error detection: partial record" {
    const partial = [_]u8{ 0x17, 0x03 }; // Only 2 bytes
    try testing.expect(!looksLikeTlsRecord(&partial));
}

// ============================================================================
// Buffer Ownership Tests
// ============================================================================

test "buffer ownership: no aliasing" {
    var buffers = tls.TlsBuffers{};

    // Get pointers to both buffers
    const enc_ptr: [*]u8 = &buffers.encrypted_buffer;
    const dec_ptr: [*]u8 = &buffers.decrypted_buffer;

    // They should not overlap
    const enc_end = @intFromPtr(enc_ptr) + buffers.encrypted_buffer.len;
    const dec_start = @intFromPtr(dec_ptr);

    try testing.expect(enc_end <= dec_start or @intFromPtr(enc_ptr) >= dec_start + buffers.decrypted_buffer.len);
}
