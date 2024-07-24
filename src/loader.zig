const std = @import("std");
const os = std.os;
const fs = std.fs;
const path = fs.path;
const win = os.windows;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var args = try std.process.argsAlloc(allocator);
    defer allocator.free(args);
    if (args.len == 1) {
        std.log.err("usage: {s} scpath", .{path.basename(args[0])});
        return;
    }
    var data = try fs.cwd().readFileAlloc(allocator, args[1], 1024 * 1024 * 1024);
    var ptr = try win.VirtualAlloc(
        null,
        data.len,
        win.MEM_COMMIT | win.MEM_RESERVE,
        win.PAGE_EXECUTE_READWRITE,
    );
    defer win.VirtualFree(ptr, 0, win.MEM_RELEASE);
    var buf: [*c]u8 = @ptrCast(ptr);
    @memcpy(buf[0..data.len], data);
    @as(*const fn () void, @ptrCast(@alignCast(ptr)))();
}
