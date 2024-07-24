const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const win32 = @import("win32.zig");

pub fn main() void {
    go();
}

pub export fn go() void {
    var apis = apiAddr{};
    if (!getApi(&apis)) {
        std.log.debug("[-]api not found", .{});
        return;
    }
    std.log.debug("[+]find {d} api", .{@typeInfo(apiAddr).Struct.fields.len});
    var cmdline = "calc".*;
    _ = apis.WinExec.?(&cmdline, 0);
    apis.ExitProcess.?(0);
}

pub export fn goEnd() void {}
const apiAddr = struct {
    const Self = @This();
    WinExec: ?*const fn (
        lpCmdLine: [*c]u8,
        UINT: windows.UINT,
    ) callconv(windows.WINAPI) windows.UINT = null,

    ExitProcess: ?*const fn (
        nExitCode: windows.LONG,
    ) callconv(windows.WINAPI) void = null,
    fn ok(self: *Self) bool {
        inline for (@typeInfo(apiAddr).Struct.fields) |field| {
            if (@field(self, field.name) == null) {
                return false;
            }
        }
        return true;
    }
};

pub fn rva2va(comptime T: type, base: *const anyopaque, rva: usize) T {
    var ptr = @intFromPtr(base) + rva;
    return switch (@typeInfo(T)) {
        .Pointer => {
            return @as(T, @ptrFromInt(ptr));
        },
        .Int => {
            if (T != usize) {
                @compileError("expected usize, found '" ++ @typeName(T) ++ "'");
            }
            return @as(T, ptr);
        },
        else => {
            @compileError("expected pointer or int, found '" ++ @typeName(T) ++ "'");
        },
    };
}

/// case insensitive
inline fn hashApi(api: []const u8) u32 {
    var h: u32 = 0x6c6c6a62; // iv for api hash
    for (api) |item| {
        // 0x20 for lowercase
        h = @addWithOverflow(@mulWithOverflow(31, h)[0], item | 0x20)[0];
    }
    return h;
}

inline fn sliceTo(buf: [*c]u8) []u8 {
    var len: usize = 0;
    while (buf[len] != 0) : ({
        len += 1;
    }) {}
    return buf[0..len];
}

fn findApi(r: *apiAddr, inst: windows.PVOID) void {
    var dos: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(inst));
    var nt = rva2va(*win32.IMAGE_NT_HEADERS, inst, @as(u32, @bitCast(dos.e_lfanew)));
    var rva = nt.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (rva == 0) {
        return;
    }
    var exp = rva2va(*win32.IMAGE_EXPORT_DIRECTORY, inst, rva);
    var cnt = exp.NumberOfNames;
    if (cnt == 0) {
        return;
    }
    var adr = rva2va([*c]u32, inst, exp.AddressOfFunctions);
    var sym = rva2va([*c]u32, inst, exp.AddressOfNames);
    var ord = rva2va([*c]u16, inst, exp.AddressOfNameOrdinals);
    var dll = sliceTo(rva2va([*c]u8, inst, exp.Name));
    std.log.debug("[i]{s}", .{dll});
    for (0..cnt) |i| {
        var sym_ = rva2va([*c]u8, inst, sym[i]);
        var adr_ = rva2va(usize, inst, adr[ord[i]]);
        var hash = hashApi(sliceTo(sym_));
        inline for (@typeInfo(apiAddr).Struct.fields) |field| {
            if (hash == comptime hashApi(field.name)) {
                @field(r, field.name) = @ptrFromInt(adr_);
                std.log.debug("[+]{s} at 0x{X}", .{ field.name, adr_ });
            }
        }
    }
}

fn getApi(apis: *apiAddr) bool {
    var peb = std.os.windows.peb();
    var ldr = peb.Ldr;
    var dte: *win32.LDR_DATA_TABLE_ENTRY = @ptrCast(ldr.InLoadOrderModuleList.Flink);
    while (dte.DllBase != null) : ({
        dte = @ptrCast(dte.InLoadOrderLinks.Flink);
    }) {
        findApi(apis, dte.DllBase.?);
        if (apis.ok()) {
            return true;
        }
    }
    return false;
}
