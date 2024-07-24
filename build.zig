const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    {
        inline for (&.{ "x86", "x86_64", "aarch64" }) |t| {
            const exe = b.addExecutable(.{
                .name = "test-" ++ t,
                .root_source_file = .{ .path = "src/main.zig" },
                .target = std.zig.CrossTarget.parse(.{ .arch_os_abi = t ++ "-windows-gnu" }) catch unreachable,
                .optimize = optimize,
            });
            b.installArtifact(exe);
        }
    }

    const sc = b.step("sc", "Build ReleaseSmall shellcode");

    {
        inline for (&.{ "x86", "x86_64", "aarch64" }) |arch| {
            const dll = b.addSharedLibrary(.{
                .name = "sc-" ++ arch,
                .root_source_file = .{ .path = "src/main.zig" },
                .target = std.zig.CrossTarget.parse(.{ .arch_os_abi = arch ++ "-windows-msvc" }) catch unreachable,
                .optimize = .ReleaseSmall,
            });
            const install = b.addInstallArtifact(dll, .{});
            const c = GenShellCode.create(b, install);
            sc.dependOn(&c.step);
        }
    }
    const loader = b.step("loader", "Build ReleaseSmall loader");

    {
        inline for (&.{ "x86", "x86_64", "aarch64" }) |t| {
            const exe = b.addExecutable(.{
                .name = "loader-" ++ t,
                .root_source_file = .{ .path = "src/loader.zig" },
                .target = std.zig.CrossTarget.parse(.{ .arch_os_abi = t ++ "-windows-gnu" }) catch unreachable,
                .optimize = .ReleaseSmall,
            });
            loader.dependOn(&b.addInstallArtifact(exe, .{}).step);
        }
    }
}

const win32 = @import("src/win32.zig");

fn getNt(base: *anyopaque) *anyopaque {
    var dos: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(base));
    return @ptrFromInt(@intFromPtr(base) + @as(u32, @bitCast(dos.e_lfanew)));
}
fn rva2ofs(comptime T: type, base: *anyopaque, rva: usize, is64: bool) T {
    var nt = getNt(base);

    var sh: [*c]win32.IMAGE_SECTION_HEADER = undefined;
    var shNum: usize = 0;
    if (is64) {
        var nt64: *win32.IMAGE_NT_HEADERS64 = @alignCast(@ptrCast(nt));
        sh = @ptrFromInt(@intFromPtr(&nt64.OptionalHeader) + nt64.FileHeader.SizeOfOptionalHeader);
        shNum = nt64.FileHeader.NumberOfSections;
    } else {
        var nt32: *win32.IMAGE_NT_HEADERS32 = @alignCast(@ptrCast(nt));
        sh = @ptrFromInt(@intFromPtr(&nt32.OptionalHeader) + nt32.FileHeader.SizeOfOptionalHeader);
        shNum = nt32.FileHeader.NumberOfSections;
    }

    var ofs: usize = 0;
    for (0..shNum) |i| {
        if (rva >= sh[i].VirtualAddress and rva < (sh[i].VirtualAddress + sh[i].SizeOfRawData)) {
            ofs = sh[i].PointerToRawData + (rva - sh[i].VirtualAddress);
            break;
        }
    }
    std.debug.assert(ofs != 0);
    var ptr = @intFromPtr(base) + ofs;
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

fn readFile(filename: []const u8, allocator: std.mem.Allocator) []u8 {
    var f = std.fs.cwd().openFile(filename, .{}) catch unreachable;
    defer f.close();
    var stream = std.ArrayList(u8).initCapacity(allocator, 512 * 1024) catch unreachable;
    var fifo = std.fifo.LinearFifo(u8, .{ .Static = 1024 }).init();
    fifo.pump(f.reader(), stream.writer()) catch unreachable;
    return stream.toOwnedSlice() catch unreachable;
}

fn genShellCode(step: *std.Build.Step, prog_node: *std.Progress.Node) anyerror!void {
    _ = prog_node;
    const c = @fieldParentPtr(GenShellCode, "step", step);
    const allocator = step.owner.allocator;
    const is64 = c.install.artifact.target.cpu_arch != .x86;

    {
        var dir = std.fs.cwd().openDir(step.owner.lib_dir, .{}) catch unreachable;
        defer dir.close();
        var inst = dir.readFileAllocOptions(
            allocator,
            c.install.dest_sub_path,
            1024 * 64,
            null,
            16,
            null,
        ) catch unreachable;
        // get shellcode by resolve go goEnd symbol
        var nt = getNt(inst.ptr);
        var rva: u32 = 0;
        if (is64) {
            var nt64: *win32.IMAGE_NT_HEADERS64 = @alignCast(@ptrCast(nt));
            rva = nt64.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        } else {
            var nt32: *win32.IMAGE_NT_HEADERS32 = @alignCast(@ptrCast(nt));
            rva = nt32.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        }

        std.debug.assert(rva != 0);
        var exp = rva2ofs(*align(1) win32.IMAGE_EXPORT_DIRECTORY, inst.ptr, rva, is64);
        var cnt = exp.NumberOfNames;
        std.debug.assert(cnt != 0);
        var adr = rva2ofs([*c]align(1) u32, inst.ptr, exp.AddressOfFunctions, is64);
        var sym = rva2ofs([*c]align(1) u32, inst.ptr, exp.AddressOfNames, is64);
        var ord = rva2ofs([*c]align(1) u16, inst.ptr, exp.AddressOfNameOrdinals, is64);
        var goFn: [*c]u8 = undefined;
        var fnLen: usize = undefined;
        for (0..cnt) |i| {
            var sym_ = std.mem.sliceTo(rva2ofs([*c]u8, inst.ptr, sym[i], is64), 0);
            var adr_ = rva2ofs(usize, inst.ptr, adr[ord[i]], is64);
            if (std.mem.eql(u8, sym_, "go")) {
                goFn = @ptrFromInt(adr_);
            } else if (std.mem.eql(u8, sym_, "goEnd")) {
                fnLen = adr_ - @as(usize, @intFromPtr(goFn));
            }
        }
        var shellcode = goFn[0..fnLen];
        var scname = switch (c.install.artifact.target.cpu_arch.?) {
            .x86 => "x86.sc",
            .x86_64 => "x86_64.sc",
            .aarch64 => "aarch64.sc",
            else => unreachable,
        };
        try dir.writeFile(scname, shellcode);
    }
}

/// gen shellcode
const GenShellCode = struct {
    step: std.Build.Step,
    install: *std.Build.Step.InstallArtifact,
    fn create(owner: *std.Build, install: *std.Build.Step.InstallArtifact) *GenShellCode {
        const self = owner.allocator.create(GenShellCode) catch unreachable;

        self.* = .{
            .step = std.Build.Step.init(.{
                .id = .install_artifact,
                .name = owner.fmt("generate shellcode for {s}", .{install.artifact.name}),
                .owner = owner,
                .makeFn = genShellCode,
            }),
            .install = install,
        };
        self.step.dependOn(&install.step);
        return self;
    }
};
