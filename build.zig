const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    {
        inline for (&.{ "x86", "x86_64", "aarch64" }) |arch| {
            const exe = b.addExecutable(.{
                .name = "test-" ++ arch,
                .root_source_file = b.path("src/main.zig"),
                .target = b.resolveTargetQuery(.{ .cpu_arch = getCpuArch(arch), .os_tag = .windows, .abi = .gnu }),
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
                .root_source_file = b.path("src/main.zig"),
                .target = b.resolveTargetQuery(.{ .cpu_arch = getCpuArch(arch), .os_tag = .windows, .abi = .msvc }),
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
                .root_source_file = b.path("src/loader.zig"),
                .target = b.resolveTargetQuery(.{ .cpu_arch = getCpuArch(t), .os_tag = .windows, .abi = .gnu }),
                .optimize = .ReleaseSmall,
            });
            loader.dependOn(&b.addInstallArtifact(exe, .{}).step);
        }
    }
}

const win32 = @import("src/win32.zig");

fn getNt(base: *anyopaque) *anyopaque {
    const dos: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(base));
    return @ptrFromInt(@intFromPtr(base) + @as(u32, @bitCast(dos.e_lfanew)));
}
fn rva2ofs(comptime T: type, base: *anyopaque, rva: usize, is64: bool) T {
    const nt = getNt(base);

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
    const ptr = @intFromPtr(base) + ofs;
    return switch (@typeInfo(T)) { // https://github.com/ziglang/zig/blob/master/lib/std/builtin.zig#L563
        .pointer => {
            return @as(T, @ptrFromInt(ptr));
        },
        .int => {
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

fn genShellCode(step: *std.Build.Step, make_options: std.Build.Step.MakeOptions) anyerror!void {
    _ = make_options;
    const c: *GenShellCode = @fieldParentPtr("step", step);
    const allocator = step.owner.allocator;
    const resolved_target = c.install.artifact.root_module.resolved_target orelse
        @panic("the root Module of a Compile step must be created with a known 'target' field");
    const target = resolved_target.result;
    const is64 = target.cpu.arch != .x86; // https://github.com/ziglang/zig/blob/master/src/target.zig

    {
        var dir = std.fs.cwd().openDir(step.owner.exe_dir, .{}) catch unreachable;
        defer dir.close();
        const inst = dir.readFileAllocOptions(
            allocator,
            c.install.dest_sub_path,
            1024 * 64,
            null,
            16,
            null,
        ) catch unreachable;
        // get shellcode by resolve go goEnd symbol
        const nt = getNt(inst.ptr);
        var rva: u32 = 0;
        if (is64) {
            const nt64: *win32.IMAGE_NT_HEADERS64 = @alignCast(@ptrCast(nt));
            rva = nt64.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        } else {
            const nt32: *win32.IMAGE_NT_HEADERS32 = @alignCast(@ptrCast(nt));
            rva = nt32.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        }

        std.debug.assert(rva != 0);
        const exp = rva2ofs(*align(1) win32.IMAGE_EXPORT_DIRECTORY, inst.ptr, rva, is64);
        const cnt = exp.NumberOfNames;
        std.debug.assert(cnt != 0);
        const adr = rva2ofs([*c]align(1) u32, inst.ptr, exp.AddressOfFunctions, is64);
        const sym = rva2ofs([*c]align(1) u32, inst.ptr, exp.AddressOfNames, is64);
        const ord = rva2ofs([*c]align(1) u16, inst.ptr, exp.AddressOfNameOrdinals, is64);
        var goFn: [*c]u8 = undefined;
        var fnLen: usize = undefined;
        for (0..cnt) |i| {
            const sym_ = std.mem.sliceTo(rva2ofs([*c]u8, inst.ptr, sym[i], is64), 0);
            const adr_ = rva2ofs(usize, inst.ptr, adr[ord[i]], is64);
            if (std.mem.eql(u8, sym_, "go")) {
                goFn = @ptrFromInt(adr_);
            } else if (std.mem.eql(u8, sym_, "goEnd")) {
                fnLen = adr_ - @as(usize, @intFromPtr(goFn));
            }
        }
        const shellcode = goFn[0..fnLen];
        const scname = switch (target.cpu.arch) {
            .x86 => "x86.sc",
            .x86_64 => "x86_64.sc",
            .aarch64 => "aarch64.sc",
            else => unreachable,
        };
        try dir.writeFile(.{ .sub_path = scname, .data = shellcode });
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

fn getCpuArch(arch: []const u8) std.Target.Cpu.Arch {
    if (std.mem.eql(u8, arch, "x86")) return .x86;
    if (std.mem.eql(u8, arch, "x86_64")) return .x86_64;
    if (std.mem.eql(u8, arch, "aarch64")) return .aarch64;
    @panic("Unsupported architecture");
}
