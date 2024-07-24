const std = @import("std");
const windows = std.os.windows;

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: windows.LIST_ENTRY,
    InMemoryOrderLinks: windows.LIST_ENTRY,
    Reserved2: [2]windows.PVOID,
    DllBase: ?windows.PVOID,
    EntryPoint: windows.PVOID,
    SizeOfImage: windows.ULONG,
    FullDllName: windows.UNICODE_STRING,
    Reserved4: [8]windows.BYTE,
    Reserved5: [3]windows.PVOID,
    DUMMYUNIONNAME: extern union {
        CheckSum: windows.ULONG,
        Reserved6: windows.PVOID,
    },
    TimeDateStamp: windows.ULONG,
};

pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: windows.WORD,
    e_cblp: windows.WORD,
    e_cp: windows.WORD,
    e_crlc: windows.WORD,
    e_cparhdr: windows.WORD,
    e_minalloc: windows.WORD,
    e_maxalloc: windows.WORD,
    e_ss: windows.WORD,
    e_sp: windows.WORD,
    e_csum: windows.WORD,
    e_ip: windows.WORD,
    e_cs: windows.WORD,
    e_lfarlc: windows.WORD,
    e_ovno: windows.WORD,
    e_res: [4]windows.WORD,
    e_oemid: windows.WORD,
    e_oeminfo: windows.WORD,
    e_res2: [10]windows.WORD,
    e_lfanew: windows.LONG,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: windows.DWORD,
    Size: windows.DWORD,
};
pub const IMAGE_OPTIONAL_HEADER32 = extern struct {
    Magic: windows.WORD,
    MajorLinkerVersion: windows.BYTE,
    MinorLinkerVersion: windows.BYTE,
    SizeOfCode: windows.DWORD,
    SizeOfInitializedData: windows.DWORD,
    SizeOfUninitializedData: windows.DWORD,
    AddressOfEntryPoint: windows.DWORD,
    BaseOfCode: windows.DWORD,
    BaseOfData: windows.DWORD,
    ImageBase: windows.DWORD,
    SectionAlignment: windows.DWORD,
    FileAlignment: windows.DWORD,
    MajorOperatingSystemVersion: windows.WORD,
    MinorOperatingSystemVersion: windows.WORD,
    MajorImageVersion: windows.WORD,
    MinorImageVersion: windows.WORD,
    MajorSubsystemVersion: windows.WORD,
    MinorSubsystemVersion: windows.WORD,
    Win32VersionValue: windows.DWORD,
    SizeOfImage: windows.DWORD,
    SizeOfHeaders: windows.DWORD,
    CheckSum: windows.DWORD,
    Subsystem: windows.WORD,
    DllCharacteristics: windows.WORD,
    SizeOfStackReserve: windows.DWORD,
    SizeOfStackCommit: windows.DWORD,
    SizeOfHeapReserve: windows.DWORD,
    SizeOfHeapCommit: windows.DWORD,
    LoaderFlags: windows.DWORD,
    NumberOfRvaAndSizes: windows.DWORD,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};
pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: windows.WORD,
    MajorLinkerVersion: windows.BYTE,
    MinorLinkerVersion: windows.BYTE,
    SizeOfCode: windows.DWORD,
    SizeOfInitializedData: windows.DWORD,
    SizeOfUninitializedData: windows.DWORD,
    AddressOfEntryPoint: windows.DWORD,
    BaseOfCode: windows.DWORD,
    ImageBase: windows.ULONGLONG,
    SectionAlignment: windows.DWORD,
    FileAlignment: windows.DWORD,
    MajorOperatingSystemVersion: windows.WORD,
    MinorOperatingSystemVersion: windows.WORD,
    MajorImageVersion: windows.WORD,
    MinorImageVersion: windows.WORD,
    MajorSubsystemVersion: windows.WORD,
    MinorSubsystemVersion: windows.WORD,
    Win32VersionValue: windows.DWORD,
    SizeOfImage: windows.DWORD,
    SizeOfHeaders: windows.DWORD,
    CheckSum: windows.DWORD,
    Subsystem: windows.WORD,
    DllCharacteristics: windows.WORD,
    SizeOfStackReserve: windows.ULONGLONG,
    SizeOfStackCommit: windows.ULONGLONG,
    SizeOfHeapReserve: windows.ULONGLONG,
    SizeOfHeapCommit: windows.ULONGLONG,
    LoaderFlags: windows.DWORD,
    NumberOfRvaAndSizes: windows.DWORD,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};
pub const IMAGE_FILE_HEADER = extern struct {
    Machine: windows.WORD,
    NumberOfSections: windows.WORD,
    TimeDateStamp: windows.DWORD,
    PointerToSymbolTable: windows.DWORD,
    NumberOfSymbols: windows.DWORD,
    SizeOfOptionalHeader: windows.WORD,
    Characteristics: windows.WORD,
};
pub const IMAGE_NT_HEADERS64 = extern struct {
    Signature: windows.DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

pub const IMAGE_NT_HEADERS32 = extern struct {
    Signature: windows.DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
};

pub const IMAGE_OPTIONAL_HEADER = if (@sizeOf(usize) == 4) IMAGE_OPTIONAL_HEADER32 else IMAGE_OPTIONAL_HEADER64;
pub const IMAGE_NT_HEADERS = if (@sizeOf(usize) == 4) IMAGE_NT_HEADERS32 else IMAGE_NT_HEADERS64;

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: windows.DWORD,
    TimeDateStamp: windows.DWORD,
    MajorVersion: windows.WORD,
    MinorVersion: windows.WORD,
    Name: windows.DWORD,
    Base: windows.DWORD,
    NumberOfFunctions: windows.DWORD,
    NumberOfNames: windows.DWORD,
    AddressOfFunctions: windows.DWORD,
    AddressOfNames: windows.DWORD,
    AddressOfNameOrdinals: windows.DWORD,
};

pub const IMAGE_DIRECTORY_ENTRY_EXPORT = @as(c_int, 0);
pub const IMAGE_DIRECTORY_ENTRY_IMPORT = @as(c_int, 1);
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE = @as(c_int, 2);
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION = @as(c_int, 3);
pub const IMAGE_DIRECTORY_ENTRY_SECURITY = @as(c_int, 4);
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC = @as(c_int, 5);
pub const IMAGE_DIRECTORY_ENTRY_DEBUG = @as(c_int, 6);
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = @as(c_int, 7);
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR = @as(c_int, 8);
pub const IMAGE_DIRECTORY_ENTRY_TLS = @as(c_int, 9);
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = @as(c_int, 10);
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = @as(c_int, 11);
pub const IMAGE_DIRECTORY_ENTRY_IAT = @as(c_int, 12);
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = @as(c_int, 13);
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = @as(c_int, 14);

pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]windows.UCHAR,
    VirtualSize: windows.ULONG,
    VirtualAddress: windows.ULONG,
    SizeOfRawData: windows.ULONG,
    PointerToRawData: windows.ULONG,
    PointerToRelocations: windows.ULONG,
    PointerToLinenumbers: windows.ULONG,
    NumberOfRelocations: windows.USHORT,
    NumberOfLinenumbers: windows.USHORT,
    Characteristics: windows.ULONG,
};

pub const IMAGE_BASE_RELOCATION = extern struct {
    VirtualAddress: windows.DWORD,
    SizeOfBlock: windows.DWORD,
};

pub const IMAGE_RELOC = packed struct(u16) {
    offset: u12,
    typ: u4,
};
pub const IMAGE_REL_BASED_DIR64: u6 = 10;
pub const IMAGE_REL_BASED_HIGHLOW: u6 = 3;
pub const IMAGE_REL_TYPE = if (@sizeOf(usize) == 4) IMAGE_REL_BASED_HIGHLOW else IMAGE_REL_BASED_DIR64;

pub const IMAGE_IMPORT_DESCRIPTOR = extern struct {
    OriginalFirstThunk: windows.DWORD,
    TimeDateStamp: windows.DWORD,
    ForwarderChain: windows.DWORD,
    Name: windows.DWORD,
    FirstThunk: windows.DWORD,
};
pub const IMAGE_THUNK_DATA64 = extern union {
    const Self = @This();
    ForwarderString: windows.ULONGLONG,
    Function: windows.ULONGLONG,
    Ordinal: windows.ULONGLONG,
    AddressOfData: windows.ULONGLONG,
    pub fn IMAGE_SNAP_BY_ORDINAL(self: *Self) bool {
        return (self.Ordinal & 0x8000000000000000) != 0;
    }
    pub fn IMAGE_ORDINAL(self: *Self) usize {
        return self.Ordinal & 0xFFFF;
    }
};
pub const IMAGE_THUNK_DATA32 = extern union {
    const Self = @This();
    ForwarderString: windows.DWORD,
    Function: windows.DWORD,
    Ordinal: windows.DWORD,
    AddressOfData: windows.DWORD,
    pub fn IMAGE_SNAP_BY_ORDINAL(self: *Self) bool {
        return (self.Ordinal & 0x80000000) != 0;
    }
    pub fn IMAGE_ORDINAL(self: *Self) usize {
        return self.Ordinal & 0xFFFF;
    }
};

pub const IMAGE_THUNK_DATA = if (@sizeOf(usize) == 4) IMAGE_THUNK_DATA32 else IMAGE_THUNK_DATA64;

pub const IMAGE_IMPORT_BY_NAME = extern struct {
    Hint: windows.WORD,
    Name: [1]windows.CHAR,
};

pub const IMAGE_FILE_RELOCS_STRIPPED = 0x0001;

pub const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
pub const IMAGE_SCN_MEM_READ = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE = 0x80000000;
