from ctypes import *

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_DOSZM_SIGNATURE = 0x4D5A

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic', c_uint16),
        ('e_cblp', c_uint16),
        ('e_cp', c_uint16),
        ('e_crlc', c_uint16),
        ('e_cparhdr', c_uint16),
        ('e_minalloc', c_uint16),
        ('e_maxalloc', c_uint16),
        ('e_ss', c_uint16),
        ('e_sp', c_uint16),
        ('e_csum', c_uint16),
        ('e_ip', c_uint16),
        ('e_cs', c_uint16),
        ('e_lfarlc', c_uint16),
        ('e_ovno', c_uint16),
        ('e_res1', c_uint16 * 4),
        ('e_oemid', c_uint16),
        ('e_oeminfo', c_uint16),
        ('e_res2', c_uint16 * 10),
        ('e_lfanew', c_int32)
    ]

IMAGE_NE_SIGNATURE = 0x454E
IMAGE_LE_SIGNATURE = 0x454C
IMAGE_LX_SIGNATURE = 0x584C
IMAGE_NT_SIGNATURE = 0x4550

IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_IA64 = 0x0200
IMAGE_FILE_MACHINE_AMD64 = 0x8664

class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Machine', c_uint16),
        ('NumberOfSections', c_uint16),
        ('TimeDateStamp', c_uint32),
        ('PointerToSymbolTable', c_uint32),
        ('NumberOfSymbols', c_uint32),
        ('SizeOfOptionalHeader', c_uint16),
        ('Characteristics', c_uint16)
    ]

class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress', c_uint32),
        ('Size', c_uint32)
    ]

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_DIRECTORY_ENTRY_EXPORT     = 0
IMAGE_DIRECTORY_ENTRY_IMPORT     = 1
IMAGE_DIRECTORY_ENTRY_BASERELOC  = 5
IMAGE_DIRECTORY_ENTRY_TLS        = 9

IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [
        ('Magic', c_uint16),
        ('MajorLinkerVersion', c_ubyte),
        ('MinorLinkerVersion', c_ubyte),
        ('SizeOfCode', c_uint32),
        ('SizeOfInitializedData', c_uint32),
        ('SizeOfUninitializedData', c_uint32),
        ('AddressOfEntryPoint', c_uint32),
        ('BaseOfCode', c_uint32),
        ('BaseOfData', c_uint32),
        ('ImageBase', c_uint32),
        ('SectionAlignment', c_uint32),
        ('FileAlignment', c_uint32),
        ('MajorOperatingSystemVersion', c_int16),
        ('MinorOperatingSystemVersion', c_int16),
        ('MajorImageVersion', c_int16),
        ('MinorImageVersion', c_int16),
        ('MajorSubsystemVersion', c_int16),
        ('MinorSubsystemVersion', c_int16),
        ('Win32VersionValue', c_uint32),
        ('SizeOfImage', c_uint32),
        ('SizeOfHeaders', c_uint32),
        ('CheckSum', c_uint32),
        ('Subsystem', c_int16),
        ('DllCharacteristics', c_int16),
        ('SizeOfStackReserve', c_uint32),
        ('SizeOfStackCommit', c_uint32),
        ('SizeOfHeapReserve', c_uint32),
        ('SizeOfHeapCommit', c_uint32),
        ('LoaderFlags', c_uint32),
        ('NumberOfRvaAndSizes', c_uint32),
        ('DataDirectory',
            IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]

class IMAGE_OPTIONAL_HEADER64(Structure):
    _fields_ = [
        ('Magic', c_uint16),
        ('MajorLinkerVersion', c_ubyte),
        ('MinorLinkerVersion', c_ubyte),
        ('SizeOfCode', c_uint32),
        ('SizeOfInitializedData', c_uint32),
        ('SizeOfUninitializedData', c_uint32),
        ('AddressOfEntryPoint', c_uint32),
        ('BaseOfCode', c_uint32),
        ('ImageBase', c_uint64),
        ('SectionAlignment', c_uint32),
        ('FileAlignment', c_uint32),
        ('MajorOperatingSystemVersion', c_uint16),
        ('MinorOperatingSystemVersion', c_uint16),
        ('MajorImageVersion', c_uint16),
        ('MinorImageVersion', c_uint16),
        ('MajorSubsystemVersion', c_uint16),
        ('MinorSubsystemVersion', c_uint16),
        ('Win32VersionValue', c_uint32),
        ('SizeOfImage', c_uint32),
        ('SizeOfHeaders', c_uint32),
        ('CheckSum', c_uint32),
        ('Subsystem', c_uint16),
        ('DllCharacteristics', c_uint16),
        ('SizeOfStackReserve', c_uint64),
        ('SizeOfStackCommit', c_uint64),
        ('SizeOfHeapReserve', c_uint64),
        ('SizeOfHeapCommit', c_uint64),
        ('LoaderFlags', c_uint32),
        ('NumberOfRvaAndSizes', c_uint32),
        ('DataDirectory',
            IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]

class IMAGE_NT_HEADERS(Structure):
    _fields_ = [
        ('Signature', c_uint32),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER),
    ]

IMAGE_SIZEOF_SHORT_NAME = 8

class IMAGE_SECTION_HEADER_Misc(Union):
    _fields_ = [
        ('PhysicalAddress', c_uint32),
        ('VirtualSize', c_uint32)
    ]

IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ('Name', c_char * 8),
        ('Misc', IMAGE_SECTION_HEADER_Misc),
        ('VirtualAddress', c_uint32),
        ('SizeOfRawData', c_uint32),
        ('PointerToRawData', c_uint32),
        ('PointerToRelocations', c_uint32),
        ('PointerToLinenumbers', c_uint32),
        ('NumberOfRelocations', c_int16),
        ('NumberOfLinenumbers', c_int16),
        ('Characteristics', c_uint32)
    ]

class IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [
        ('Characteristics', c_uint32),
        ('TimeDateStamp', c_uint32),
        ('MajorVersion', c_int16),
        ('MinorVersion', c_int16),
        ('Name', c_uint32),
        ('Base', c_uint32),
        ('NumberOfFunctions', c_uint32),
        ('NumberOfNames', c_uint32),
        ('AddressOfFunctions', c_uint32),
        ('AddressOfNames', c_uint32),
        ('AddressOfNameOrdinals', c_uint32)
    ]

class IMAGE_IMPORT_DESCRIPTOR_Union(Union):
    _fields_ = [
        ('Characteristics', c_uint32),
        ('OriginalFirstThunk', c_uint32)
    ]

class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _anonymous_ = ('DummyUnionName', )
    _fields_ = [
        ('DummyUnionName', IMAGE_IMPORT_DESCRIPTOR_Union),
        ('TimeDateStamp', c_uint32),
        ('ForwarderChain', c_uint32),
        ('Name', c_uint32),
        ('FirstThunk', c_uint32)
    ]

IMAGE_ORDINAL_FLAG32 = 0x80000000

class IMAGE_THUNK_DATA32(Union):
    _fields_ = [
        ('ForwarderString', c_uint32),
        ('Function', c_uint32),
        ('Ordinal', c_uint32),
        ('AddressOfData', c_uint32)
    ]

class IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [
        ('Hint', c_uint16),
    ]

class IMAGE_BASE_RELOCATION(Structure):
    _fields_ = [
        ('VirtualAddress', c_uint32),
        ('SizeOfBlock', c_uint32)
    ]

class IMAGE_FIXUP_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ('Offset', c_uint32, 12),
        ('Type', c_uint32, 4)
    ]

class IMAGE_TLS_DIRECTORY32(Structure):
    _fields_ = [
        ('StartAddressOfRawData', c_uint32),
        ('EndAddressOfRawData', c_uint32),
        ('AddressOfIndex', c_uint32),
        ('AddressOfCallBacks', c_uint32),
        ('SizeOfZeroFill', c_uint32),
        ('Characteristics', c_uint32)
    ]
