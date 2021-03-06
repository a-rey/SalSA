/**
 * PE parsing library for use in a browser
 */

// TODO: better logging
// TODO: better error handling

var PE = (() => {
  'use strict';
  var _offset = 0;  // file offset
  var _data = {};   // parsed data
  var _file = null; // file reference
  var _x64 = false; // x64 flag

  // Microsoft PE headers and structures
  // https://source.winehq.org/source/include/winnt.h
  const _headers = {
    'DOS_HEADER': [
      ['e_magic',   2],
      ['e_cblp',    2],
      ['e_cp',      2],
      ['e_crlc',    2],
      ['e_cparhdr', 2],
      ['e_minalloc',2],
      ['e_maxalloc',2],
      ['e_ss',      2],
      ['e_sp',      2],
      ['e_csum',    2],
      ['e_ip',      2],
      ['e_cs',      2],
      ['e_lfarlc',  2],
      ['e_ovno',    2],
      ['e_res',     8],
      ['e_oemid',   2],
      ['e_oeminfo', 2],
      ['e_res2',    20],
      ['e_lfanew',  4],
    ],
    'PE_HEADER': [
      ['Signature',           4],
      ['Machine',             2],
      ['NumberOfSections',    2],
      ['TimeDateStamp',       4],
      ['PointerToSymbolTable',4],
      ['NumberOfSymbols',     4],
      ['SizeOfOptionalHeader',2],
      ['Characteristics',     2],
    ],
    'IMAGE_HEADER_32': [
      ['Magic',                      2],
      ['MajorLinkerVersion',         1],
      ['MinorLinkerVersion',         1],
      ['SizeOfCode',                 4],
      ['SizeOfInitializedData',      4],
      ['SizeOfUninitializedData',    4],
      ['AddressOfEntryPoint',        4],
      ['BaseOfCode',                 4],
      ['BaseOfData',                 4],
      ['ImageBase',                  4],
      ['SectionAlignment',           4],
      ['FileAlignment',              4],
      ['MajorOperatingSystemVersion',2],
      ['MinorOperatingSystemVersion',2],
      ['MajorImageVersion',          2],
      ['MinorImageVersion',          2],
      ['MajorSubsystemVersion',      2],
      ['MinorSubsystemVersion',      2],
      ['Win32VersionValue',          4],
      ['SizeOfImage',                4],
      ['SizeOfHeaders',              4],
      ['CheckSum',                   4],
      ['Subsystem',                  2],
      ['DllCharacteristics',         2],
      ['SizeOfStackReserve',         4],
      ['SizeOfStackCommit',          4],
      ['SizeOfHeapReserve',          4],
      ['SizeOfHeapCommit',           4],
      ['LoaderFlags',                4],
      ['NumberOfRvaAndSizes',        4],
    ],
    'IMAGE_HEADER_64': [
      ['Magic',                      2],
      ['MajorLinkerVersion',         1],
      ['MinorLinkerVersion',         1],
      ['SizeOfCode',                 4],
      ['SizeOfInitializedData',      4],
      ['SizeOfUninitializedData',    4],
      ['AddressOfEntryPoint',        4],
      ['BaseOfCode',                 4],
      ['ImageBase',                  8],
      ['SectionAlignment',           4],
      ['FileAlignment',              4],
      ['MajorOperatingSystemVersion',2],
      ['MinorOperatingSystemVersion',2],
      ['MajorImageVersion',          2],
      ['MinorImageVersion',          2],
      ['MajorSubsystemVersion',      2],
      ['MinorSubsystemVersion',      2],
      ['Win32VersionValue',          4],
      ['SizeOfImage',                4],
      ['SizeOfHeaders',              4],
      ['CheckSum',                   4],
      ['Subsystem',                  2],
      ['DllCharacteristics',         2],
      ['SizeOfStackReserve',         8],
      ['SizeOfStackCommit',          8],
      ['SizeOfHeapReserve',          8],
      ['SizeOfHeapCommit',           8],
      ['LoaderFlags',                4],
      ['NumberOfRvaAndSizes',        4],
    ],
    'DATA_DIRECTORY': [
      ['Export',                       4],
      ['Export_size',                  4],
      ['Import',                       4],
      ['Import_size',                  4],
      ['Resource',                     4],
      ['Resource_size',                4],
      ['Exception',                    4],
      ['Exception_size',               4],
      ['CertificateTable',             4],
      ['CertificateTable_size',        4],
      ['BaseRelocationTable',          4],
      ['BaseRelocationTable_size',     4],
      ['Debug',                        4],
      ['Debug_size',                   4],
      ['ArchitectureSpecificData',     4],
      ['ArchitectureSpecificData_size',4],
      ['GlobalPointerRegister',        4],
      ['GlobalPointerRegister_size',   4],
      ['ThreadLocalStorage',           4],
      ['ThreadLocalStorage_size',      4],
      ['LoadConfiguration',            4],
      ['LoadConfiguration_size',       4],
      ['BoundImport',                  4],
      ['BoundImport_size',             4],
      ['ImportAddressTable',           4],
      ['ImportAddressTable_size',      4],
      ['DelayImportTable',             4],
      ['DelayImportTable_size',        4],
      ['CLRRuntimeHeader',             4],
      ['CLRRuntimeHeader_size',        4],
      ['Reserved',                     4],
      ['Reserved_size',                4],
    ],
    'SECTION_HEADER': [
      ['Name',                8],
      ['VirtualSize',         4],
      ['VirtualAddress',      4],
      ['SizeOfRawData',       4],
      ['PointerToRawData',    4],
      ['PointerToRelocations',4],
      ['PointerToLinenumbers',4],
      ['NumberOfRelocations', 2],
      ['NumberOfLinenumbers', 2],
      ['Characteristics',     4],
    ],
    'EXPORT_DIRECTORY': [
      ['Characteristics',      4],
      ['TimeDateStamp',        4],
      ['MajorVersion',         2],
      ['MinorVersion',         2],
      ['Name',                 4],
      ['Base',                 4],
      ['NumberOfFunctions',    4],
      ['NumberOfNames',        4],
      ['AddressOfFunctions',   4],
      ['AddressOfNames',       4],
      ['AddressOfNameOrdinals',4],
    ],
    'DEBUG_DIRECTORY': [
      ['Characteristics', 4],
      ['TimeDateStamp',   4],
      ['MajorVersion',    2],
      ['MinorVersion',    2],
      ['Type',            4],
      ['SizeOfData',      4],
      ['AddressOfRawData',4],
      ['PointerToRawData',4],
    ],
    'IMPORT_DESCRIPTOR': [
      ['OriginalFirstThunk',4],
      ['TimeDateStamp',     4],
      ['ForwarderChain',    4],
      ['Name',              4],
      ['FirstThunk',        4],
    ],
    'DELAY_IMPORT_DESCRIPTOR': [
      ['Attributes',             4],
      ['Name',                   4],
      ['ModuleHandle',           4],
      ['ImportAddressTable',     4],
      ['ImportNameTable',        4],
      ['BoundImportAddressTable',4],
      ['UnloadInformationTable', 4],
      ['TimeDateStamp',          4],
    ],
    'BOUND_IMPORT_DESCRIPTOR': [
      ['TimeDateStamp',              4],
      ['OffsetModuleName',           2],
      ['NumberOfModuleForwarderRefs',2],
    ],
    'BASE_RELOCATION': [
      ['VirtualAddress',4],
      ['SizeOfBlock',   4],
    ],
    'EXCEPTION_FUNCTION_ENTRY': [
      ['StartingAddress',  4],
      ['EndingAddress',    4],
      ['UnwindInfoAddress',4],
    ],
    'TLS_DIRECTORY_32': [
      ['StartAddressOfRawData',4],
      ['EndAddressOfRawData',  4],
      ['AddressOfIndex',       4],
      ['AddressOfCallBacks',   4],
      ['SizeOfZeroFill',       4],
      ['Characteristics',      4],
    ],
    'TLS_DIRECTORY_64': [
      ['StartAddressOfRawData',8],
      ['EndAddressOfRawData',  8],
      ['AddressOfIndex',       8],
      ['AddressOfCallBacks',   8],
      ['SizeOfZeroFill',       4],
      ['Characteristics',      4],
    ],
    'LOAD_CONFIG_DIRECTORY_32': [
      ['Size',                         4],
      ['TimeDateStamp',                4],
      ['MajorVersion',                 2],
      ['MinorVersion',                 2],
      ['GlobalFlagsClear',             4],
      ['GlobalFlagsSet',               4],
      ['CriticalSectionDefaultTimeout',4],
      ['DeCommitFreeBlockThreshold',   4],
      ['DeCommitTotalFreeThreshold',   4],
      ['LockPrefixTable',              4],
      ['MaximumAllocationSize',        4],
      ['VirtualMemoryThreshold',       4],
      ['ProcessHeapFlags',             4],
      ['ProcessAffinityMask',          4],
      ['CSDVersion',                   2],
      ['Reserved1',                    2],
      ['EditList',                     4],
      ['SecurityCookie',               4],
      ['SEHandlerTable',               4],
      ['SEHandlerCount',               4],
    ],
    'LOAD_CONFIG_DIRECTORY_64': [
      ['Size',                         4],
      ['TimeDateStamp',                4],
      ['MajorVersion',                 2],
      ['MinorVersion',                 2],
      ['GlobalFlagsClear',             4],
      ['GlobalFlagsSet',               4],
      ['CriticalSectionDefaultTimeout',4],
      ['DeCommitFreeBlockThreshold',   8],
      ['DeCommitTotalFreeThreshold',   8],
      ['LockPrefixTable',              8],
      ['MaximumAllocationSize',        8],
      ['VirtualMemoryThreshold',       8],
      ['ProcessAffinityMask',          8],
      ['ProcessHeapFlags',             4],
      ['CSDVersion',                   2],
      ['Reserved1',                    2],
      ['EditList',                     8],
      ['SecurityCookie',               8],
      ['SEHandlerTable',               8],
      ['SEHandlerCount',               8],
    ],
    'RESOURCE_DIRECTORY': [
      ['Characteristics',     4],
      ['TimeDateStamp',       4],
      ['MajorVersion',        2],
      ['MinorVersion',        2],
      ['NumberOfNamedEntries',2],
      ['NumberOfIdEntries',   2],
    ],
  }

  // static constants for the PE format
  const _static = {
    // Machine Types
    // https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#machine-types
    "IMAGE_FILE_MACHINE_UNKNOWN": 0x0,
    "IMAGE_FILE_MACHINE_AM33": 0x1d3,
    "IMAGE_FILE_MACHINE_AMD64": 0x8664,
    "IMAGE_FILE_MACHINE_ARM": 0x1c0,
    "IMAGE_FILE_MACHINE_ARM64": 0xaa64,
    "IMAGE_FILE_MACHINE_ARMNT": 0x1c4,
    "IMAGE_FILE_MACHINE_EBC": 0xebc,
    "IMAGE_FILE_MACHINE_I386": 0x14c,
    "IMAGE_FILE_MACHINE_IA64": 0x200,
    "IMAGE_FILE_MACHINE_M32R": 0x9041,
    "IMAGE_FILE_MACHINE_MIPS16": 0x266,
    "IMAGE_FILE_MACHINE_MIPSFPU": 0x366,
    "IMAGE_FILE_MACHINE_MIPSFPU16": 0x466,
    "IMAGE_FILE_MACHINE_POWERPC": 0x1f0,
    "IMAGE_FILE_MACHINE_POWERPCFP": 0x1f1,
    "IMAGE_FILE_MACHINE_R4000": 0x166,
    "IMAGE_FILE_MACHINE_RISCV32": 0x5032,
    "IMAGE_FILE_MACHINE_RISCV64": 0x5064,
    "IMAGE_FILE_MACHINE_RISCV128": 0x5128,
    "IMAGE_FILE_MACHINE_SH3": 0x1a2,
    "IMAGE_FILE_MACHINE_SH3DSP": 0x1a3,
    "IMAGE_FILE_MACHINE_SH4": 0x1a6,
    "IMAGE_FILE_MACHINE_SH5": 0x1a8,
    "IMAGE_FILE_MACHINE_THUMB": 0x1c2,
    "IMAGE_FILE_MACHINE_WCEMIPSV2": 0x169,
    // Characteristics
    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
    "IMAGE_FILE_RELOCS_STRIPPED": 0x0001,
    "IMAGE_FILE_EXECUTABLE_IMAGE": 0x0002,
    "IMAGE_FILE_LINE_NUMS_STRIPPED": 0x0004,
    "IMAGE_FILE_LOCAL_SYMS_STRIPPED": 0x0008,
    "IMAGE_FILE_AGGRESSIVE_WS_TRIM": 0x0010,
    "IMAGE_FILE_LARGE_ADDRESS_AWARE": 0x0020,
    "IMAGE_FILE_RESERVED": 0x0040,
    "IMAGE_FILE_BYTES_REVERSED_LO": 0x0080,
    "IMAGE_FILE_32BIT_MACHINE": 0x0100,
    "IMAGE_FILE_DEBUG_STRIPPED": 0x0200,
    "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP": 0x0400,
    "IMAGE_FILE_NET_RUN_FROM_SWAP": 0x0800,
    "IMAGE_FILE_SYSTEM": 0x1000,
    "IMAGE_FILE_DLL": 0x2000,
    "IMAGE_FILE_UP_SYSTEM_ONLY": 0x4000,
    "IMAGE_FILE_BYTES_REVERSED_HI": 0x8000,
  }

  // given a struct from _headers, calculate the total struct size
  const _size = (struct) => {
    var s = 0;
    struct.forEach((e) => {
      s += e[1];
    });
    return s;
  };

  // unpack binary structures from file data
  async function _unpack(struct, fileOffset) {
    var data = await salsa.utils.read(_file, fileOffset, _size(struct));
    for (var i = 0, structOffset = 0, result = {}; i < struct.length; i++) {
      result[struct[i][0]] = data.slice(structOffset, structOffset + struct[i][1]);
      structOffset += struct[i][1];
    }
    return result;
  }

  // parse DOS header
  // https://source.winehq.org/source/include/winnt.h#2556
  async function _DOS_HEADER() {
    _offset = 0;
    _data['DOS_HEADER'] = await _unpack(_headers['DOS_HEADER'], _offset);
  }

  // parse DOS stub
  // https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#ms-dos-stub-image-only
  async function _DOS_STUB() {
    var stubLength = salsa.utils.uint(_data['DOS_HEADER']['e_lfanew']) - _size(_headers['DOS_HEADER']);
    _data['DOS_STUB'] = await salsa.utils.read(_file, _size(_headers['DOS_HEADER']), stubLength);
    _offset += salsa.utils.uint(_data['DOS_HEADER']['e_lfanew']);
  }

  // parse PE header (COFF header)
  // https://source.winehq.org/source/include/winnt.h#2592
  // https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#coff-file-header-object-and-image
  async function _PE_HEADER() {
    _data['PE_HEADER'] = await _unpack(_headers['PE_HEADER'], _offset);
    _offset += _size(_headers['PE_HEADER']);
  }

  // parse "optional" IMAGE header
  // (x86) https://source.winehq.org/source/include/winnt.h#2877
  // (x64) https://source.winehq.org/source/include/winnt.h#2838
  // https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#optional-header-standard-fields-image-only
  async function _IMAGE_HEADER() {
    if (salsa.utils.uint(_data['PE_HEADER']['SizeOfOptionalHeader']) > 0) {
      var arch = await salsa.utils.read(_file, _offset, 2);
      if (salsa.utils.uint(arch) == 0x20b) {
        // x64
        _x64 = true;
        _data['IMAGE_HEADER'] = await _unpack(_headers['IMAGE_HEADER_64'], _offset);
        _offset += _size(_headers['IMAGE_HEADER_64']);
      } else if (salsa.utils.uint(arch) == 0x10b) {
        // x86
        _x64 = false;
        _data['IMAGE_HEADER'] = await _unpack(_headers['IMAGE_HEADER_32'], _offset);
        _offset += _size(_headers['IMAGE_HEADER_32']);
      } else {
        throw('_IMAGE_HEADER(): Unknown machine type in header: ' + salsa.utils.uint(arch));
      }
    } else {
      throw('_IMAGE_HEADER(): IMAGE header size is 0');
    }
  }

  // parse DATA directories (number of directories varies by compiler)
  // https://source.winehq.org/source/include/winnt.h#2831
  // https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#optional-header-data-directories-image-only
  async function _DATA_DIRECTORY() {
    var numDirs = salsa.utils.uint(_data['IMAGE_HEADER']['NumberOfRvaAndSizes']);
    // only parse data directories that are specified
    var dirFmt = _headers['DATA_DIRECTORY'].slice(Math.min(numDirs * 2, _headers['DATA_DIRECTORY'].length));
    _data['DATA_DIRECTORY'] = await _unpack(_headers['DATA_DIRECTORY'], _offset);
    _offset += _size(_headers['DATA_DIRECTORY']);
  }

  // parse section headers
  // https://source.winehq.org/source/include/winnt.h#2938
  // https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#section-table-section-headers
  async function _SECTION_HEADERS() {
    _data['SECTIONS'] = [];
    for (var i = 0; i < salsa.utils.uint(_data['PE_HEADER']['NumberOfSections']); i++) {
      var section = await _unpack(_headers['SECTION_HEADER'], _offset);
      _offset += _size(_headers['SECTION_HEADER']);
      _data['SECTIONS'].push(section);
    }
  }

  // parse debug data directory entry
  // https://source.winehq.org/source/include/winnt.h#3712
  // https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#the-debug-section
  async function _DATA_DIRECTORY_DEBUG() {
    _data['PE_HEADER'] = await _unpack(_headers['PE_HEADER'], _offset);
    _offset += _size(_headers['PE_HEADER']);
  }

  // parse an executable from start to end
  async function parse(file) {
    _file = file;
    // TODO: add try/catch here for each section
    await _DOS_HEADER();
    await _DOS_STUB();
    await _PE_HEADER();
    await _IMAGE_HEADER();
    await _DATA_DIRECTORY();
    await _SECTION_HEADERS();
    // TODO: data directories
    // await _DATA_DIRECTORY_DEBUG();
    // give raw PE data to the application
    return _data;
  }

  // object interface to the application
  var _api = {
    'parse': parse,
  };
  // add static constants
  for (var k in _static) {
    if (_static.hasOwnProperty(k)) {
      _api[k] = _static[k];
    }
  }
  return _api;

})();
