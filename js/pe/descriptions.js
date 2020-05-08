/**
 * PE parsing library header descriptions
 */

PE.descriptions = (() => {
  'use strict';

  const descs = {
    'dos_header': 'https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#MS-DOS_header',
    'dos_header.e_magic': 'Magic number (\'MZ\' in ASCII)',
    'dos_header.e_cblp': 'Bytes in last page of file',
    'dos_header.e_cp': 'Number of pages in file',
    'dos_header.e_crlc': 'Relocation items',
    'dos_header.e_cparhdr': 'Number of paragraphs in header',
    'dos_header.e_minalloc': 'Minimum extra paragraphs needed',
    'dos_header.e_maxalloc': 'Maximum extra paragraphs needed',
    'dos_header.e_ss': 'Initial (relative) SS value',
    'dos_header.e_sp': 'Initial SP value',
    'dos_header.e_csum': 'Checksum',
    'dos_header.e_ip': 'Initial IP value',
    'dos_header.e_cs': 'Initial (relative) CS value',
    'dos_header.e_lfarlc': 'File address of relocation table',
    'dos_header.e_ovno': 'Overlay number',
    'dos_header.e_res': '<strong>Reserved</strong>',
    'dos_header.e_oemid': 'OEM identifier (for <span class="is-family-code">e_oeminfo</span>)',
    'dos_header.e_oeminfo': 'OEM information (<span class="is-family-code">e_oemid</span> specific)',
    'dos_header.e_res2': '<strong>Reserved</strong>',
    'dos_header.e_lfanew': 'File offset of the PE/COFF header',
    'coff_header': 'https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image',
    'coff_header.NumberOfSections': 'The number of sections. This indicates the size of the section table, which immediately follows the headers.',
    'coff_header.TimeDateStamp': 'The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), that indicates when the file was created.',
    'coff_header.PointerToSymbolTable': 'The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated.',
    'coff_header.NumberOfSymbols': 'The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated.',
    'coff_header.SizeOfOptionalHeader': 'The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file.',
    'coff_header.Characteristics': 'The flags that indicate the attributes of the file.',
    'image_header': 'https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only',
    'image_header.Magic': 'The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable.',
    'image_header.MajorLinkerVersion': 'The linker major version number.',
    'image_header.MinorLinkerVersion': 'The linker minor version number.',
    'image_header.SizeOfCode': 'The size of the code (text) section, or the sum of all code sections if there are multiple sections.',
    'image_header.SizeOfInitializedData': 'The size of the initialized data section, or the sum of all such sections if there are multiple data sections.',
    'image_header.SizeOfUninitializedData': 'The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.',
    'image_header.AddressOfEntryPoint': 'The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero.',
    'image_header.BaseOfCode': 'The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.',
    'image_header.BaseOfData': 'The address that is relative to the image base of the beginning-of-data section when it is loaded into memory.',
    'image_header.ImageBase': 'The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.',
    'image_header.SectionAlignment': 'The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.',
    'image_header.FileAlignment': 'The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture\'s page size, then FileAlignment must match SectionAlignment.',
    'image_header.MajorOperatingSystemVersion': 'The major version number of the required operating system.',
    'image_header.MinorOperatingSystemVersion': 'The minor version number of the required operating system.',
    'image_header.MajorImageVersion': 'The major version number of the image.',
    'image_header.MinorImageVersion': 'The minor version number of the image.',
    'image_header.MajorSubsystemVersion': 'The major version number of the subsystem.',
    'image_header.MinorSubsystemVersion': 'The minor version number of the subsystem.',
    'image_header.Win32VersionValue': 'Reserved, must be zero.',
    'image_header.SizeOfImage': 'The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.',
    'image_header.SizeOfHeaders': 'The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.',
    'image_header.CheckSum': 'The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.',
    'image_header.Subsystem': 'The subsystem that is required to run this image.',
    'image_header.DllCharacteristics': 'Characteristics of the DLL if the image is one.',
    'image_header.SizeOfStackReserve': 'The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached.',
    'image_header.SizeOfStackCommit': 'The size of the stack to commit.',
    'image_header.SizeOfHeapReserve': 'The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.',
    'image_header.SizeOfHeapCommit': 'The size of the local heap space to commit.',
    'image_header.LoaderFlags': 'Reserved, must be zero.',
    'image_header.NumberOfRvaAndSizes': 'The number of data-directory entries in the remainder of the optional header. Each describes a location and size.',
  };

  function getDescription(id) {
    return descs[id];
  }

  // object API
  return {
    get: getDescription,
  }

})();