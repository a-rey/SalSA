/**
 * utilities for handling raw file data
 */

salsa.utils = {

  // synchronous delay using promises
  delay: (ms) => {
    return new Promise((resolve, reject) => {
      setTimeout(() => resolve(), ms);
    });
  },

  // browser interaction with uploaded files using promises
  read: (file, offset, length) => new Promise((resolve, reject) => {
    // FileReader API: https://developer.mozilla.org/en-US/docs/Web/API/FileReader
    var fr = new FileReader();
    fr.onload = (e) => {
      resolve(e.target.result);
    };
    fr.onerror = (e) => {
      e.abort();
      return reject(this);
    };
    fr.readAsArrayBuffer(file.slice(offset, offset + length));
  }),

  // convert an ArrayBuffer to an unsigned integer
  uint: (buffer, reverse=false) => {
    var r = 0;
    const a = new Uint8Array(buffer);
    if (reverse) {
      for (var i = 0; i < a.length; i++) {
        r += (a[i] << (8 * i));
      }
    } else {
      for (var i = (a.length - 1); i >= 0; i--) {
        r += (a[i] << (8 * i));
      }
    }
    return r;
  },

  // convert an ArrayBuffer of bytes to an ASCII string
  str: (buffer, reverse=false) => {
    var r = '';
    const a = new Uint8Array(buffer);
    if (reverse) {
      for (var i = 0; i < a.length; i++) {
        r += String.fromCharCode(a[i]);
      }
    } else {
      for (var i = (a.length - 1); i >= 0; i--) {
        r += String.fromCharCode(a[i]);
      }
    }
    return r;
  },

  // convert an ArrayBuffer of bytes to a hex string
  hex: (buffer, reverse=false) => {
    var r = '';
    const a = new DataView(buffer);
    if (reverse) {
      for (var i = (a.byteLength - 1); i >= 0; i--) {
        var c = a.getUint8(i).toString(16);
        // zero pad one byte results
        if (c.length < 2) {
          c = '0' + c;
        }
        r += c;
      }
    } else {
      for (var i = 0; i < a.byteLength; i++) {
        var c = a.getUint8(i).toString(16);
        // zero pad one byte results
        if (c.length < 2) {
          c = '0' + c;
        }
        r += c;
      }
    }
    return r;
  },

  // perform a "hexdump" on some binary data
  hexdump: (buffer) => {
    var r = '';
    const a = new Uint8Array(buffer);
    // parse hex dump in groups of 16
    for (var blk_idx = 0; blk_idx < a.length; blk_idx += 16) {
      // get block from raw data
      var blk = a.slice(blk_idx, Math.min(blk_idx + 16, a.length));
      // write line offset to monitor buffer
      r += (('00000000' + blk_idx.toString(16)).slice(-8) + ' ');
      // create hex display
      var hex = '';
      for (var i = 0; i < blk.length; i++) {
        hex += (' ' + ((0xF0 & blk[i]) >> 4).toString(16).toUpperCase() + (0x0F & blk[i]).toString(16).toUpperCase());
      }
      hex += '   '.repeat(16 - blk.length);
      // add hex to buffer
      r += (hex + '  ');
      // create ASCII text display
      var chars = '';
      for (var i = 0; i < blk.length; i++) {
        chars += String.fromCharCode(blk[i]);
      }
      // replace non-ASCII with a '.'
      r += chars.replace(/[\x00-\x1F\x7F-\xFF\x20]/g, '.');
      r += '\n';
    }
    return r;
  },

  // match a binary PE machine type to a description string
  // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
  getMachineTypeDescriptionPE: (type) => {
    switch (type) {
      case PE.IMAGE_FILE_MACHINE_UNKNOWN:
        return 'Applicable to any machine type';
      case PE.IMAGE_FILE_MACHINE_AM33:
        return 'Matsushita AM33';
      case PE.IMAGE_FILE_MACHINE_AMD64:
        return 'Intel x64';
      case PE.IMAGE_FILE_MACHINE_ARM:
        return 'ARM little endian';
      case PE.IMAGE_FILE_MACHINE_ARM64:
        return 'ARM64 little endian';
      case PE.IMAGE_FILE_MACHINE_ARMNT:
        return 'ARM Thumb-2 little endian';
      case PE.IMAGE_FILE_MACHINE_EBC:
        return 'EFI byte code';
      case PE.IMAGE_FILE_MACHINE_I386:
        return 'Intel x86 (386 and similar processors)';
      case PE.IMAGE_FILE_MACHINE_IA64:
        return 'Intel Itanium processor family';
      case PE.IMAGE_FILE_MACHINE_M32R:
        return 'Mitsubishi M32R little endian';
      case PE.IMAGE_FILE_MACHINE_MIPS16:
        return 'MIPS16';
      case PE.IMAGE_FILE_MACHINE_MIPSFPU:
        return 'MIPS with FPU';
      case PE.IMAGE_FILE_MACHINE_MIPSFPU16:
        return 'MIPS16 with FPU';
      case PE.IMAGE_FILE_MACHINE_POWERPC:
        return 'Power PC little endian';
      case PE.IMAGE_FILE_MACHINE_POWERPCF:
        return 'Power PC with floating point support';
      case PE.IMAGE_FILE_MACHINE_R4000:
        return 'MIPS little endian';
      case PE.IMAGE_FILE_MACHINE_RISCV32:
        return 'RISC-V 32-bit address space';
      case PE.IMAGE_FILE_MACHINE_RISCV64:
        return 'RISC-V 64-bit address space';
      case PE.IMAGE_FILE_MACHINE_RISCV128:
        return 'RISC-V 128-bit address space';
      case PE.IMAGE_FILE_MACHINE_SH3:
        return 'Hitachi SH3';
      case PE.IMAGE_FILE_MACHINE_SH3DSP:
        return 'Hitachi SH3 DSP';
      case PE.IMAGE_FILE_MACHINE_SH4:
        return 'Hitachi SH4';
      case PE.IMAGE_FILE_MACHINE_SH5:
        return 'Hitachi SH5';
      case PE.IMAGE_FILE_MACHINE_THUMB:
        return 'Thumb';
      case PE.IMAGE_FILE_MACHINE_WCEMIPSV:
        return 'MIPS little endian WCE v2';
      default:
        return 'Invalid Machine Type';
    }
  },

  // match a PE characteristic flag to a description string
  // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
  getCharacteristicDescriptionPE: (type) => {
    switch (type) {
      case PE.IMAGE_FILE_RELOCS_STRIPPED:
        return 'This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error.';
      case PE.IMAGE_FILE_EXECUTABLE_IMAGE:
        return 'This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.';
      case PE.IMAGE_FILE_LINE_NUMS_STRIPPED:
        return 'COFF line numbers have been removed. This flag is deprecated and should be zero.';
      case PE.IMAGE_FILE_LOCAL_SYMS_STRIPPED:
        return 'COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.';
      case PE.IMAGE_FILE_AGGRESSIVE_WS_TRIM:
        return 'This flag is deprecated for Windows 2000 and later and must be zero.';
      case PE.IMAGE_FILE_LARGE_ADDRESS_AWARE:
        return 'Application can handle > 2 GB addresses.';
      case PE.IMAGE_FILE_RESERVED:
        return 'This flag is reserved for future use.';
      case PE.IMAGE_FILE_BYTES_REVERSED_LO:
        return 'Little endian. This flag is deprecated and should be zero.';
      case PE.IMAGE_FILE_32BIT_MACHINE:
        return 'Code is based on a 32-bit-word architecture.';
      case PE.IMAGE_FILE_DEBUG_STRIPPED:
        return 'Debugging information is removed from the image file.';
      case PE.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP:
        return 'If the image is on removable media, fully load it and copy it to the swap file.';
      case PE.IMAGE_FILE_NET_RUN_FROM_SWAP:
        return 'If the image is on network media, fully load it and copy it to the swap file.';
      case PE.IMAGE_FILE_SYSTEM:
        return 'The image file is a system file, not a user program.';
      case PE.IMAGE_FILE_DLL:
        return 'The image file is a dynamic-link library (DLL)';
      case PE.IMAGE_FILE_UP_SYSTEM_ONLY:
        return 'The file should be run only on a uniprocessor machine.';
      case PE.IMAGE_FILE_BYTES_REVERSED_HI:
        return 'Big endian. This flag is deprecated and should be zero.';
    }
  }

};
