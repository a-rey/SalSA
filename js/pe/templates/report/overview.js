/**
 * generates overview panel for a PE report
 */

salsa.templates['PE'].push((() => {
  'use strict';
  var sha1hash = null;
  var sha256hash = null;

  async function render(pedata) {
    // use Web Cryptography API to generate hashes of the file
    var rawData = salsa.utils.read(salsa.file, 0, salsa.file.size);
    const data = new Uint8Array(rawData);
    const sha1Promise = window.crypto.subtle.digest({'name':'SHA-1'}, data);
    const sha256Promise = window.crypto.subtle.digest({'name':'SHA-256'}, data);
    await Promise.all([sha1Promise, sha256Promise]).then(([sha1, sha256]) => {
      sha1hash = salsa.utils.hex(sha1, true);     // reverse due to little endian
      sha256hash = salsa.utils.hex(sha256, true); // reverse due to little endian
    });
    // identify machine type
    var machine_type = '';
    // reverse due to little endian
    switch (salsa.utils.uint(pedata['PE_HEADER']['Machine'], true)) {
      case PE.IMAGE_FILE_MACHINE_UNKNOWN:
        machine_type = 'Applicable to any machine type';
        break;
      case PE.IMAGE_FILE_MACHINE_AM33:
        machine_type = 'Matsushita AM33';
        break;
      case PE.IMAGE_FILE_MACHINE_AMD64:
        machine_type = 'Intel x64';
        break;
      case PE.IMAGE_FILE_MACHINE_ARM:
        machine_type = 'ARM little endian';
        break;
      case PE.IMAGE_FILE_MACHINE_ARM64:
        machine_type = 'ARM64 little endian';
        break;
      case PE.IMAGE_FILE_MACHINE_ARMNT:
        machine_type = 'ARM Thumb-2 little endian';
        break;
      case PE.IMAGE_FILE_MACHINE_EBC:
        machine_type = 'EFI byte code';
        break;
      case PE.IMAGE_FILE_MACHINE_I386:
        machine_type = 'Intel x86 (386 and similar processors)';
        break;
      case PE.IMAGE_FILE_MACHINE_IA64:
        machine_type = 'Intel Itanium processor family';
        break;
      case PE.IMAGE_FILE_MACHINE_M32R:
        machine_type = 'Mitsubishi M32R little endian';
        break;
      case PE.IMAGE_FILE_MACHINE_MIPS16:
        machine_type = 'MIPS16';
        break;
      case PE.IMAGE_FILE_MACHINE_MIPSFPU:
        machine_type = 'MIPS with FPU';
        break;
      case PE.IMAGE_FILE_MACHINE_MIPSFPU16:
        machine_type = 'MIPS16 with FPU';
        break;
      case PE.IMAGE_FILE_MACHINE_POWERPC:
        machine_type = 'Power PC little endian';
        break;
      case PE.IMAGE_FILE_MACHINE_POWERPCF:
        machine_type = 'Power PC with floating point support';
        break;
      case PE.IMAGE_FILE_MACHINE_R4000:
        machine_type = 'MIPS little endian';
        break;
      case PE.IMAGE_FILE_MACHINE_RISCV32:
        machine_type = 'RISC-V 32-bit address space';
        break;
      case PE.IMAGE_FILE_MACHINE_RISCV64:
        machine_type = 'RISC-V 64-bit address space';
        break;
      case PE.IMAGE_FILE_MACHINE_RISCV128:
        machine_type = 'RISC-V 128-bit address space';
        break;
      case PE.IMAGE_FILE_MACHINE_SH3:
        machine_type = 'Hitachi SH3';
        break;
      case PE.IMAGE_FILE_MACHINE_SH3DSP:
        machine_type = 'Hitachi SH3 DSP';
        break;
      case PE.IMAGE_FILE_MACHINE_SH4:
        machine_type = 'Hitachi SH4';
        break;
      case PE.IMAGE_FILE_MACHINE_SH5:
        machine_type = 'Hitachi SH5';
        break;
      case PE.IMAGE_FILE_MACHINE_THUMB:
        machine_type = 'Thumb';
        break;
      case PE.IMAGE_FILE_MACHINE_WCEMIPSV:
        machine_type = 'MIPS little endian WCE v2';
        break;
      default:
        machine_type = 'Invalid Machine Type';
    }
    // get compilation time (reverse due to little endian)
    const creation_time = new Date(1000 * salsa.utils.uint(pedata['PE_HEADER']['TimeDateStamp'], true));
    // get human readable file size
    var file_size = '';
    if (salsa.file.size == 0) {
      file_size = "0.00 B";
    } else {
      var e = Math.floor(Math.log(salsa.file.size) / Math.log(1024));
      file_size = (salsa.file.size / Math.pow(1024, e)).toFixed(2) + ' ' + ' KMGTP'.charAt(e) + 'B';
    }
    // load template from DOM
    var template = document.getElementById('template-pe-report-overview');
    // format template
    template.innerHTML = template.innerHTML.replace(/{{SHA1}}/g, sha1hash)
                                           .replace(/{{SHA256}}/g, sha256hash)
                                           .replace(/{{FILENAME}}/g, salsa.file.name)
                                           .replace(/{{FILESIZE_ACTUAL}}/g, salsa.file.size)
                                           .replace(/{{FILESIZE_READABLE}}/g, file_size)
                                           .replace(/{{MACHINE_TYPE}}/g, machine_type)
                                           .replace(/{{TIMESTAMP}}/g, creation_time);
    // add html to DOM
    for (var i = 0; i < template.content.children.length; i++) {
      document.body.appendChild(template.content.children[i]);
    }
  };

  // object interface to the caller
  return {
    'render': render
  };
})());
