/**
 * supported file formats
 */

salsa.magic = {
  // https://asecuritysite.com/forensics/magic
  'PE':  new Uint8Array([0x4D, 0x5A]),
  'ELF': new Uint8Array([0x7F, 0x45, 0x4C, 0x46]),
};