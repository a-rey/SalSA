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

};
