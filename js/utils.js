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

};
