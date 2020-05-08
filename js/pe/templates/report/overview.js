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
    const machine_type = PE.utils.getMachineType(salsa.utils.uint(pedata['PE_HEADER']['Machine'], true));
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
