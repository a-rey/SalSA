/**
 * Main site handler for user file upload
 */

((window, document) => {
  'use strict';
  // global application container
  window.salsa = {};
  // delay in milliseconds for progress bar updating
  const _PROGRESS_DELAY_MS = 300;

  // utility function for progress bar UI
  const _delay = (ms) => {
    return (val) => {
      return new Promise((resolve, reject) => {
        setTimeout(() => resolve(val), ms);
      });
    };
  };

  // utility function to convert an ArrayBuffer to a hex string
  const _raw2Hex = (a) => {
    var hex = '';
    const view = new DataView(a);
    for (var i = 0; i < view.byteLength; i++) {
      var c = view.getUint8(i).toString(16);
      // zero pad one byte results
      if (c.length < 2) {
        c = '0' + c;
      }
      hex += c;
    }
    return hex;
  };``

  // creates the main progress bar for the application's status
  salsa.initProgressBar = () => {
    // make progress bar
    var progressBar = document.createElement('progress');
    var progressBarContainer = document.createElement('div');
    var progressBarHeader = document.createElement('h1');
    // make background modal
    var modalContent = document.createElement('div');
    var modalContainer = document.createElement('div');
    var modalBackground = document.createElement('div');
    // build HTML structure
    progressBarContainer.appendChild(progressBarHeader);
    progressBarContainer.appendChild(progressBar);
    modalContainer.appendChild(modalBackground);
    modalContainer.appendChild(modalContent);
    modalContent.appendChild(progressBarContainer);
    // add Bulma CSS classes
    modalContainer.classList.add('modal');
    modalContainer.classList.add('is-active');
    modalBackground.classList.add('modal-background');
    modalContent.classList.add('modal-content');
    progressBar.classList.add('progress');
    progressBar.classList.add('is-large');
    progressBarContainer.classList.add('box');
    progressBarHeader.classList.add('has-text-centered');
    progressBarHeader.classList.add('title');
    progressBarHeader.classList.add('has-text-weight-semibold');
    // set HTML attributes
    progressBar.setAttribute('max', '100');
    // append modal to the DOM
    document.body.appendChild(modalContainer);
    // maintain important references to progress bar
    salsa._progressBar = progressBar;
    salsa._progressBarContainer = modalContainer;
    salsa._progressBarHeader = progressBarHeader;
  };

  // updates the progress bar with value and status message
  salsa.updateProgressBar = (value, msg) => {
    salsa._progressBar.setAttribute('value', value);
    salsa._progressBarHeader.innerHTML = msg;
  };

  // removes the progress bar from the DOM
  salsa.removeProgressBar = () => {
    salsa._progressBarContainer.remove();
  };

  // hides all default HTML and "empties" the <body>
  salsa.hideDefaultContent = () => {
    salsa._defaultContent = [];
    // get all <section> tags that are a child of <body> and hide them
    document.querySelectorAll('body > section').forEach((ele) => {
      // save references in order for later viewing
      salsa._defaultContent.push(ele);
      ele.style.display = 'none';
    });
  };

  // shows all default HTML on a page refresh
  salsa.showDefaultContent = () => {
    // get all <section> tags that are a child of <body> and hide them
    salsa._defaultContent.forEach((e) => {
      e.style.display = 'block';
    });
  };

  // generates HTML for a report's navigation bar
  salsa.generateReportNavBar = () => {
    // load template from DOM
    var template = document.getElementById('report-navbar-template');
    // get the contents of the template
    var templateHtml = template.innerHTML;
    // TODO: add templating for alerts to show how many per section
    // render HTML
    salsa._reportNavBar = document.createElement('div');
    salsa._reportNavBar.innerHTML = templateHtml;
    document.body.classList.add('has-navbar-fixed-top');
    document.body.appendChild(salsa._reportNavBar);
  };

  // generates display for overview pane of a report
  salsa.generateReportOverview = () => {
    // use Web Cryptography API to generate hashes of the file
    PE.read(salsa._file, 0, salsa._file.size).then((rawData) => {
      const data = new Uint8Array(rawData);
      const sha1Promise = window.crypto.subtle.digest({'name':'SHA-1'}, data);
      const sha256Promise = window.crypto.subtle.digest({'name':'SHA-256'}, data);
      return Promise.all([sha1Promise, sha256Promise]).then(([sha1, sha256]) => {
        salsa._sha1hash = _raw2Hex(sha1);
        salsa._sha256hash = _raw2Hex(sha256);
      });
    }).then(() => {
      // identify machine type
      var machine_type = '';
      switch (PE.uint(salsa._pedata['PE_HEADER']['Machine'])) {
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
          machine_type = 'Intel x86';
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
      // get compilation time
      const creation_time = new Date(1000 * PE.uint(salsa._pedata['PE_HEADER']['TimeDateStamp']));
      // get human readable file size
      var file_size = '';
      if (salsa._file.size == 0) {
        file_size = "0.00 B";
      } else {
        var e = Math.floor(Math.log(salsa._file.size) / Math.log(1024));
        file_size = (salsa._file.size / Math.pow(1024, e)).toFixed(2) + ' ' + ' KMGTP'.charAt(e) + 'B';
      }
      // load template from DOM
      var template = document.getElementById('report-overview-template');
      // format HTML
      var html = template.innerHTML.replace(/{{SHA1}}/g, salsa._sha1hash)
                                   .replace(/{{SHA256}}/g, salsa._sha256hash)
                                   .replace(/{{FILENAME}}/g, salsa._file.name)
                                   .replace(/{{FILESIZE_ACTUAL}}/g, salsa._file.size)
                                   .replace(/{{FILESIZE_READABLE}}/g, file_size)
                                   .replace(/{{MACHINE_TYPE}}/g, machine_type)
                                   .replace(/{{TIMESTAMP}}/g, creation_time);
      // render HTML
      salsa._reportOverviewSection = document.createElement('div');
      salsa._reportOverviewSection.innerHTML = html;
      document.body.appendChild(salsa._reportOverviewSection);
    });
  };

  // generates display for DOS header
  salsa.generateReportDOS = () => {
    // load template from DOM
    var template = document.getElementById('report-dos-template').innerHTML;
    // format HTML
    for (var k in salsa._pedata['DOS_HEADER']) {
      template = template.replace(new RegExp(`{{${k}}}`, 'g'), '0x' + _raw2Hex(salsa._pedata['DOS_HEADER'][k]));
    }
    // TODO: make a better view for this
    template = template.replace(/{{DOS_STUB}}/g, '0x' + _raw2Hex(salsa._pedata['DOS_STUB']));
    // render HTML
    salsa._reportDOSSection = document.createElement('div');
    salsa._reportDOSSection.innerHTML = template;
    document.body.appendChild(salsa._reportDOSSection);
  };

  // applies pane toggle to all <a> tags with the pane class
  salsa.initPanes = () => {
    document.querySelectorAll('.salsa-pane-link').forEach((ele) => {
      ele.addEventListener('click', (event) => {
        // find active pane and hide it
        document.querySelectorAll('.salsa-pane-link').forEach((e) => {
          if (e.classList.contains('is-active')) {
            const active = document.getElementById(e.dataset.target);
            active.classList.add('is-hidden');
            e.classList.toggle('is-active');
          }
        });
        // get the target pane ID from the "data-target" attribute
        const target = document.getElementById(ele.dataset.target);
        // toggle the "is-active" class
        ele.classList.toggle('is-active');
        target.classList.toggle('is-hidden');
      });
    });
  };

  // finds all navigation bars on the DOM and adds the toggle listener for mobile views
  salsa.initNavBars = () => {
    document.querySelectorAll('.navbar-burger').forEach((ele) => {
      ele.addEventListener('click', (event) => {
        // get the target from the "data-target" attribute
        const target = document.getElementById(ele.dataset.target);
        // toggle the "is-active" class on both the "navbar-burger" and the "navbar-menu"
        ele.classList.toggle('is-active');
        target.classList.toggle('is-active');
      });
    });
  };

  // main routine for parsing a user file
  salsa.parseFile = (e) => {
    // display the progress bar
    salsa._file = e.target.files[0];
    salsa.initProgressBar();
    salsa.updateProgressBar('0', `parsing ${salsa._file.name} ...`);
    PE.parse(salsa._file).then((d) => {
      // save parsed data
      salsa._pedata = d;
    }).then(_delay(_PROGRESS_DELAY_MS)).then(() => {
      // apply rules
      salsa.updateProgressBar('33', `applying rules to ${salsa._file.name} ...`);
    }).then(_delay(_PROGRESS_DELAY_MS)).then(() => {
      // render HTML report
      salsa.updateProgressBar('66', `generating report for ${salsa._file.name} ...`);
      salsa.hideDefaultContent();
      salsa.generateReportNavBar();
      salsa.initNavBars();
      salsa.generateReportOverview();
      salsa.generateReportDOS();

      salsa.initPanes();
    }).then(_delay(_PROGRESS_DELAY_MS)).then(() => {
      salsa.updateProgressBar('100', 'done!');
    }).then(_delay(_PROGRESS_DELAY_MS)).then(() => {
      // cleanup and display results
      salsa.removeProgressBar();
    });
  };

  // setup main page default event listeners
  salsa.init = () => {
    document.addEventListener('DOMContentLoaded', () => {
      document.getElementById('pe-uploader').addEventListener('change', salsa.parseFile, false);
      salsa.initNavBars();
    });
  };

  // start the application
  salsa.init();

})(window, document);
