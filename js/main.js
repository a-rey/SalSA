/**
 * Main site handler for user file upload
 */

((window, document) => {
  'use strict';
  // global application container
  window.salsa = {};
  // define empty template arrays
  salsa.templates = {
    'PE': [],
    'ELF': [],
  };
  // delay in milliseconds for progress bar text updating
  const _PROGRESS_DELAY_MS = 300;

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
  salsa.updateProgressBar = async (value, msg) => {
    salsa._progressBar.setAttribute('value', value);
    salsa._progressBarHeader.innerHTML = msg;
    await salsa.utils.delay(_PROGRESS_DELAY_MS);
  };

  // removes the progress bar from the DOM
  salsa.removeProgressBar = async () => {
    await salsa.utils.delay(_PROGRESS_DELAY_MS);
    salsa._progressBarContainer.remove();
  };

  // removes all default HTML and "empties" the <body>
  salsa.removeDefaultContent = () => {
    salsa._defaultContent = [];
    // get all <section> tags that are a child of <body> and hide them
    document.querySelectorAll('body > section').forEach((ele) => {
      // save references in order for later viewing
      salsa._defaultContent.push(ele);
      ele.parentNode.removeChild(ele);
    });
  };

  // adds all default HTML on a page refresh
  salsa.addDefaultContent = () => {
    // get all <section> tags that are a child of <body> and show them
    salsa._defaultContent.forEach((e) => {
      document.body.appendChild(e);
    });
  };

  // finds all navigation bars on the DOM and adds the toggle listener for mobile views
  salsa.initDefaultNavBar = () => {
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

  // looks through magic file signatures to identify file type
  salsa.getFileFormat = async () => {
    // loop through known file signatures
    for (var key in salsa.magic) {
      if (salsa.magic.hasOwnProperty(key)) {
        var signature = await salsa.utils.read(salsa.file, 0, salsa.magic[key].length);
        signature = new Uint8Array(signature);
        // check signature
        var match = true;
        for (var i = 0; i < salsa.magic[key].length; i++) {
          if (salsa.magic[key][i] !== signature[i]) {
            match = false;
            break;
          }
        }
        // for a match, load parser
        if (match) {
          return key
        }
      }
    }
    return 'UNKNOWN';
  };

  // main routine for parsing a user file
  salsa.parseFile = async (e) => {
    // display the progress bar
    salsa.file = e.target.files[0];
    salsa.initProgressBar();
    await salsa.updateProgressBar('0', `examining ${salsa.file.name} ...`);
    // try to figure out file format
    var fmt = await salsa.getFileFormat();
    await salsa.updateProgressBar('10', `file format is ${fmt} ...`);
    salsa.parser = null;
    switch (fmt) {
      case 'PE':
        salsa.parser = PE;
        break;
      case 'ELF':
        salsa.parser = ELF;
        break;
    }
    // for each parsed file format, generate the report
    if (salsa.parser) {
      await salsa.updateProgressBar('20', `parsing ${salsa.file.name} ...`);
      const data = await salsa.parser.parse(salsa.file);
      await salsa.updateProgressBar('30', `generating report for ${salsa.file.name} ...`);
      salsa.removeDefaultContent();
      for (var i = 0; i < salsa.templates[fmt].length; i++) {
        await salsa.templates[fmt][i].render(data);
      }
      // TODO: apply rules
      await salsa.updateProgressBar('100', 'done!');
    } else {
      console.log('invalid')
    }
    await salsa.removeProgressBar();
  };

  // setup main page default event listeners
  salsa.init = () => {
    document.addEventListener('DOMContentLoaded', () => {
      document.getElementById('uploader').addEventListener('change', salsa.parseFile, false);
      salsa.initDefaultNavBar();
    });
  };

  // start the application
  salsa.init();

})(window, document);
