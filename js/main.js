/**
 * Main site handler for user file upload
 */

((window, document) => {
  'use strict';
  window.salsa = {};

  // creates the main progress bar for the application's status
  salsa.initProgressBar = (msg) => {
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
    progressBar.setAttribute('value', '0');
    progressBar.setAttribute('max', '100');
    progressBarHeader.innerHTML = msg;
    // append modal to the DOM
    document.body.appendChild(modalContainer);
    // maintain references to progress bar
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

  salsa.parseFile = (e) => {
    salsa._file = e.target.files[0];
    // display the progress bar
    salsa.initProgressBar(`parsing ${salsa._file.name} ...`);
    // parse the file
    PE.parse(salsa._file).then((d) => {
      salsa._pedata = d;
      salsa.updateProgressBar('33', `applying rules to ${salsa._file.name} ...`);
      // TODO: apply rules
      // salsa.updateProgressBar(66, `generating report for ${salsa._file.name} ...`);
      // TODO: render new HTML
      // salsa.updateProgressBar(100, 'Done!');
      // salsa.removeProgressBar();
    });
  };

  salsa.init = () => {
    // setup main page event listeners
    document.querySelector('#pe-uploader').addEventListener('change', salsa.parseFile, false);
  };

  // start the application
  salsa.init();

})(window, document);
