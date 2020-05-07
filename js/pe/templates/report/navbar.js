/**
 * generates navigation panel for a PE report
 */

salsa.templates['PE'].push((() => {
  'use strict';

  async function render(pedata) {
    // load template from DOM
    var template = document.getElementById('template-pe-report-navbar');
    // TODO: add templating for alerts to show how many per section
    document.body.classList.add('has-navbar-fixed-top');
    // add html to DOM
    for (var i = 0; i < template.content.children.length; i++) {
      document.body.appendChild(template.content.children[i]);
    }
    // apply mobile trigger for navbar-burger to show actual navbar
    document.querySelectorAll('.navbar-burger').forEach((ele) => {
      ele.addEventListener('click', (event) => {
        // get the target from the "data-target" attribute
        const target = document.getElementById(ele.dataset.target);
        // toggle the "is-active" class on both the "navbar-burger" and the "navbar-menu"
        ele.classList.toggle('is-active');
        target.classList.toggle('is-active');
      });
    });
    // apply toggle listener for clicking on report panel links from navbar
    document.querySelectorAll('.navbar-item').forEach((ele) => {
      // check if the element has a target
      if (ele.dataset.target) {
          ele.addEventListener('click', (event) => {
          // find current active panel and hide it
          document.querySelectorAll('.navbar-item').forEach((e) => {
            if (e.classList.contains('is-active')) {
              const active = document.getElementById(e.dataset.target);
              active.classList.add('is-hidden');
              e.classList.toggle('is-active');
            }
          });
          // get the target from the "data-target" attribute
          const target = document.getElementById(ele.dataset.target);
          // toggle the "is-active" class on both the navbar-item and the target panel
          ele.classList.toggle('is-active');
          target.classList.toggle('is-active');
          target.classList.toggle('is-hidden');
        });
      }
    });
  };

  // object interface to the caller
  return {
    'render': render
  };
})());
