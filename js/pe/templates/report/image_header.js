/**
 * generates image header panel for a PE report
 */

salsa.templates['PE'].push((() => {
  'use strict';

  async function render(pedata) {
    // load template from DOM
    var template = document.getElementById('template-pe-report-image');
    // format general HTML
    for (var k in pedata['IMAGE_HEADER']) {
      template.innerHTML = template.innerHTML.replace(
        new RegExp(`{{${k}}}`, 'g'),
        salsa.utils.hex(pedata['IMAGE_HEADER'][k], true)
      );
    }
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
