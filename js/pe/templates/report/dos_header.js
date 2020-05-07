/**
 * generates dos header panel for a PE report
 */

salsa.templates['PE'].push((() => {
  'use strict';

  async function render(pedata) {
    // load template from DOM
    var template = document.getElementById('template-pe-report-dos');
    // format general HTML
    for (var k in pedata['DOS_HEADER']) {
      template.innerHTML = template.innerHTML.replace(
        new RegExp(`{{${k}}}`, 'g'),
        salsa.utils.hex(pedata['DOS_HEADER'][k], true)
      );
    }
    template.innerHTML = template.innerHTML.replace(
      /{{DOS_STUB}}/g,
      salsa.utils.hex(pedata['DOS_STUB'])
    );
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
