/**
 * generates pe/coff header panel for a PE report
 */

salsa.templates['PE'].push((() => {
  'use strict';
  const LEVEL = {
    INFO: 1,
    WARN: 2,
    ERROR: 3,
  }

  // make a Bulma CSS notification from a PE header Characteristic flag
  function makeMessage(key, flag, type) {
    var style = ''
    switch (type) {
      case LEVEL.INFO:
        style = 'is-info';
        break;
      case LEVEL.WARN:
        style = 'is-warning';
        break;
      case LEVEL.ERROR:
        style = 'is-danger';
        break;
    }
    const msg = salsa.utils.getCharacteristicDescriptionPE(flag);
    return `
    <article class="message ${style}">
      <div class="message-header"><p>${key}:</p></div>
      <div class="message-body">${msg}</div>
    </article>`;
  }

  async function render(pedata) {
    // load template from DOM
    var template = document.getElementById('template-pe-report-coff');
    // format general HTML
    for (var k in pedata['PE_HEADER']) {
      if (k !== 'Signature') {
        template.innerHTML = template.innerHTML.replace(
          new RegExp(`{{${k}}}`, 'g'),
          salsa.utils.hex(pedata['PE_HEADER'][k], true)
        );
      } else {
        // dont reverse string characters
        template.innerHTML = template.innerHTML.replace(
          new RegExp(`{{${k}}}`, 'g'),
          salsa.utils.hex(pedata['PE_HEADER'][k])
        );
      }
    }
    // identify machine type description
    const machine_type = salsa.utils.getMachineTypeDescriptionPE(salsa.utils.uint(pedata['PE_HEADER']['Machine'], true));
    template.innerHTML = template.innerHTML.replace(/{{MACHINE_TYPE}}/g, machine_type);
    // set readable timestamp
    const timestamp = new Date(1000 * salsa.utils.uint(pedata['PE_HEADER']['TimeDateStamp'], true));
    template.innerHTML = template.innerHTML.replace(/{{TIMESTAMP}}/g, timestamp);
    // parse characteristics and add notifications
    var notifications = '';
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_RELOCS_STRIPPED) {
      notifications += makeMessage('IMAGE_FILE_RELOCS_STRIPPED', PE.IMAGE_FILE_RELOCS_STRIPPED, LEVEL.INFO);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_EXECUTABLE_IMAGE) {
      notifications += makeMessage('IMAGE_FILE_EXECUTABLE_IMAGE', PE.IMAGE_FILE_EXECUTABLE_IMAGE, LEVEL.INFO);
    } else {
      // should always be set
      notifications += makeMessage('IMAGE_FILE_EXECUTABLE_IMAGE (missing?)', PE.IMAGE_FILE_EXECUTABLE_IMAGE, LEVEL.ERROR);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_LINE_NUMS_STRIPPED) {
      // should be zero
      notifications += makeMessage('IMAGE_FILE_LINE_NUMS_STRIPPED', PE.IMAGE_FILE_LINE_NUMS_STRIPPED, LEVEL.WARN);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_LOCAL_SYMS_STRIPPED) {
      // should be zero
      notifications += makeMessage('IMAGE_FILE_LOCAL_SYMS_STRIPPED', PE.IMAGE_FILE_LOCAL_SYMS_STRIPPED, LEVEL.WARN);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_AGGRESSIVE_WS_TRIM) {
      // should not be set
      notifications += makeMessage('IMAGE_FILE_AGGRESSIVE_WS_TRIM', PE.IMAGE_FILE_AGGRESSIVE_WS_TRIM, LEVEL.ERROR);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_LARGE_ADDRESS_AWARE) {
      notifications += makeMessage('IMAGE_FILE_LARGE_ADDRESS_AWARE', PE.IMAGE_FILE_LARGE_ADDRESS_AWARE, LEVEL.INFO);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_RESERVED) {
      // should not be set
      notifications += makeMessage('IMAGE_FILE_RESERVED', PE.IMAGE_FILE_RESERVED, LEVEL.ERROR);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_BYTES_REVERSED_LO) {
      // should be zero
      notifications += makeMessage('IMAGE_FILE_BYTES_REVERSED_LO', PE.IMAGE_FILE_BYTES_REVERSED_LO, LEVEL.WARN);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_32BIT_MACHINE) {
      notifications += makeMessage('IMAGE_FILE_32BIT_MACHINE', PE.IMAGE_FILE_32BIT_MACHINE, LEVEL.INFO);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_DEBUG_STRIPPED) {
      notifications += makeMessage('IMAGE_FILE_DEBUG_STRIPPED', PE.IMAGE_FILE_DEBUG_STRIPPED, LEVEL.INFO);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) {
      notifications += makeMessage('IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP', PE.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, LEVEL.INFO);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_NET_RUN_FROM_SWAP) {
      notifications += makeMessage('IMAGE_FILE_NET_RUN_FROM_SWAP', PE.IMAGE_FILE_NET_RUN_FROM_SWAP, LEVEL.INFO);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_SYSTEM) {
      notifications += makeMessage('IMAGE_FILE_SYSTEM', PE.IMAGE_FILE_SYSTEM, LEVEL.INFO);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_DLL) {
      notifications += makeMessage('IMAGE_FILE_DLL', PE.IMAGE_FILE_DLL, LEVEL.INFO);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_UP_SYSTEM_ONLY) {
      notifications += makeMessage('IMAGE_FILE_UP_SYSTEM_ONLY', PE.IMAGE_FILE_UP_SYSTEM_ONLY, LEVEL.INFO);
    }
    if (salsa.utils.uint(pedata['PE_HEADER']['Characteristics'], true) & PE.IMAGE_FILE_BYTES_REVERSED_HI) {
      // should be zero
      notifications += makeMessage('IMAGE_FILE_BYTES_REVERSED_HI', PE.IMAGE_FILE_BYTES_REVERSED_HI, LEVEL.WARN);
    }
    template.innerHTML = template.innerHTML.replace(/{{CHARACTERISTICS}}/g, notifications);
    // add formatted html to DOM
    for (var i = 0; i < template.content.children.length; i++) {
      document.body.appendChild(template.content.children[i]);
    }
  };

  // object interface to the caller
  return {
    'render': render
  };
})());
