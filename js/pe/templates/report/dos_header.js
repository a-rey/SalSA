/**
 * generates dos header panel for a PE report
 */

salsa.templates['PE'].push((() => {
  'use strict';

  // https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#MS-DOS_header
  const REF_STUB_1 = `; Using NASM with Intel Syntax
push cs        ; push CS onto the stack
pop ds         ; set DS to CS

; this means that Data Segment and Code Segment point to the same
; 64k byte area of memory. without this we would not be able
; to load any data.

mov dx,message ; load address of message
mov ah, 09     ; ah = 9 is the DOS interrupt print a string
int 0x21
mov ax,0x4c01  ; terminate the program
int 0x21

; 0Dh is the 'Carriage return' ASCII code
; 0Ah is the 'Line feed' ASCII code
; '$$' is the string-terminator in DOS
message db "This program cannot be run in DOS mode.", 0x0d, 0x0d, 0x0a, '$$'`;

  // https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#MS-DOS_header
  const REF_STUB_2 = `00000000  0E      push cs
00000001  1F      pop ds
00000002  BA0E00  mov dx,0xe
00000005  B409    mov ah,0x9
00000007  CD21    int 0x21
00000009  B8014C  mov ax,0x4c01
0000000C  CD21    int 0x21`;

  async function render(pedata) {
    // load template from DOM
    var template = document.getElementById('template-pe-report-dos');
    // format general HTML
    for (var k in pedata['DOS_HEADER']) {
      if (k !== 'e_magic') {
        template.innerHTML = template.innerHTML.replace(
          new RegExp(`{{${k}}}`, 'g'),
          salsa.utils.hex(pedata['DOS_HEADER'][k], true)
        );
      } else {
        // dont reverse string characters
        template.innerHTML = template.innerHTML.replace(
          new RegExp(`{{${k}}}`, 'g'),
          salsa.utils.hex(pedata['DOS_HEADER'][k])
        );
      }
    }
    // perform hexdump of DOS_STUB
    template.innerHTML = template.innerHTML.replace(
      /{{DOS_STUB}}/g,
      salsa.utils.hexdump(pedata['DOS_STUB'])
    );
    // add DOS stub references
    template.innerHTML = template.innerHTML.replace(/{{REF_STUB_1}}/g, REF_STUB_1);
    template.innerHTML = template.innerHTML.replace(/{{REF_STUB_2}}/g, REF_STUB_2);
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
