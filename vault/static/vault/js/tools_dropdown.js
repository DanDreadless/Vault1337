// tools_dropdown.js
$(document).ready(function() {
  // Initial state on page load
  updateSubToolChoices();

  // Bind an event listener to the tool dropdown change
  $('#id_tool').change(function() {
    updateSubToolChoices();
  });

  function updateSubToolChoices() {
    // Get the selected tool value
    var selectedTool = $('#id_tool').val();

    // Define subtool choices based on the selected tool
    var subToolChoices = {};
    subToolChoices['lief-parser'] = [
      ['dos_header', 'DOS Header'],
      ['rich_header', 'Rich Header'],
      ['pe_header', 'PE Header'],
      ['entrypoint', 'Entrypoint'],
      ['sections', 'Sections'],
      ['imports', 'Imports']
    ];
    subToolChoices['oletools'] = [
      ['oleid', 'OLEID'],
      ['olemeta', 'OLEMETA'],
      ['oledump', 'OLEDUMP'],
      ['olevba', 'OLEVBA'],
      ['rtfobj', 'RTFOBJ'],
      ['oleobj', 'OLEOBJ']
    ];
    subToolChoices['email-parser'] = [
      ['email_headers', 'Get Email Headers'],
      ['email_body', 'Get Email Body'],
    ];
    subToolChoices['strings'] = [
      ['utf-8', 'utf-8'],
      ['latin-1', 'latin-1'],
      ['utf-16', 'utf-16'],
      ['utf-16le', 'utf-16le'],
      ['utf-16be', 'utf-16be'],
      ['utf-32', 'utf-32'],
      ['ascii', 'ascii'],
    ];
    // Add more subtool choices as needed
  
    // Get the subtool dropdown element
    var subToolDropdown = $('#id_sub_tool');

    // Clear existing options
    subToolDropdown.empty();

    // Populate options based on the selected tool
    if (selectedTool in subToolChoices) {
      subToolDropdown.prop('disabled', false);
      for (var i = 0; i < subToolChoices[selectedTool].length; i++) {
        var option = $('<option>');
        option.val(subToolChoices[selectedTool][i][0]);
        option.text(subToolChoices[selectedTool][i][1]);
        subToolDropdown.append(option);
      }
    } else {
      subToolDropdown.prop('disabled', true);
    }
  }
});
