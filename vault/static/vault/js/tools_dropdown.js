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
        ['entrypoint', 'Entrypoint']
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
  