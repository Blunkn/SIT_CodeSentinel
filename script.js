// script.js

// Wait for DOM to be ready before attaching event listeners
document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    // Attach an event listener to the button
    scanBtn.addEventListener('click', myFunction);
  });
  
  // This function is called when the button is clicked
  function myFunction() {
    alert('Button clicked! This is from an external JavaScript file.');
  }
  
