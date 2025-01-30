// script.js

// Import parse from acorn (Named import)
import { parse } from 'acorn';

// A function to parse JavaScript code using acorn
function parseCode(code) {
    try {
        const parsed = parse(code, { ecmaVersion: 2020 }); // Using the parse function
        console.log(parsed);
    } catch (error) {
        console.error('Error parsing code:', error);
    }
}

// Sample JavaScript code to be parsed
const code = `
  const x = 10;
  function hello() {
    console.log('Hello, world!');
  }
`;

// Parse the code
parseCode(code);

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