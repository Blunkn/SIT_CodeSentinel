// Import parse from acorn (Named import)
import { parse } from 'acorn';

// A function to parse JavaScript code using acorn
export function parseJSCode(code) {
    try {
        const parsed = parse(code, { ecmaVersion: 2020 }); // Using the parse function
        console.log(parsed);
    } catch (error) {
        console.error('Error parsing code:', error);
    }
}