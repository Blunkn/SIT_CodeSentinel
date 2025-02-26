# CodeSentinel
## Version 1.3
---
Group project for Singapore Institute of Technology's ICT2214 Web Security module.

CodeSentinel is a Chrome extension that scrapes a GitHub repository web page for potential malicious code.
It warns developers and users alike of such code before they clone/fetch/pull from the repo for their own uses.

! DISCLAIMER

This is a proof-of-concept extension because our lecturers told us to create a "novel" web security solution.

This extension is imperfect and may not detect very unique malicious code signatures.

We are but poor university students and bear no responsibility for any malicious code that slips through during scans.

Audit code manually yourself or use a better, production-quality code scanner.

## Features
---
- Scans a repository's source code while on its web page.
- Performs static analysis and lets you know if any suspicious code is found.
- Code signatures it detects:
    - Command injection
    - Data exfil
    - Eval code
    - Obfuscated code
    - Cryptomining
    - Environment variable access
    - File ops

## Dependencies
---
- Google Chrome
- Node.js v22.13.1

## How to Use
---
1. Download NodeJS (https://nodejs.org/en/download). Downloading the Windows Installer (.msi) is easier if you don't have Node installed
2. Add NodeJS to your environment variables (Windows)
3. Run "npx webpack --config webpack.config.js" on SIT_CodeSentinel (Project Folder) everytime you change the code and want to test it

## Issues
---
- Repo is currently untested; add issues here if you encounter any during runtime

## Roadmap
---
- N/A

## Credits
---
- trumenl - Initial code and templates
- Norman_C - Documentation research
- tjx34 - node.js integration
- crazycodf - Ideation & concept refining

## Version Control
---
v1.3 - node.js integration
- imported static analysis tools from node.js libraries
- libraries parse codes and generate abstract syntax tree

v1.2 - main code dump
- tweaked .json to have perms for github URLs
- gave .js scanning functionality
- tweaked .html to accommodate scripting functions

v1.1 - general improvements
- created base chrome extension
- improved UI
- fixed .js invoke issue

v1.0 - Initial commit
