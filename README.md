# CodeSentinel
---
Project for Singapore Institute of Technology's ICT2214 Web Security module.

## Version 1.2
---
CodeSentinel is a Chrome extension that scrapes a GitHub repository web page for potential malicious code.
It warns developers and users alike of such code before they clone/fetch/pull from the repo for their own uses.

## Features
---
- Scans a repository's source code while on its web page.
- Lets you know if any suspicious code is found.
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
Fleshing this out later

## How to Use
---
Fleshing this out later too

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
- crazycodf, tjx34 - Ideation & concept refining

## Version Control
---
v1.2 - main code dump
- tweaked .json to have perms for github URLs
- gave .js scanning functionality
- tweaked .html to accommodate scripting functions

v1.1 - general improvements
- created base chrome extension
- improved UI
- fixed .js invoke issue

v1.0 - Initial commit
