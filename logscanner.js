document.getElementById("scanBtn").addEventListener("click", async function() {
  // Show the spinner while scanning
  const button = this;
  const spinner = button.querySelector(".spinner");
  button.disabled = true;
  spinner.style.display = "inline-block";
  document.getElementById("results").innerHTML = ""; // Clear previous results
  
  // Get the current GitHub URL
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const url = new URL(tabs[0].url);
      const pathParts = url.pathname.split('/');
  
      // Ensure it's a valid GitHub repository page
      if (pathParts.length < 3) {
          alert("Please open a valid GitHub repository page.");
          button.disabled = false;
          spinner.style.display = "none";
          return;
      }
  
      const user = pathParts[1];
      const repo = pathParts[2];
  
      // Call the scan function to scan the repo
      await scanGitHubRepo(user, repo);
  
      // Hide the spinner and re-enable the button
      button.disabled = false;
      spinner.style.display = "none";
  });
});

// Function to fetch file content from GitHub
async function getFileContentFromGitHub(user, repo, filePath) {
  const rawUrl = `https://raw.githubusercontent.com/${user}/${repo}/main/${filePath}`;
  
  try {
      const response = await fetch(rawUrl);
      if (response.ok) {
          return await response.text();
      } else {
          console.error(`[ERROR] Failed to fetch ${filePath}: ${response.status}`);
          return null;
      }
  } catch (error) {
      console.error(`[ERROR] Error fetching file ${filePath}: ${error.message}`);
      return null;
  }
}

// Function to get all files from the GitHub repository
async function getAllFilesInRepo(user, repo) {
  const apiUrl = `https://api.github.com/repos/${user}/${repo}/contents`;
  
  try {
      const response = await fetch(apiUrl);
      if (response.ok) {
          const data = await response.json();
          return data.filter(item => item.type === 'file').map(item => item.path);
      } else {
          console.error(`[ERROR] Failed to fetch file list from repo: ${response.status}`);
          return [];
      }
  } catch (error) {
      console.error(`[ERROR] Error fetching repo file list: ${error.message}`);
      return [];
  }
}

// Function to load vulnerability patterns from patterns.json
async function loadVulnerabilityPatterns() {
  try {
      const response = await fetch("patterns.json");
      if (!response.ok) throw new Error(`Failed to load patterns.json: ${response.status}`);
      return await response.json();
  } catch (error) {
      console.error(`[ERROR] ${error.message}`);
      return [];
  }
}

// Function to scan for vulnerabilities
async function scanFile(content, vulnerabilityPatterns) {
  const vulnerabilities = [];
  
  vulnerabilityPatterns.forEach(({ pattern, description, severity }) => {
      const regex = new RegExp(pattern, "g");
      if (regex.test(content)) {
          vulnerabilities.push({ description, severity, pattern });
      }
  });
  
  return vulnerabilities.length > 0 ? vulnerabilities : null;
}

// Function to scan the entire GitHub repository
async function scanGitHubRepo(user, repo) {
  const files = await getAllFilesInRepo(user, repo);
  const vulnerabilityPatterns = await loadVulnerabilityPatterns();
  let vulnerableFiles = {};

  for (const filePath of files) {
      const content = await getFileContentFromGitHub(user, repo, filePath);
      if (content) {
          const result = await scanFile(content, vulnerabilityPatterns);
          if (result) {
              vulnerableFiles[filePath] = result;
          }
      }
  }
  
  // Display results
  const resultsDiv = document.getElementById("results");
  if (Object.keys(vulnerableFiles).length > 0) {
      resultsDiv.innerHTML = "<h3>Vulnerabilities Detected:</h3>";
      Object.entries(vulnerableFiles).forEach(([file, issues]) => {
          const fileElement = document.createElement("div");
          fileElement.classList.add("finding");
          fileElement.innerHTML = `<strong>${file}</strong>`;
          issues.forEach(({ description, severity, pattern }) => {
              fileElement.innerHTML += `
                  <div class="alert alert-danger">
                      <strong>${description}</strong> (Severity: ${severity})
                      <pre class="code-snippet">${pattern}</pre>
                  </div>
              `;
          });
          resultsDiv.appendChild(fileElement);
      });
  } else {
      resultsDiv.innerHTML += `<div class="alert alert-success"> No vulnerabilities detected.</div>`;
  }
}
