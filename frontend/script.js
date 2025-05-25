// Smooth scrolling
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    e.preventDefault();
    document.querySelector(this.getAttribute('href')).scrollIntoView({
      behavior: 'smooth'
    });
  });
  document.getElementById('scanner').classList.add('active');
});

// API base URL - updated to fix CORS issues
const API_URL = window.location.origin;

// Authentication functions
function checkAuthStatus() {
  const token = getCookie('token');
  if (token) {
    fetch(`${API_URL}/api/user`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        // User is logged in
        document.getElementById('login-btn').style.display = 'none';
        document.getElementById('register-btn').style.display = 'none';
        
        // Create logout button if it doesn't exist
        if (!document.getElementById('logout-btn')) {
          const logoutBtn = document.createElement('button');
          logoutBtn.id = 'logout-btn';
          logoutBtn.className = 'btn btn-primary';
          logoutBtn.textContent = 'Logout';
          logoutBtn.onclick = logout;
          document.querySelector('.nav-buttons').appendChild(logoutBtn);
        }
        
        // Create user info display
        const userInfo = document.createElement('div');
        userInfo.id = 'user-info';
        userInfo.className = 'user-info';
        userInfo.innerHTML = `<span>Welcome, ${data.user.username}</span>`;
        document.querySelector('.nav-buttons').prepend(userInfo);
        
        // Load user activity and update dashboard
        loadUserActivity();
        updateDashboard();
      }
    })
    .catch(error => {
      console.error('Auth check error:', error);
      // Clear invalid token
      document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    });
  }
}

function login(username, password) {
  return fetch(`${API_URL}/api/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, password }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      showNotification('Login successful!', 'success');
      closeAllModals();
      checkAuthStatus();
      return true;
    } else {
      showNotification(data.message || 'Login failed', 'error');
      return false;
    }
  })
  .catch(error => {
    console.error('Login error:', error);
    showNotification('Login failed. Please try again.', 'error');
    return false;
  });
}

function register(username, email, password) {
  return fetch(`${API_URL}/api/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, email, password }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      showNotification('Registration successful!', 'success');
      closeAllModals();
      checkAuthStatus();
      return true;
    } else {
      showNotification(data.message || 'Registration failed', 'error');
      return false;
    }
  })
  .catch(error => {
    console.error('Registration error:', error);
    showNotification('Registration failed. Please try again.', 'error');
    return false;
  });
}

function logout() {
  fetch(`${API_URL}/api/logout`, {
    method: 'POST',
    credentials: 'include'
  })
  .then(() => {
    document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    showNotification('Logged out successfully', 'success');
    
    // Remove logout button and user info
    const logoutBtn = document.getElementById('logout-btn');
    const userInfo = document.getElementById('user-info');
    if (logoutBtn) logoutBtn.remove();
    if (userInfo) userInfo.remove();
    
    // Show login and register buttons
    document.getElementById('login-btn').style.display = 'inline-block';
    document.getElementById('register-btn').style.display = 'inline-block';
    
    // Reset dashboard
    resetDashboard();
  })
  .catch(error => {
    console.error('Logout error:', error);
    showNotification('Logout failed. Please try again.', 'error');
  });
}

// Form handling
function handleLoginForm(event) {
  event.preventDefault();
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  
  if (!username || !password) {
    showNotification('Username and password are required', 'error');
    return;
  }
  
  login(username, password);
}

function handleRegisterForm(event) {
  event.preventDefault();
  const username = document.getElementById('register-username').value;
  const email = document.getElementById('register-email').value;
  const password = document.getElementById('register-password').value;
  const confirmPassword = document.getElementById('register-confirm-password').value;
  
  if (!username || !email || !password || !confirmPassword) {
    showNotification('All fields are required', 'error');
    return;
  }
  
  if (password !== confirmPassword) {
    showNotification('Passwords do not match', 'error');
    return;
  }
  
  register(username, email, password);
}

// Vulnerability testing functions
function testSQLInjection(event) {
  event.preventDefault();
  const username = document.getElementById('sqli-username').value;
  const password = document.getElementById('sqli-password').value;
  
  if (!username || !password) {
    showNotification('Username and password are required', 'error');
    return;
  }
  
  fetch(`${API_URL}/sql`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, password }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    const resultElement = document.getElementById('sqli-result');
    resultElement.innerHTML = '';
    
    // Create result card
    const resultCard = document.createElement('div');
    resultCard.className = 'result-card';
    
    // Add header based on success
    const header = document.createElement('div');
    header.className = `result-header ${data.success ? 'success' : 'failure'}`;
    header.textContent = data.success ? 'Vulnerability Exploited!' : 'Exploitation Failed';
    resultCard.appendChild(header);
    
    // Add message
    const message = document.createElement('div');
    message.className = 'result-message';
    message.textContent = data.message;
    resultCard.appendChild(message);
    
    // Add details if successful
    if (data.success) {
      // Add vulnerability info
      const vulnInfo = document.createElement('div');
      vulnInfo.className = 'vulnerability-info';
      vulnInfo.innerHTML = `
        <h3>${data.vulnerability}</h3>
        <div class="severity ${data.severity.toLowerCase()}">Severity: ${data.severity}</div>
        <p>${data.description}</p>
        <div class="instructions">
          <h4>Instructions:</h4>
          <p>${data.instructions}</p>
        </div>
      `;
      resultCard.appendChild(vulnInfo);
      
      // Update dashboard
      updateVulnerabilityStats('SQL Injection', data.severity);
    }
    
    resultElement.appendChild(resultCard);
    
    // Scroll to result
    resultElement.scrollIntoView({ behavior: 'smooth' });
  })
  .catch(error => {
    console.error('SQL Injection test error:', error);
    showNotification('Test failed. Please try again.', 'error');
  });
}

function testXSS(event) {
  event.preventDefault();
  const comment = document.getElementById('xss-input').value;
  
  if (!comment) {
    showNotification('Comment is required', 'error');
    return;
  }
  
  fetch(`${API_URL}/xss`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ comment }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    const resultElement = document.getElementById('xss-result');
    resultElement.innerHTML = '';
    
    // Create result card
    const resultCard = document.createElement('div');
    resultCard.className = 'result-card';
    
    // Add header based on success
    const header = document.createElement('div');
    header.className = `result-header ${data.success ? 'success' : 'failure'}`;
    header.textContent = data.success ? 'Vulnerability Exploited!' : 'Exploitation Failed';
    resultCard.appendChild(header);
    
    // Add message
    const message = document.createElement('div');
    message.className = 'result-message';
    message.textContent = data.message;
    resultCard.appendChild(message);
    
    // Add details if successful
    if (data.success) {
      // Add vulnerability info
      const vulnInfo = document.createElement('div');
      vulnInfo.className = 'vulnerability-info';
      vulnInfo.innerHTML = `
        <h3>${data.vulnerability}</h3>
        <div class="severity ${data.severity.toLowerCase()}">Severity: ${data.severity}</div>
        <p>${data.description}</p>
        <div class="instructions">
          <h4>Instructions:</h4>
          <p>${data.instructions}</p>
        </div>
      `;
      resultCard.appendChild(vulnInfo);
      
      // Update dashboard
      updateVulnerabilityStats('XSS', data.severity);
    } else {
      // Add instructions for failed attempt
      const instructions = document.createElement('div');
      instructions.className = 'instructions';
      instructions.innerHTML = `
        <h4>Try Again:</h4>
        <p>${data.instructions}</p>
      `;
      resultCard.appendChild(instructions);
    }
    
    resultElement.appendChild(resultCard);
    
    // Scroll to result
    resultElement.scrollIntoView({ behavior: 'smooth' });
  })
  .catch(error => {
    console.error('XSS test error:', error);
    showNotification('Test failed. Please try again.', 'error');
  });
}

function testBruteForce(event) {
  event.preventDefault();
  const username = document.getElementById('brute-username').value;
  const wordlistText = document.getElementById('brute-wordlist').value;
  
  if (!username || !wordlistText) {
    showNotification('Username and wordlist are required', 'error');
    return;
  }
  
  // Parse wordlist
  const wordlist = wordlistText.split('\n').filter(word => word.trim() !== '');
  
  if (wordlist.length === 0) {
    showNotification('Wordlist cannot be empty', 'error');
    return;
  }
  
  // Show loading indicator
  const resultElement = document.getElementById('brute-result');
  resultElement.innerHTML = '<div class="loading">Testing passwords... <div class="spinner"></div></div>';
  
  fetch(`${API_URL}/brute`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, wordlist }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    resultElement.innerHTML = '';
    
    // Create result card
    const resultCard = document.createElement('div');
    resultCard.className = 'result-card';
    
    // Add header based on success
    const header = document.createElement('div');
    header.className = `result-header ${data.success ? 'success' : 'failure'}`;
    header.textContent = data.success ? 'Vulnerability Exploited!' : 'Exploitation Failed';
    resultCard.appendChild(header);
    
    // Add message
    const message = document.createElement('div');
    message.className = 'result-message';
    message.textContent = data.message;
    resultCard.appendChild(message);
    
    // Add details if successful
    if (data.success) {
      // Add vulnerability info
      const vulnInfo = document.createElement('div');
      vulnInfo.className = 'vulnerability-info';
      vulnInfo.innerHTML = `
        <h3>${data.vulnerability}</h3>
        <div class="severity ${data.severity.toLowerCase()}">Severity: ${data.severity}</div>
        <p>${data.description}</p>
        <div class="instructions">
          <h4>Instructions:</h4>
          <p>${data.instructions}</p>
        </div>
      `;
      resultCard.appendChild(vulnInfo);
      
      // Update dashboard
      updateVulnerabilityStats('Brute Force', data.severity);
    } else {
      // Add instructions for failed attempt
      const instructions = document.createElement('div');
      instructions.className = 'instructions';
      instructions.innerHTML = `
        <h4>Try Again:</h4>
        <p>${data.instructions || 'Try a different wordlist or username.'}</p>
      `;
      resultCard.appendChild(instructions);
    }
    
    resultElement.appendChild(resultCard);
    
    // Scroll to result
    resultElement.scrollIntoView({ behavior: 'smooth' });
  })
  .catch(error => {
    console.error('Brute Force test error:', error);
    resultElement.innerHTML = '';
    showNotification('Test failed. Please try again.', 'error');
  });
}

function testPathTraversal(event) {
  event.preventDefault();
  const filepath = document.getElementById('path-filepath').value;
  
  if (!filepath) {
    showNotification('Filepath is required', 'error');
    return;
  }
  
  fetch(`${API_URL}/path`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ filepath }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    const resultElement = document.getElementById('path-result');
    resultElement.innerHTML = '';
    
    // Create result card
    const resultCard = document.createElement('div');
    resultCard.className = 'result-card';
    
    // Add header based on success
    const header = document.createElement('div');
    header.className = `result-header ${data.success ? 'success' : 'failure'}`;
    header.textContent = data.success ? 'Vulnerability Exploited!' : 'Exploitation Failed';
    resultCard.appendChild(header);
    
    // Add message
    const message = document.createElement('div');
    message.className = 'result-message';
    message.textContent = data.message;
    resultCard.appendChild(message);
    
    // Add file content if available
    if (data.fileContent) {
      const fileContent = document.createElement('div');
      fileContent.className = 'file-content';
      fileContent.innerHTML = `
        <h4>File Content:</h4>
        <pre>${data.fileContent}</pre>
      `;
      resultCard.appendChild(fileContent);
    }
    
    // Add details if successful
    if (data.success) {
      // Add vulnerability info
      const vulnInfo = document.createElement('div');
      vulnInfo.className = 'vulnerability-info';
      vulnInfo.innerHTML = `
        <h3>${data.vulnerability}</h3>
        <div class="severity ${data.severity.toLowerCase()}">Severity: ${data.severity}</div>
        <p>${data.description}</p>
        <div class="instructions">
          <h4>Instructions:</h4>
          <p>${data.instructions}</p>
        </div>
      `;
      resultCard.appendChild(vulnInfo);
      
      // Update dashboard
      updateVulnerabilityStats('Path Traversal', data.severity);
    } else {
      // Add instructions for failed attempt
      const instructions = document.createElement('div');
      instructions.className = 'instructions';
      instructions.innerHTML = `
        <h4>Try Again:</h4>
        <p>${data.instructions || 'Try a different filepath pattern.'}</p>
      `;
      resultCard.appendChild(instructions);
    }
    
    resultElement.appendChild(resultCard);
    
    // Scroll to result
    resultElement.scrollIntoView({ behavior: 'smooth' });
  })
  .catch(error => {
    console.error('Path Traversal test error:', error);
    showNotification('Test failed. Please try again.', 'error');
  });
}

function testCommandInjection(event) {
  event.preventDefault();
  const command = document.getElementById('command-input').value;
  
  if (!command) {
    showNotification('Command is required', 'error');
    return;
  }
  
  fetch(`${API_URL}/command`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ command }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    const resultElement = document.getElementById('command-result');
    resultElement.innerHTML = '';
    
    // Create result card
    const resultCard = document.createElement('div');
    resultCard.className = 'result-card';
    
    // Add header based on success
    const header = document.createElement('div');
    header.className = `result-header ${data.success ? 'success' : 'failure'}`;
    header.textContent = data.success ? 'Vulnerability Exploited!' : 'Exploitation Failed';
    resultCard.appendChild(header);
    
    // Add message
    const message = document.createElement('div');
    message.className = 'result-message';
    message.textContent = data.message;
    resultCard.appendChild(message);
    
    // Add command output if available
    if (data.output) {
      const output = document.createElement('div');
      output.className = 'command-output';
      output.innerHTML = `
        <h4>Command Output:</h4>
        <pre>${data.output}</pre>
      `;
      resultCard.appendChild(output);
    }
    
    // Add details if successful
    if (data.success) {
      // Add vulnerability info
      const vulnInfo = document.createElement('div');
      vulnInfo.className = 'vulnerability-info';
      vulnInfo.innerHTML = `
        <h3>${data.vulnerability}</h3>
        <div class="severity ${data.severity.toLowerCase()}">Severity: ${data.severity}</div>
        <p>${data.description}</p>
        <div class="instructions">
          <h4>Instructions:</h4>
          <p>${data.instructions}</p>
        </div>
      `;
      resultCard.appendChild(vulnInfo);
      
      // Update dashboard
      updateVulnerabilityStats('Command Injection', data.severity);
    } else {
      // Add instructions for failed attempt
      const instructions = document.createElement('div');
      instructions.className = 'instructions';
      instructions.innerHTML = `
        <h4>Try Again:</h4>
        <p>${data.instructions || 'Try a different command pattern.'}</p>
      `;
      resultCard.appendChild(instructions);
    }
    
    resultElement.appendChild(resultCard);
    
    // Scroll to result
    resultElement.scrollIntoView({ behavior: 'smooth' });
  })
  .catch(error => {
    console.error('Command Injection test error:', error);
    showNotification('Test failed. Please try again.', 'error');
  });
}

// Scanner functionality
function runVulnerabilityScan(event) {
  event.preventDefault();
  const target = document.getElementById('scan-target').value;
  
  if (!target) {
    showNotification('Target URL is required', 'error');
    return;
  }
  
  // Show loading indicator
  const resultElement = document.getElementById('scan-result');
  resultElement.innerHTML = '<div class="loading">Scanning target... <div class="spinner"></div></div>';
  
  fetch(`${API_URL}/api/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${getCookie('token')}`
    },
    body: JSON.stringify({ target }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    resultElement.innerHTML = '';
    
    if (data.success) {
      // Create scan report
      const scanReport = document.createElement('div');
      scanReport.className = 'scan-report';
      
      // Add header
      const header = document.createElement('div');
      header.className = 'scan-header';
      header.innerHTML = `
        <h3>Scan Results for ${target}</h3>
        <div class="scan-meta">
          <span>Scan ID: ${data.scan.id}</span>
          <span>Timestamp: ${new Date(data.scan.timestamp).toLocaleString()}</span>
        </div>
      `;
      scanReport.appendChild(header);
      
      // Add findings
      const findings = document.createElement('div');
      findings.className = 'scan-findings';
      
      if (data.scan.findings && data.scan.findings.length > 0) {
        const findingsList = document.createElement('ul');
        findingsList.className = 'findings-list';
        
        data.scan.findings.forEach(finding => {
          const findingItem = document.createElement('li');
          findingItem.className = `finding-item ${finding.severity.toLowerCase()}`;
          findingItem.innerHTML = `
            <div class="finding-header">
              <span class="finding-type">${finding.type}</span>
              <span class="finding-severity ${finding.severity.toLowerCase()}">Severity: ${finding.severity}</span>
            </div>
            <div class="finding-details">
              <p>${finding.description}</p>
              <div class="finding-location">Location: ${finding.location}</div>
            </div>
          `;
          findingsList.appendChild(findingItem);
          
          // Update dashboard
          updateVulnerabilityStats(finding.type, finding.severity);
        });
        
        findings.appendChild(findingsList);
      } else {
        findings.innerHTML = '<p class="no-findings">No vulnerabilities found.</p>';
      }
      
      scanReport.appendChild(findings);
      
      // Add recommendations
      if (data.scan.recommendations && data.scan.recommendations.length > 0) {
        const recommendations = document.createElement('div');
        recommendations.className = 'scan-recommendations';
        recommendations.innerHTML = '<h4>Recommendations:</h4>';
        
        const recommendationsList = document.createElement('ul');
        data.scan.recommendations.forEach(rec => {
          const recItem = document.createElement('li');
          recItem.textContent = rec;
          recommendationsList.appendChild(recItem);
        });
        
        recommendations.appendChild(recommendationsList);
        scanReport.appendChild(recommendations);
      }
      
      resultElement.appendChild(scanReport);
    } else {
      // Show error
      const errorMessage = document.createElement('div');
      errorMessage.className = 'error-message';
      errorMessage.textContent = data.message || 'Scan failed. Please try again.';
      resultElement.appendChild(errorMessage);
    }
    
    // Scroll to result
    resultElement.scrollIntoView({ behavior: 'smooth' });
  })
  .catch(error => {
    console.error('Scan error:', error);
    resultElement.innerHTML = '';
    showNotification('Scan failed. Please try again.', 'error');
  });
}

// Dashboard functions
function updateDashboard() {
  fetch(`${API_URL}/api/user/scans`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${getCookie('token')}`,
      'Content-Type': 'application/json'
    },
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      // Update dashboard stats
      let testsRun = 0;
      let vulnerabilitiesExploited = 0;
      const vulnerabilityTypes = {};
      
      data.scans.forEach(scan => {
        testsRun++;
        
        if (scan.findings && typeof scan.findings === 'string') {
          try {
            const findings = JSON.parse(scan.findings);
            vulnerabilitiesExploited += findings.length;
            
            findings.forEach(finding => {
              if (!vulnerabilityTypes[finding.type]) {
                vulnerabilityTypes[finding.type] = 0;
              }
              vulnerabilityTypes[finding.type]++;
            });
          } catch (e) {
            console.error('Error parsing findings:', e);
          }
        }
      });
      
      // Update stats display
      document.getElementById('tests-run').textContent = testsRun;
      document.getElementById('vulnerabilities-exploited').textContent = vulnerabilitiesExploited;
      
      // Calculate success rate
      const successRate = testsRun > 0 ? Math.round((vulnerabilitiesExploited / testsRun) * 100) : 0;
      document.getElementById('success-rate').textContent = `${successRate}%`;
      
      // Update vulnerability distribution
      updateVulnerabilityDistribution(vulnerabilityTypes);
    }
  })
  .catch(error => {
    console.error('Dashboard update error:', error);
  });
}

function updateVulnerabilityStats(type, severity) {
  // Increment tests run
  const testsRunElement = document.getElementById('tests-run');
  let testsRun = parseInt(testsRunElement.textContent) || 0;
  testsRunElement.textContent = testsRun + 1;
  
  // Increment vulnerabilities exploited
  const vulnerabilitiesExploitedElement = document.getElementById('vulnerabilities-exploited');
  let vulnerabilitiesExploited = parseInt(vulnerabilitiesExploitedElement.textContent) || 0;
  vulnerabilitiesExploitedElement.textContent = vulnerabilitiesExploited + 1;
  
  // Update success rate
  const successRateElement = document.getElementById('success-rate');
  const successRate = Math.round(((vulnerabilitiesExploited + 1) / (testsRun + 1)) * 100);
  successRateElement.textContent = `${successRate}%`;
  
  // Update vulnerability distribution
  const distributionElement = document.getElementById('vulnerability-distribution');
  
  // Check if chart exists
  let chart = distributionElement.chart;
  
  if (!chart) {
    // Create new chart
    chart = {
      data: {}
    };
    distributionElement.chart = chart;
  }
  
  // Update chart data
  if (!chart.data[type]) {
    chart.data[type] = 0;
  }
  chart.data[type]++;
  
  // Render chart
  renderVulnerabilityChart(distributionElement, chart.data);
  
  // Update activity log
  updateActivityLog(`${type} vulnerability (${severity}) exploited`);
}

function updateVulnerabilityDistribution(data) {
  const distributionElement = document.getElementById('vulnerability-distribution');
  renderVulnerabilityChart(distributionElement, data);
  distributionElement.chart = { data };
}

function renderVulnerabilityChart(element, data) {
  // Clear element
  element.innerHTML = '';
  
  if (Object.keys(data).length === 0) {
    element.innerHTML = '<p class="no-data">No vulnerability data available</p>';
    return;
  }
  
  // Create chart
  const chart = document.createElement('div');
  chart.className = 'chart';
  
  // Calculate total
  let total = 0;
  Object.values(data).forEach(value => {
    total += value;
  });
  
  // Create bars
  Object.entries(data).forEach(([type, count]) => {
    const percentage = Math.round((count / total) * 100);
    
    const bar = document.createElement('div');
    bar.className = 'chart-bar';
    
    const barFill = document.createElement('div');
    barFill.className = 'chart-bar-fill';
    barFill.style.width = `${percentage}%`;
    barFill.style.backgroundColor = getColorForVulnerabilityType(type);
    
    const barLabel = document.createElement('div');
    barLabel.className = 'chart-bar-label';
    barLabel.textContent = `${type}: ${count} (${percentage}%)`;
    
    bar.appendChild(barFill);
    bar.appendChild(barLabel);
    chart.appendChild(bar);
  });
  
  element.appendChild(chart);
}

function getColorForVulnerabilityType(type) {
  const colors = {
    'SQL Injection': '#ff5722',
    'XSS': '#2196f3',
    'Brute Force': '#9c27b0',
    'Path Traversal': '#4caf50',
    'Command Injection': '#f44336'
  };
  
  return colors[type] || '#607d8b';
}

function updateActivityLog(activity) {
  const activityElement = document.getElementById('recent-activity');
  
  // Create activity item
  const activityItem = document.createElement('div');
  activityItem.className = 'activity-item';
  
  const timestamp = document.createElement('span');
  timestamp.className = 'activity-timestamp';
  timestamp.textContent = new Date().toLocaleTimeString();
  
  const activityText = document.createElement('span');
  activityText.className = 'activity-text';
  activityText.textContent = activity;
  
  activityItem.appendChild(timestamp);
  activityItem.appendChild(activityText);
  
  // Add to activity log
  activityElement.insertBefore(activityItem, activityElement.firstChild);
  
  // Limit to 10 items
  if (activityElement.children.length > 10) {
    activityElement.removeChild(activityElement.lastChild);
  }
}

function loadUserActivity() {
  fetch(`${API_URL}/api/user/activity`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${getCookie('token')}`,
      'Content-Type': 'application/json'
    },
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      const activityElement = document.getElementById('recent-activity');
      activityElement.innerHTML = '';
      
      if (data.logs && data.logs.length > 0) {
        data.logs.forEach(log => {
          const activityItem = document.createElement('div');
          activityItem.className = 'activity-item';
          
          const timestamp = document.createElement('span');
          timestamp.className = 'activity-timestamp';
          timestamp.textContent = new Date(log.timestamp).toLocaleTimeString();
          
          const activityText = document.createElement('span');
          activityText.className = 'activity-text';
          activityText.textContent = `${log.action}: ${log.details}`;
          
          activityItem.appendChild(timestamp);
          activityItem.appendChild(activityText);
          
          activityElement.appendChild(activityItem);
        });
      } else {
        activityElement.innerHTML = '<p class="no-data">No activity data available</p>';
      }
    }
  })
  .catch(error => {
    console.error('Activity load error:', error);
  });
}

function resetDashboard() {
  document.getElementById('tests-run').textContent = '0';
  document.getElementById('vulnerabilities-exploited').textContent = '0';
  document.getElementById('success-rate').textContent = '0%';
  document.getElementById('vulnerability-distribution').innerHTML = '<p class="no-data">No vulnerability data available</p>';
  document.getElementById('recent-activity').innerHTML = '<p>Welcome to SecurePen 2.1</p>';
}

// UI functions
function showModal(modalId) {
  // Close any open modals
  closeAllModals();
  
  // Show modal
  const modal = document.getElementById(modalId);
  modal.style.display = 'block';
  
  // Add event listener to close button
  const closeBtn = modal.querySelector('.close');
  if (closeBtn) {
    closeBtn.onclick = function() {
      modal.style.display = 'none';
    };
  }
  
  // Close when clicking outside
  window.onclick = function(event) {
    if (event.target === modal) {
      modal.style.display = 'none';
    }
  };
}

function closeAllModals() {
  const modals = document.querySelectorAll('.modal');
  modals.forEach(modal => {
    modal.style.display = 'none';
  });
}

function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.textContent = message;
  
  document.body.appendChild(notification);
  
  // Show notification
  setTimeout(() => {
    notification.classList.add('show');
  }, 10);
  
  // Hide and remove notification
  setTimeout(() => {
    notification.classList.remove('show');
    setTimeout(() => {
      notification.remove();
    }, 300);
  }, 3000);
}

function showSection(sectionId) {
  // Hide all sections
  const sections = document.querySelectorAll('.section');
  sections.forEach(section => {
    section.style.display = 'none';
  });
  
  // Show selected section
  const section = document.getElementById(sectionId);
  if (section) {
    section.style.display = 'block';
  }
  
  // Update active nav item
  const navItems = document.querySelectorAll('nav a');
  navItems.forEach(item => {
    item.classList.remove('active');
  });
  
  const activeNavItem = document.querySelector(`nav a[href="#${sectionId}"]`);
  if (activeNavItem) {
    activeNavItem.classList.add('active');
  }
}

// Helper functions
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
  // Check authentication status
  checkAuthStatus();
  
  // Navigation
  document.querySelectorAll('nav a').forEach(link => {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      const sectionId = this.getAttribute('href').substring(1);
      showSection(sectionId);
      
      // Update active nav item
      document.querySelectorAll('nav a').forEach(item => {
        item.classList.remove('active');
      });
      this.classList.add('active');
    });
  });
  
  // Login button
  document.getElementById('login-btn').addEventListener('click', function() {
    showModal('login-modal');
  });
  
  // Register button
  document.getElementById('register-btn').addEventListener('click', function() {
    showModal('register-modal');
  });
  
  // Login form
  document.getElementById('login-form').addEventListener('submit', handleLoginForm);
  
  // Register form
  document.getElementById('register-form').addEventListener('submit', handleRegisterForm);
  
  // Login link in register modal
  document.getElementById('login-link').addEventListener('click', function(e) {
    e.preventDefault();
    showModal('login-modal');
  });
  
  // Register link in login modal
  document.getElementById('register-link').addEventListener('click', function(e) {
    e.preventDefault();
    showModal('register-modal');
  });
  
  // SQL Injection form
  document.getElementById('sqli-form').addEventListener('submit', testSQLInjection);
  
  // XSS form
  document.getElementById('xss-form').addEventListener('submit', testXSS);
  
  // Brute Force form
  document.getElementById('brute-form').addEventListener('submit', testBruteForce);
  
  // Path Traversal form
  document.getElementById('path-form').addEventListener('submit', testPathTraversal);
  
  // Command Injection form
  document.getElementById('command-form').addEventListener('submit', testCommandInjection);
  
  // Scanner form
  document.getElementById('scan-form').addEventListener('submit', runVulnerabilityScan);
  
  // Get Started button
  document.getElementById('get-started-btn').addEventListener('click', function() {
    showSection('scanner');
    
    // Update active nav item
    document.querySelectorAll('nav a').forEach(item => {
      item.classList.remove('active');
    });
    document.querySelector('nav a[href="#scanner"]').classList.add('active');
  });
  
  // Show dashboard by default
  showSection('dashboard');
});

// Add sample data for demonstration
function addSampleData() {
  // Update dashboard stats
  document.getElementById('tests-run').textContent = '5';
  document.getElementById('vulnerabilities-exploited').textContent = '3';
  document.getElementById('success-rate').textContent = '60%';
  
  // Add sample vulnerability distribution
  const sampleData = {
    'SQL Injection': 1,
    'XSS': 1,
    'Brute Force': 1
  };
  
  updateVulnerabilityDistribution(sampleData);
  
  // Add sample activity
  updateActivityLog('SQL Injection vulnerability (High) exploited');
  updateActivityLog('XSS vulnerability (Medium) exploited');
  updateActivityLog('Brute Force vulnerability (Medium) exploited');
  updateActivityLog('Path Traversal test failed');
  updateActivityLog('Command Injection test failed');
}

// Call addSampleData if no user is logged in
if (!getCookie('token')) {
  setTimeout(addSampleData, 1000);
}
