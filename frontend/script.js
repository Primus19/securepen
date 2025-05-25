// Smooth scrolling
document.querySelectorAll('nav a').forEach(anchor => {
  anchor.addEventListener('click', function(e) {
    e.preventDefault();
    const targetId = this.getAttribute('href');
    const targetSection = document.querySelector(targetId);
    
    // Hide all sections
    document.querySelectorAll('main section').forEach(section => {
      section.classList.remove('active');
    });
    
    // Show target section
    targetSection.classList.add('active');
  });
});

// Get Started button
document.getElementById('get-started').addEventListener('click', function() {
  document.querySelectorAll('main section').forEach(section => {
    section.classList.remove('active');
  });
  document.getElementById('scanner').classList.add('active');
});

// API base URL - updated to fix CORS issues
const API_URL = window.location.hostname === 'localhost' 
  ? 'http://localhost:3000'
  : `https://${window.location.hostname.replace('44425', '3000')}`;

// Authentication functions
function checkAuthStatus() {
  const token = getCookie('token');
  if (token) {
    // Fetch user data
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
      if (data.success && data.user) {
        // User is logged in
        document.getElementById('user-logged-out').style.display = 'none';
        document.getElementById('user-logged-in').style.display = 'flex';
        document.getElementById('username-display').textContent = data.user.username;
        
        // Fetch user activity
        fetchUserActivity();
      } else {
        // Token invalid
        document.getElementById('user-logged-out').style.display = 'flex';
        document.getElementById('user-logged-in').style.display = 'none';
      }
    })
    .catch(error => {
      console.error('Auth check error:', error);
      document.getElementById('user-logged-out').style.display = 'flex';
      document.getElementById('user-logged-in').style.display = 'none';
    });
  } else {
    // No token
    document.getElementById('user-logged-out').style.display = 'flex';
    document.getElementById('user-logged-in').style.display = 'none';
  }
}

function fetchUserActivity() {
  const token = getCookie('token');
  if (!token) return;
  
  fetch(`${API_URL}/api/user/activity`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    if (data.success && data.logs) {
      // Update activity log
      const activityLog = document.getElementById('activity-log');
      activityLog.innerHTML = '';
      
      data.logs.forEach(log => {
        const logEntry = document.createElement('p');
        logEntry.textContent = `${new Date(log.timestamp).toLocaleString()}: ${log.action} - ${log.details}`;
        activityLog.appendChild(logEntry);
      });
      
      // Update stats
      updateStats();
    }
  })
  .catch(error => {
    console.error('Activity fetch error:', error);
  });
}

function updateStats() {
  const token = getCookie('token');
  if (!token) return;
  
  fetch(`${API_URL}/api/user/scans`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    if (data.success && data.scans) {
      // Update dashboard stats
      const testsCount = data.scans.length;
      const vulnsCount = data.scans.filter(scan => scan.findings && scan.findings.includes('vulnerable')).length;
      const successRate = testsCount > 0 ? Math.round((vulnsCount / testsCount) * 100) : 0;
      
      document.getElementById('tests-count').textContent = testsCount;
      document.getElementById('vulns-count').textContent = vulnsCount;
      document.getElementById('success-rate').textContent = `${successRate}%`;
      
      // Update vulnerability chart (simplified)
      const vulnChart = document.getElementById('vuln-chart');
      vulnChart.innerHTML = 'Chart data updated';
    }
  })
  .catch(error => {
    console.error('Stats fetch error:', error);
  });
}

// Auth modal handling
const loginButton = document.getElementById('login-button');
const registerButton = document.getElementById('register-button');
const loginModal = document.getElementById('login-modal');
const registerModal = document.getElementById('register-modal');
const closeBtns = document.querySelectorAll('.close');
const showRegisterLink = document.getElementById('show-register');
const showLoginLink = document.getElementById('show-login');
const logoutButton = document.getElementById('logout-button');

loginButton.addEventListener('click', () => {
  loginModal.style.display = 'block';
});

registerButton.addEventListener('click', () => {
  registerModal.style.display = 'block';
});

closeBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    loginModal.style.display = 'none';
    registerModal.style.display = 'none';
  });
});

showRegisterLink.addEventListener('click', (e) => {
  e.preventDefault();
  loginModal.style.display = 'none';
  registerModal.style.display = 'block';
});

showLoginLink.addEventListener('click', (e) => {
  e.preventDefault();
  registerModal.style.display = 'none';
  loginModal.style.display = 'block';
});

window.addEventListener('click', (e) => {
  if (e.target === loginModal) {
    loginModal.style.display = 'none';
  }
  if (e.target === registerModal) {
    registerModal.style.display = 'none';
  }
});

// Form handling
document.getElementById('login-form').addEventListener('submit', function(e) {
  e.preventDefault();
  const username = this.elements.username.value;
  const password = this.elements.password.value;
  
  fetch(`${API_URL}/api/login`, {
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
      loginModal.style.display = 'none';
      checkAuthStatus();
      showNotification('Login successful!');
    } else {
      showNotification('Login failed: ' + data.message, 'error');
    }
  })
  .catch(error => {
    console.error('Login error:', error);
    showNotification('Login error: ' + error.message, 'error');
  });
});

document.getElementById('register-form').addEventListener('submit', function(e) {
  e.preventDefault();
  const username = this.elements.username.value;
  const email = this.elements.email.value;
  const password = this.elements.password.value;
  const confirmPassword = this.elements['confirm-password'].value;
  
  if (password !== confirmPassword) {
    showNotification('Passwords do not match', 'error');
    return;
  }
  
  fetch(`${API_URL}/api/register`, {
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
      registerModal.style.display = 'none';
      checkAuthStatus();
      showNotification('Registration successful!');
    } else {
      showNotification('Registration failed: ' + data.message, 'error');
    }
  })
  .catch(error => {
    console.error('Registration error:', error);
    showNotification('Registration error: ' + error.message, 'error');
  });
});

logoutButton.addEventListener('click', function() {
  fetch(`${API_URL}/api/logout`, {
    method: 'POST',
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    checkAuthStatus();
    showNotification('Logout successful!');
  })
  .catch(error => {
    console.error('Logout error:', error);
  });
});

// SQL Injection form
document.getElementById('sql-form').addEventListener('submit', function(e) {
  e.preventDefault();
  const username = this.elements[0].value;
  const password = this.elements[1].value;
  
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
    const resultsDiv = document.getElementById('sql-results');
    resultsDiv.innerHTML = '';
    
    const messageEl = document.createElement('p');
    messageEl.textContent = data.message;
    resultsDiv.appendChild(messageEl);
    
    if (data.success) {
      resultsDiv.classList.add('success');
      
      if (data.instructions) {
        const instructionsEl = document.createElement('div');
        instructionsEl.className = 'result-instructions';
        instructionsEl.innerHTML = `<h4>What happened?</h4><p>${data.description}</p><h4>Instructions:</h4><p>${data.instructions}</p>`;
        resultsDiv.appendChild(instructionsEl);
      }
    } else {
      resultsDiv.classList.remove('success');
    }
  })
  .catch(error => {
    console.error('SQL injection test error:', error);
    document.getElementById('sql-results').textContent = 'Error: ' + error.message;
  });
});

// XSS form
document.getElementById('xss-form').addEventListener('submit', function(e) {
  e.preventDefault();
  const comment = this.elements[0].value;
  
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
    const resultsDiv = document.getElementById('xss-results');
    resultsDiv.innerHTML = '';
    
    const messageEl = document.createElement('p');
    messageEl.textContent = data.message;
    resultsDiv.appendChild(messageEl);
    
    if (data.success) {
      resultsDiv.classList.add('success');
      
      // Demonstrate XSS vulnerability by inserting raw HTML
      const outputDiv = document.getElementById('xss-output');
      outputDiv.innerHTML = data.rawHtml;
      
      if (data.instructions) {
        const instructionsEl = document.createElement('div');
        instructionsEl.className = 'result-instructions';
        instructionsEl.innerHTML = `<h4>What happened?</h4><p>${data.description}</p><h4>Instructions:</h4><p>${data.instructions}</p>`;
        resultsDiv.appendChild(instructionsEl);
      }
    } else {
      resultsDiv.classList.remove('success');
      
      if (data.instructions) {
        const instructionsEl = document.createElement('div');
        instructionsEl.className = 'result-instructions';
        instructionsEl.innerHTML = `<h4>Instructions:</h4><p>${data.instructions}</p>`;
        resultsDiv.appendChild(instructionsEl);
      }
    }
  })
  .catch(error => {
    console.error('XSS test error:', error);
    document.getElementById('xss-results').textContent = 'Error: ' + error.message;
  });
});

// Brute Force form
document.getElementById('brute-form').addEventListener('submit', function(e) {
  e.preventDefault();
  const username = this.elements[0].value;
  const wordlistText = this.elements[1].value;
  const wordlist = wordlistText.split('\n').filter(word => word.trim() !== '');
  
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
    const resultsDiv = document.getElementById('brute-results');
    resultsDiv.innerHTML = '';
    
    const messageEl = document.createElement('p');
    messageEl.textContent = data.message;
    resultsDiv.appendChild(messageEl);
    
    if (data.success) {
      resultsDiv.classList.add('success');
      
      if (data.instructions) {
        const instructionsEl = document.createElement('div');
        instructionsEl.className = 'result-instructions';
        instructionsEl.innerHTML = `<h4>What happened?</h4><p>${data.description}</p><h4>Instructions:</h4><p>${data.instructions}</p>`;
        resultsDiv.appendChild(instructionsEl);
      }
    } else {
      resultsDiv.classList.remove('success');
      
      if (data.instructions) {
        const instructionsEl = document.createElement('div');
        instructionsEl.className = 'result-instructions';
        instructionsEl.innerHTML = `<h4>Instructions:</h4><p>${data.instructions}</p>`;
        resultsDiv.appendChild(instructionsEl);
      }
    }
  })
  .catch(error => {
    console.error('Brute force test error:', error);
    document.getElementById('brute-results').textContent = 'Error: ' + error.message;
  });
});

// Path Traversal form
document.getElementById('path-form').addEventListener('submit', function(e) {
  e.preventDefault();
  const filename = this.elements[0].value;
  
  fetch(`${API_URL}/path`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ filename }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    const resultsDiv = document.getElementById('path-results');
    resultsDiv.innerHTML = '';
    
    const messageEl = document.createElement('p');
    messageEl.textContent = data.message;
    resultsDiv.appendChild(messageEl);
    
    if (data.success) {
      resultsDiv.classList.add('success');
      
      if (data.fileContent) {
        const contentEl = document.createElement('pre');
        contentEl.textContent = data.fileContent;
        resultsDiv.appendChild(contentEl);
      }
      
      if (data.instructions) {
        const instructionsEl = document.createElement('div');
        instructionsEl.className = 'result-instructions';
        instructionsEl.innerHTML = `<h4>What happened?</h4><p>${data.description}</p><h4>Instructions:</h4><p>${data.instructions}</p>`;
        resultsDiv.appendChild(instructionsEl);
      }
    } else {
      resultsDiv.classList.remove('success');
      
      if (data.instructions) {
        const instructionsEl = document.createElement('div');
        instructionsEl.className = 'result-instructions';
        instructionsEl.innerHTML = `<h4>Instructions:</h4><p>${data.instructions}</p>`;
        resultsDiv.appendChild(instructionsEl);
      }
    }
  })
  .catch(error => {
    console.error('Path traversal test error:', error);
    document.getElementById('path-results').textContent = 'Error: ' + error.message;
  });
});

// Command Injection form
document.getElementById('command-form').addEventListener('submit', function(e) {
  e.preventDefault();
  const host = this.elements[0].value;
  
  fetch(`${API_URL}/command`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ host }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    const resultsDiv = document.getElementById('command-results');
    resultsDiv.innerHTML = '';
    
    const messageEl = document.createElement('p');
    messageEl.textContent = data.message;
    resultsDiv.appendChild(messageEl);
    
    if (data.success) {
      resultsDiv.classList.add('success');
      
      if (data.output) {
        const outputEl = document.createElement('pre');
        outputEl.textContent = data.output;
        resultsDiv.appendChild(outputEl);
      }
      
      if (data.instructions) {
        const instructionsEl = document.createElement('div');
        instructionsEl.className = 'result-instructions';
        instructionsEl.innerHTML = `<h4>What happened?</h4><p>${data.description}</p><h4>Instructions:</h4><p>${data.instructions}</p>`;
        resultsDiv.appendChild(instructionsEl);
      }
    } else {
      resultsDiv.classList.remove('success');
      
      if (data.instructions) {
        const instructionsEl = document.createElement('div');
        instructionsEl.className = 'result-instructions';
        instructionsEl.innerHTML = `<h4>Instructions:</h4><p>${data.instructions}</p>`;
        resultsDiv.appendChild(instructionsEl);
      }
    }
  })
  .catch(error => {
    console.error('Command injection test error:', error);
    document.getElementById('command-results').textContent = 'Error: ' + error.message;
  });
});

// Scanner form
document.getElementById('scanner-form').addEventListener('submit', function(e) {
  e.preventDefault();
  const target = this.elements[0].value;
  const vulnerabilities = [];
  
  this.querySelectorAll('input[type="checkbox"]:checked').forEach(checkbox => {
    vulnerabilities.push(checkbox.value);
  });
  
  fetch(`${API_URL}/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ target, vulnerabilities }),
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    const resultsDiv = document.getElementById('scan-results');
    resultsDiv.innerHTML = '';
    
    const titleEl = document.createElement('h4');
    titleEl.textContent = 'Scan Results for ' + target;
    resultsDiv.appendChild(titleEl);
    
    if (data.results && data.results.length > 0) {
      const resultsList = document.createElement('ul');
      resultsList.className = 'scan-results-list';
      
      data.results.forEach(result => {
        const resultItem = document.createElement('li');
        resultItem.className = `severity-${result.severity.toLowerCase()}`;
        resultItem.innerHTML = `
          <h5>${result.type}</h5>
          <p><strong>Severity:</strong> ${result.severity}</p>
          <p>${result.description}</p>
          <p><strong>Recommendation:</strong> ${result.recommendation}</p>
        `;
        resultsList.appendChild(resultItem);
      });
      
      resultsDiv.appendChild(resultsList);
    } else {
      const noResultsEl = document.createElement('p');
      noResultsEl.textContent = 'No vulnerabilities found or scan failed.';
      resultsDiv.appendChild(noResultsEl);
    }
  })
  .catch(error => {
    console.error('Scanner error:', error);
    document.getElementById('scan-results').textContent = 'Error: ' + error.message;
  });
});

// Info icon toggle for instructions
document.querySelectorAll('.info-icon').forEach(icon => {
  icon.addEventListener('click', function() {
    const panel = this.nextElementSibling;
    panel.classList.toggle('show');
  });
});

// Helper functions
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}

function showNotification(message, type = 'success') {
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.textContent = message;
  
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.classList.add('show');
  }, 10);
  
  setTimeout(() => {
    notification.classList.remove('show');
    setTimeout(() => {
      document.body.removeChild(notification);
    }, 300);
  }, 3000);
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
  checkAuthStatus();
});
