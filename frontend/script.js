// API base URL configuration
const API_BASE_URL = (() => {
  // Get the current hostname
  const hostname = window.location.hostname;
  const protocol = window.location.protocol;
  
  // Check if running on the load balancer domain
  if (hostname.includes('elb.us-east-1.amazonaws.com')) {
    return `${protocol}//${hostname}/api`;
  }
  
  // If running locally (development)
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname.includes('manusvm.computer')) {
    return 'http://localhost:3000/api'; // Use absolute URL for local development
  }
  
  // In production, use the same origin
  return `${protocol}//${hostname}/api`;
})();

// DOM Elements
const dashboardLink = document.getElementById("dashboard-link");
const scannerLink = document.getElementById("scanner-link");
const sqlLink = document.getElementById("sql-link");
const xssLink = document.getElementById("xss-link");
const bruteLink = document.getElementById("brute-link");
const pathLink = document.getElementById("path-link");
const commandLink = document.getElementById("command-link");
const loginBtn = document.getElementById("login-btn");
const registerBtn = document.getElementById("register-btn");
const logoutBtn = document.getElementById("logout-btn");
const userDisplay = document.getElementById("user-display");
const mainContent = document.getElementById("main-content");
const loginModal = document.getElementById("login-modal");
const registerModal = document.getElementById("register-modal");
const closeLoginBtn = document.getElementById("close-login");
const closeRegisterBtn = document.getElementById("close-register");
const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");
const notificationContainer = document.getElementById("notification-container");

// State management
let currentUser = null;
let currentModule = null;

// Notification system
function showNotification(message, type = 'info', duration = 5000) {
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.innerHTML = `
    <div class="notification-icon">
      ${type === 'success' ? '<i class="fas fa-check-circle"></i>' : 
        type === 'error' ? '<i class="fas fa-exclamation-circle"></i>' : 
        '<i class="fas fa-info-circle"></i>'}
    </div>
    <div class="notification-message">${message}</div>
    <button class="notification-close">&times;</button>
  `;
  
  notificationContainer.appendChild(notification);
  
  // Add event listener to close button
  const closeBtn = notification.querySelector('.notification-close');
  closeBtn.addEventListener('click', () => {
    notification.classList.add('notification-hide');
    setTimeout(() => {
      notificationContainer.removeChild(notification);
    }, 300);
  });
  
  // Auto-remove after duration
  setTimeout(() => {
    if (notification.parentNode === notificationContainer) {
      notification.classList.add('notification-hide');
      setTimeout(() => {
        if (notification.parentNode === notificationContainer) {
          notificationContainer.removeChild(notification);
        }
      }, 300);
    }
  }, duration);
}

// Utility function for API calls
async function fetchAPI(url, method = 'GET', data = null) {
  const options = {
    method,
    headers: {
      'Content-Type': 'application/json'
    }
  };
  
  // Add authorization header if user is logged in
  if (currentUser && currentUser.token) {
    options.headers['Authorization'] = `Bearer ${currentUser.token}`;
  }
  
  // Add body if data is provided
  if (data) {
    options.body = JSON.stringify(data);
  }
  
  try {
    console.log(`\n\n\n           ${method} ${url}`);
    const response = await fetch(url, options);
    
    // Handle non-2xx responses
    if (!response.ok) {
      console.error(`API Error (${response.status}): ${response.statusText}`);
      throw new Error(response.statusText);
    }
    
    // Parse JSON response
    const result = await response.json();
    return result;
  } catch (error) {
    console.error('Fetch API error:', error);
    throw error;
  }
}

// Authentication functions
function checkAuth() {
  const userData = localStorage.getItem('securepen_user');
  if (userData) {
    try {
      currentUser = JSON.parse(userData);
      updateUIForAuthState(true);
    } catch (error) {
      console.error('Error parsing user data:', error);
      localStorage.removeItem('securepen_user');
      updateUIForAuthState(false);
    }
  } else {
    updateUIForAuthState(false);
  }
}

function updateUIForAuthState(isLoggedIn) {
  if (isLoggedIn && currentUser) {
    loginBtn.style.display = 'none';
    registerBtn.style.display = 'none';
    logoutBtn.style.display = 'inline-block';
    userDisplay.textContent = currentUser.username;
    userDisplay.style.display = 'inline-block';
  } else {
    loginBtn.style.display = 'inline-block';
    registerBtn.style.display = 'inline-block';
    logoutBtn.style.display = 'none';
    userDisplay.style.display = 'none';
  }
}

async function handleLogin(event) {
  event.preventDefault();
  
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  
  if (!username || !password) {
    showNotification('Username and password are required', 'error');
    return;
  }
  
  try {
    const result = await fetchAPI(`${API_BASE_URL}/auth/login`, 'POST', { username, password });
    
    // Store user data
    currentUser = {
      id: result.user.id,
      username: result.user.username,
      email: result.user.email,
      token: result.token
    };
    
    localStorage.setItem('securepen_user', JSON.stringify(currentUser));
    
    // Update UI
    updateUIForAuthState(true);
    
    // Close modal
    loginModal.style.display = 'none';
    
    // Show success notification
    showNotification('Login successful', 'success');
    
    // Reset form
    loginForm.reset();
    
    // Reload dashboard
    navigateTo('#dashboard');
  } catch (error) {
    console.error('[ERROR] Login failed:', error.message);
    showNotification(`Login failed: ${error.message}`, 'error');
  }
}

async function handleRegister(event) {
  event.preventDefault();
  
  const username = document.getElementById('register-username').value;
  const email = document.getElementById('register-email').value;
  const password = document.getElementById('register-password').value;
  const confirmPassword = document.getElementById('register-confirm-password').value;
  
  // Validate inputs
  if (!username || !email || !password || !confirmPassword) {
    showNotification('All fields are required', 'error');
    return;
  }
  
  if (password !== confirmPassword) {
    showNotification('Passwords do not match', 'error');
    return;
  }
  
  try {
    const result = await fetchAPI(`${API_BASE_URL}/auth/register`, 'POST', { 
      username, 
      email, 
      password 
    });
    
    // Close modal
    registerModal.style.display = 'none';
    
    // Show success notification
    showNotification('Registration successful! You can now log in.', 'success');
    
    // Reset form
    registerForm.reset();
    
    // Open login modal
    loginModal.style.display = 'block';
  } catch (error) {
    console.error('[ERROR] Registration failed:', error.message);
    showNotification(`Registration failed: ${error.message}`, 'error');
  }
}

function handleLogout() {
  // Clear user data
  currentUser = null;
  localStorage.removeItem('securepen_user');
  
  // Update UI
  updateUIForAuthState(false);
  
  // Show notification
  showNotification('Logged out successfully', 'info');
  
  // Navigate to dashboard
  navigateTo('#dashboard');
}

// Modal functions
function openLoginModal() {
  loginModal.style.display = 'block';
}

function openRegisterModal() {
  registerModal.style.display = 'block';
}

function closeLoginModal() {
  loginModal.style.display = 'none';
}

function closeRegisterModal() {
  registerModal.style.display = 'none';
}

// Close modals when clicking outside
window.onclick = function(event) {
  if (event.target === loginModal) {
    closeLoginModal();
  } else if (event.target === registerModal) {
    closeRegisterModal();
  }
};

// Navigation functions
function navigateTo(hash) {
  // Default to dashboard if no hash
  if (!hash || hash === '#') {
    hash = '#dashboard';
    window.location.hash = hash;
    return;
  }
  
  // Extract module name from hash
  const module = hash.substring(1);
  
  // Update current module
  currentModule = module;
  
  // Update active link
  document.querySelectorAll('nav a').forEach(link => {
    link.classList.remove('active');
  });
  
  const activeLink = document.querySelector(`nav a[href="${hash}"]`);
  if (activeLink) {
    activeLink.classList.add('active');
  }
  
  // Load module content
  loadModuleContent(module);
}

function handleHashChange() {
  navigateTo(window.location.hash);
}

// Content loading functions
async function loadModuleContent(module) {
  try {
    // Clear main content
    mainContent.innerHTML = '<div class="loading">Loading...</div>';
    
    // Load module content based on module name
    switch (module) {
      case 'dashboard':
        loadDashboard();
        break;
      case 'scanner':
      case 'sql-injection':
      case 'xss':
      case 'brute-force':
      case 'path-traversal':
      case 'command-injection':
        await loadVulnerabilityModule(module);
        break;
      default:
        mainContent.innerHTML = '<h2>Page Not Found</h2><p>The requested page does not exist.</p>';
    }
  } catch (error) {
    console.error(`Error loading ${module} module:`, error);
    mainContent.innerHTML = `
      <div class="error-container">
        <h2>Error Loading Module</h2>
        <p>There was an error loading the ${module} module. Please try again later.</p>
        <p class="error-details">${error.message}</p>
      </div>
    `;
  }
}

async function loadDashboard() {
  let statsHtml = '';
  let activityHtml = '';
  
  if (currentUser) {
    try {
      // Fetch user stats
      const stats = await fetchAPI(`${API_BASE_URL}/user/stats`);
      
      statsHtml = `
        <div class="stats-container">
          <div class="stat-card">
            <h3>Tests Run</h3>
            <div class="stat-value">${stats.total_scans}</div>
            <div class="stat-icon"><i class="fas fa-vial"></i></div>
          </div>
          <div class="stat-card">
            <h3>Vulnerabilities Found</h3>
            <div class="stat-value">${stats.total_vulnerabilities}</div>
            <div class="stat-icon"><i class="fas fa-bug"></i></div>
          </div>
          <div class="stat-card">
            <h3>Success Rate</h3>
            <div class="stat-value">${stats.success_rate}%</div>
            <div class="stat-icon"><i class="fas fa-chart-line"></i></div>
          </div>
        </div>
      `;
      
      // Fetch user activity
      const activity = await fetchAPI(`${API_BASE_URL}/user/activity`);
      
      if (activity.activities && activity.activities.length > 0) {
        activityHtml = `
          <div class="activity-container">
            <h3>Recent Activity</h3>
            <ul class="activity-list">
              ${activity.activities.map(item => `
                <li class="activity-item">
                  <div class="activity-icon">
                    ${item.action === 'SCAN' ? '<i class="fas fa-search"></i>' :
                      item.action === 'LOGIN' ? '<i class="fas fa-sign-in-alt"></i>' :
                      item.action === 'REGISTER' ? '<i class="fas fa-user-plus"></i>' :
                      '<i class="fas fa-clipboard-list"></i>'}
                  </div>
                  <div class="activity-details">
                    <div class="activity-title">${item.details}</div>
                    <div class="activity-time">${new Date(item.created_at).toLocaleString()}</div>
                  </div>
                </li>
              `).join('')}
            </ul>
          </div>
        `;
      } else {
        activityHtml = `
          <div class="activity-container">
            <h3>Recent Activity</h3>
            <p class="no-activity">No recent activity</p>
          </div>
        `;
      }
    } catch (error) {
      console.error('Error fetching user data:', error);
      statsHtml = `
        <div class="error-container">
          <p>Error loading user statistics. Please try again later.</p>
        </div>
      `;
      activityHtml = `
        <div class="error-container">
          <p>Error loading user activity. Please try again later.</p>
        </div>
      `;
    }
  } else {
    statsHtml = `
      <div class="stats-container">
        <div class="stat-card">
          <h3>Tests Run</h3>
          <div class="stat-value">0</div>
          <div class="stat-icon"><i class="fas fa-vial"></i></div>
        </div>
        <div class="stat-card">
          <h3>Vulnerabilities Found</h3>
          <div class="stat-value">0</div>
          <div class="stat-icon"><i class="fas fa-bug"></i></div>
        </div>
        <div class="stat-card">
          <h3>Success Rate</h3>
          <div class="stat-value">0%</div>
          <div class="stat-icon"><i class="fas fa-chart-line"></i></div>
        </div>
      </div>
    `;
    
    activityHtml = `
      <div class="activity-container">
        <div class="activity-item welcome-activity">
          <div class="activity-icon">
            <i class="fas fa-info-circle"></i>
          </div>
          <div class="activity-details">
            <div class="activity-title">Welcome to SecurePen</div>
            <div class="activity-description">Login or register to save your activity</div>
            <div class="activity-time">Just now</div>
          </div>
        </div>
      </div>
    `;
  }
  
  // Vulnerability distribution chart (placeholder)
  const distributionHtml = `
    <div class="chart-container">
      <h3>Vulnerability Distribution</h3>
      <div class="chart-placeholder">
        <div class="chart-legend">
          <div class="legend-item"><span class="legend-color sql"></span> SQL Injection</div>
          <div class="legend-item"><span class="legend-color xss"></span> XSS</div>
          <div class="legend-item"><span class="legend-color brute"></span> Brute Force</div>
          <div class="legend-item"><span class="legend-color path"></span> Path Traversal</div>
          <div class="legend-item"><span class="legend-color command"></span> Command Injection</div>
          <div class="legend-item"><span class="legend-color scanner"></span> Scanner</div>
        </div>
      </div>
    </div>
  `;
  
  // Quick actions
  const quickActionsHtml = `
    <div class="quick-actions">
      <h3>Quick Actions</h3>
      <div class="action-buttons">
        <a href="#scanner" class="action-button">
          <i class="fas fa-search"></i>
          <span>Run Scanner</span>
        </a>
        <a href="#sql-injection" class="action-button">
          <i class="fas fa-database"></i>
          <span>SQL Injection Test</span>
        </a>
        <a href="#xss" class="action-button">
          <i class="fas fa-code"></i>
          <span>XSS Test</span>
        </a>
      </div>
    </div>
  `;
  
  // Combine all sections
  mainContent.innerHTML = `
    <h2>Welcome to SecurePen</h2>
    <p class="subtitle">Enterprise-grade vulnerability testing platform</p>
    
    ${statsHtml}
    
    ${distributionHtml}
    
    <div class="dashboard-bottom">
      <div class="dashboard-column">
        <h3>Recent Activity</h3>
        ${activityHtml}
      </div>
      <div class="dashboard-column">
        ${quickActionsHtml}
      </div>
    </div>
  `;
}

async function loadVulnerabilityModule(module) {
  try {
    // Convert module name to API endpoint format
    const endpoint = module.replace('-', '/');
    
    // Fetch module data
    const moduleData = await fetchAPI(`${API_BASE_URL}/modules/${endpoint}`);
    
    // Build module UI based on module type
    let moduleHtml = '';
    
    if (module === 'scanner') {
      moduleHtml = buildScannerModule(moduleData);
    } else {
      moduleHtml = buildVulnerabilityTestModule(moduleData, module);
    }
    
    // Update main content
    mainContent.innerHTML = moduleHtml;
    
    // Add event listeners to the form
    const testForm = document.getElementById(`${module}-form`);
    if (testForm) {
      testForm.addEventListener('submit', (event) => {
        event.preventDefault();
        handleVulnerabilityTest(module);
      });
    }
  } catch (error) {
    throw error;
  }
}

function buildVulnerabilityTestModule(moduleData, moduleType) {
  // Build examples list
  const examplesList = moduleData.examples.map(example => 
    `<li><code>${example}</code></li>`
  ).join('');
  
  // Build test cases list
  const testCasesList = moduleData.testCases.map(testCase => 
    `<div class="test-case">
      <h4>${testCase.name}</h4>
      <p>${testCase.description}</p>
      ${testCase.payload ? `<div class="payload"><code>${testCase.payload}</code></div>` : ''}
    </div>`
  ).join('');
  
  return `
    <div class="module-container">
      <h2>${moduleData.title}</h2>
      <p class="module-description">${moduleData.description}</p>
      
      <div class="module-sections">
        <div class="module-section">
          <h3>Instructions</h3>
          <p>${moduleData.instructions}</p>
          
          <form id="${moduleType}-form" class="vulnerability-form">
            <div class="form-group">
              <label for="${moduleType}-target">Target URL or Input</label>
              <input type="text" id="${moduleType}-target" name="target" placeholder="Enter target URL or input" required>
            </div>
            
            <div class="form-group">
              <label for="${moduleType}-payload">Payload</label>
              <input type="text" id="${moduleType}-payload" name="payload" placeholder="Enter payload or select from examples">
            </div>
            
            <button type="submit" class="primary-button">Run Test</button>
          </form>
          
          <div id="${moduleType}-result" class="test-result"></div>
        </div>
        
        <div class="module-section">
          <h3>Examples</h3>
          <ul class="examples-list">
            ${examplesList}
          </ul>
          
          <h3>Test Cases</h3>
          <div class="test-cases">
            ${testCasesList}
          </div>
        </div>
      </div>
    </div>
  `;
}

function buildScannerModule(moduleData) {
  // Build scan types list
  const scanTypesList = moduleData.scanTypes.map(scanType => 
    `<div class="scan-type">
      <input type="radio" id="scan-type-${scanType.name.toLowerCase().replace(' ', '-')}" 
        name="scan-type" value="${scanType.name.toLowerCase().replace(' ', '-')}">
      <label for="scan-type-${scanType.name.toLowerCase().replace(' ', '-')}">
        <h4>${scanType.name}</h4>
        <p>${scanType.description}</p>
        <span class="duration">Duration: ${scanType.duration}</span>
      </label>
    </div>`
  ).join('');
  
  // Build vulnerability types list
  const vulnerabilityTypesList = moduleData.vulnerabilityTypes.map(vulnType => 
    `<div class="vulnerability-type">
      <input type="checkbox" id="vuln-type-${vulnType.toLowerCase().replace(/\s+/g, '-')}" 
        name="vulnerability-types" value="${vulnType.toLowerCase().replace(/\s+/g, '-')}">
      <label for="vuln-type-${vulnType.toLowerCase().replace(/\s+/g, '-')}">
        ${vulnType}
      </label>
    </div>`
  ).join('');
  
  return `
    <div class="module-container">
      <h2>${moduleData.title}</h2>
      <p class="module-description">${moduleData.description}</p>
      
      <div class="module-sections">
        <div class="module-section">
          <h3>Scanner Configuration</h3>
          <p>${moduleData.instructions}</p>
          
          <form id="scanner-form" class="vulnerability-form">
            <div class="form-group">
              <label for="scanner-target">Target URL or IP</label>
              <input type="text" id="scanner-target" name="target" placeholder="Enter target URL or IP" required>
            </div>
            
            <div class="form-group">
              <label>Scan Type</label>
              <div class="scan-types">
                ${scanTypesList}
              </div>
            </div>
            
            <div class="form-group custom-scan-options" style="display: none;">
              <label>Vulnerability Types to Scan</label>
              <div class="vulnerability-types">
                ${vulnerabilityTypesList}
              </div>
            </div>
            
            <button type="submit" class="primary-button">Start Scan</button>
          </form>
          
          <div id="scanner-result" class="test-result"></div>
        </div>
        
        <div class="module-section">
          <h3>Scan Information</h3>
          <div class="scan-info">
            <p>The vulnerability scanner will analyze your target for security weaknesses across multiple vulnerability categories.</p>
            <p>Select the appropriate scan type based on your needs:</p>
            <ul>
              <li><strong>Quick Scan:</strong> Fast analysis of common vulnerabilities</li>
              <li><strong>Full Scan:</strong> Comprehensive analysis of all vulnerability types</li>
              <li><strong>Custom Scan:</strong> Select specific vulnerability types to scan for</li>
            </ul>
            <p>For best results, ensure you have proper authorization to scan the target.</p>
          </div>
        </div>
      </div>
    </div>
  `;
}

async function handleVulnerabilityTest(module) {
  if (!currentUser) {
    showNotification('Please log in to run vulnerability tests', 'error');
    openLoginModal();
    return;
  }
  
  const resultContainer = document.getElementById(`${module}-result`);
  resultContainer.innerHTML = '<div class="loading">Running test...</div>';
  
  try {
    // Get form values
    const target = document.getElementById(`${module}-target`).value;
    const payload = document.getElementById(`${module}-payload`)?.value || '';
    
    // Convert module name to API endpoint format
    const endpoint = module.replace('-', '/');
    
    // Call API
    const result = await fetchAPI(`${API_BASE_URL}/scan/${endpoint}`, 'POST', { target, payload });
    
    // Display result
    if (result.success) {
      resultContainer.innerHTML = `
        <div class="result-card ${result.vulnerabilitiesFound > 0 ? 'vulnerable' : 'secure'}">
          <div class="result-header">
            <div class="result-icon">
              ${result.vulnerabilitiesFound > 0 ? 
                '<i class="fas fa-exclamation-triangle"></i>' : 
                '<i class="fas fa-shield-alt"></i>'}
            </div>
            <div class="result-title">
              ${result.vulnerabilitiesFound > 0 ? 'Vulnerability Detected' : 'No Vulnerabilities Detected'}
            </div>
          </div>
          <div class="result-body">
            <p>${result.result}</p>
          </div>
        </div>
      `;
      
      showNotification('Test completed successfully', 'success');
    } else {
      resultContainer.innerHTML = `
        <div class="result-card error">
          <div class="result-header">
            <div class="result-icon">
              <i class="fas fa-times-circle"></i>
            </div>
            <div class="result-title">Test Failed</div>
          </div>
          <div class="result-body">
            <p>${result.error || 'An unknown error occurred'}</p>
          </div>
        </div>
      `;
      
      showNotification('Test failed', 'error');
    }
  } catch (error) {
    resultContainer.innerHTML = `
      <div class="result-card error">
        <div class="result-header">
          <div class="result-icon">
            <i class="fas fa-times-circle"></i>
          </div>
          <div class="result-title">Test Failed</div>
        </div>
        <div class="result-body">
          <p>${error.message || 'An unknown error occurred'}</p>
        </div>
      </div>
    `;
    
    showNotification(`Test failed: ${error.message}`, 'error');
  }
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  // Check authentication state
  checkAuth();
  
  // Set up event listeners
  loginBtn.addEventListener('click', openLoginModal);
  registerBtn.addEventListener('click', openRegisterModal);
  logoutBtn.addEventListener('click', handleLogout);
  closeLoginBtn.addEventListener('click', closeLoginModal);
  closeRegisterBtn.addEventListener('click', closeRegisterModal);
  loginForm.addEventListener('submit', handleLogin);
  registerForm.addEventListener('submit', handleRegister);
  
  // Set up navigation
  window.addEventListener('hashchange', handleHashChange);
  
  // Initial navigation
  navigateTo(window.location.hash);
});
