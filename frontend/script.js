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

const dashboardSection = document.getElementById("dashboard");
const scannerSection = document.getElementById("scanner");
const sqlSection = document.getElementById("sql-injection");
const xssSection = document.getElementById("xss");
const bruteSection = document.getElementById("brute-force");
const pathSection = document.getElementById("path-traversal");
const commandSection = document.getElementById("command-injection");

// Modal elements and buttons
let loginBtn;
let registerBtn;
let authButtons;
let loginModal;
let registerModal;
let closeLoginBtn;
let closeRegisterBtn;

// Initialize modal elements after DOM is fully loaded
document.addEventListener("DOMContentLoaded", function() {
  console.log("DOM fully loaded and parsed");
  
  // Get auth buttons
  loginBtn = document.getElementById("login-btn");
  registerBtn = document.getElementById("register-btn");
  authButtons = document.querySelector(".auth-buttons");
  
  // Get modal elements - using correct camelCase IDs
  loginModal = document.getElementById("loginModal");
  registerModal = document.getElementById("registerModal");
  closeLoginBtn = document.getElementById("close-login");
  closeRegisterBtn = document.getElementById("close-register");
  
  // Attach event listeners for modals
  if (loginBtn) {
    loginBtn.addEventListener("click", function() {
      openModal(loginModal);
    });
  }
  
  if (registerBtn) {
    registerBtn.addEventListener("click", function() {
      openModal(registerModal);
    });
  }
  
  if (closeLoginBtn) {
    closeLoginBtn.addEventListener("click", function() {
      closeModal(loginModal);
    });
  }
  
  if (closeRegisterBtn) {
    closeRegisterBtn.addEventListener("click", function() {
      closeModal(registerModal);
    });
  }
  
  // Close modals when clicking outside
  window.addEventListener("click", function(event) {
    if (event.target === loginModal) {
      closeModal(loginModal);
    }
    if (event.target === registerModal) {
      closeModal(registerModal);
    }
  });
  
  // Form submission handlers
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  
  if (loginForm) {
    loginForm.addEventListener("submit", handleLogin);
  }
  
  if (registerForm) {
    registerForm.addEventListener("submit", handleRegister);
  }
  
  // Switch between login and register modals
  const showRegisterLink = document.getElementById("show-register");
  const showLoginLink = document.getElementById("show-login");
  
  if (showRegisterLink) {
    showRegisterLink.addEventListener("click", function(e) {
      e.preventDefault();
      closeModal(loginModal);
      openModal(registerModal);
    });
  }
  
  if (showLoginLink) {
    showLoginLink.addEventListener("click", function(e) {
      e.preventDefault();
      closeModal(registerModal);
      openModal(loginModal);
    });
  }
  
  // Initialize other UI elements
  initializeNavigation();
  initializeChart();
  
  // Check authentication state
  checkAuthState();
  
  // Initialize notification system
  initializeNotifications();
  
  console.log("Initialization complete");
});

// Dashboard elements
const testsCount = document.getElementById("tests-count");
const vulnsCount = document.getElementById("vulns-count");
const successRate = document.getElementById("success-rate");
const activityList = document.getElementById("activity-list");
const vulnerabilityChartCtx = document.getElementById("vulnerability-chart")?.getContext("2d");
let vulnerabilityChart;

// State
let currentUser = null;
let currentToken = null;
let dashboardStats = {
  tests: 0,
  vulns: 0,
  sql: 0,
  xss: 0,
  brute: 0,
  path: 0,
  command: 0,
  scan: 0,
};

// Current active module
let currentModule = "dashboard";

// ── Notification System ────────────────────────────────────────────

// Create notification container
function initializeNotifications() {
  // Check if container already exists
  if (document.getElementById('notification-container')) return;
  
  const container = document.createElement('div');
  container.id = 'notification-container';
  container.style.position = 'fixed';
  container.style.top = '20px';
  container.style.right = '20px';
  container.style.zIndex = '9999';
  document.body.appendChild(container);
}

// Function to show notifications
function showNotification(message, type = "info") {
  console.log(`[${type.toUpperCase()}] ${message}`);
  
  const container = document.getElementById('notification-container');
  if (!container) return;
  
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.innerHTML = `
    <div class="notification-icon">
      <i class="fas ${getNotificationIcon(type)}"></i>
    </div>
    <div class="notification-content">
      <div class="notification-message">${message}</div>
    </div>
    <button class="notification-close">&times;</button>
  `;
  
  // Style the notification
  notification.style.backgroundColor = getNotificationColor(type);
  notification.style.color = '#fff';
  notification.style.padding = '15px';
  notification.style.borderRadius = '5px';
  notification.style.marginBottom = '10px';
  notification.style.boxShadow = '0 4px 8px rgba(0,0,0,0.2)';
  notification.style.display = 'flex';
  notification.style.alignItems = 'center';
  notification.style.minWidth = '300px';
  notification.style.maxWidth = '400px';
  notification.style.animation = 'slideIn 0.3s ease-out forwards';
  
  // Add close button event
  const closeBtn = notification.querySelector('.notification-close');
  closeBtn.style.background = 'none';
  closeBtn.style.border = 'none';
  closeBtn.style.color = '#fff';
  closeBtn.style.fontSize = '20px';
  closeBtn.style.cursor = 'pointer';
  closeBtn.style.marginLeft = 'auto';
  
  closeBtn.addEventListener('click', () => {
    notification.style.animation = 'slideOut 0.3s ease-out forwards';
    setTimeout(() => {
      container.removeChild(notification);
    }, 300);
  });
  
  // Add to container
  container.appendChild(notification);
  
  // Auto-remove after 5 seconds
  setTimeout(() => {
    if (notification.parentNode === container) {
      notification.style.animation = 'slideOut 0.3s ease-out forwards';
      setTimeout(() => {
        if (notification.parentNode === container) {
          container.removeChild(notification);
        }
      }, 300);
    }
  }, 5000);
  
  // Add CSS animations if not already present
  if (!document.getElementById('notification-styles')) {
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
      }
    `;
    document.head.appendChild(style);
  }
}

function getNotificationIcon(type) {
  switch (type) {
    case 'success': return 'fa-check-circle';
    case 'error': return 'fa-exclamation-circle';
    case 'warning': return 'fa-exclamation-triangle';
    default: return 'fa-info-circle';
  }
}

function getNotificationColor(type) {
  switch (type) {
    case 'success': return '#28a745';
    case 'error': return '#dc3545';
    case 'warning': return '#ffc107';
    default: return '#17a2b8';
  }
}

// ── Modal Functions ────────────────────────────────────────────

// Function to open a modal
function openModal(modal) {
  if (!modal) return;
  
  // Clear any previous error messages
  const errorMessages = modal.querySelectorAll('.error-message');
  errorMessages.forEach(el => el.remove());
  
  // Reset form if present
  const form = modal.querySelector('form');
  if (form) form.reset();
  
  modal.style.display = "block";
}

// Function to close a modal
function closeModal(modal) {
  if (!modal) return;
  modal.style.display = "none";
}

// Function to show form error
function showFormError(formElement, message) {
  // Remove any existing error messages
  const existingErrors = formElement.querySelectorAll('.error-message');
  existingErrors.forEach(el => el.remove());
  
  // Create error message element
  const errorDiv = document.createElement('div');
  errorDiv.className = 'error-message';
  errorDiv.textContent = message;
  errorDiv.style.color = '#dc3545';
  errorDiv.style.marginTop = '10px';
  errorDiv.style.fontSize = '14px';
  
  // Add to form
  formElement.appendChild(errorDiv);
}

// ── Authentication Functions ────────────────────────────────────────────

// Function to handle login form submission
async function handleLogin(event) {
  event.preventDefault();
  
  const form = event.target;
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;
  
  // Validate inputs
  if (!username || !password) {
    showFormError(form, "Username and password are required");
    return;
  }
  
  try {
    const response = await fetchAPI("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    
    if (response.token) {
      // Store token in cookie
      document.cookie = `token=${response.token}; path=/; max-age=86400`;
      currentToken = response.token;
      currentUser = response.user;
      
      // Close modal and update UI
      closeModal(loginModal);
      updateAuthState(response.user);
      showNotification(`Welcome back, ${response.user.username}!`, "success");
      logActivity("Login", "Successfully logged in", "fa-sign-in-alt", "success");
    }
  } catch (error) {
    showFormError(form, `Login failed: ${error.message}`);
    showNotification(`Login failed: ${error.message}`, "error");
  }
}

// Function to handle register form submission
async function handleRegister(event) {
  event.preventDefault();
  
  const form = event.target;
  const username = document.getElementById("register-username").value;
  const email = document.getElementById("register-email").value;
  const password = document.getElementById("register-password").value;
  const confirmPassword = document.getElementById("register-confirm").value;
  
  // Validate inputs
  if (!username || !email || !password || !confirmPassword) {
    showFormError(form, "All fields are required");
    return;
  }
  
  if (password !== confirmPassword) {
    showFormError(form, "Passwords do not match");
    return;
  }
  
  try {
    const response = await fetchAPI("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password }),
    });
    
    closeModal(registerModal);
    showNotification("Registration successful! Please log in.", "success");
    
    // Open login modal
    openModal(loginModal);
  } catch (error) {
    let errorMessage = error.message;
    
    // Provide more user-friendly messages for common errors
    if (error.message.includes("409") || error.message.includes("Conflict")) {
      errorMessage = "Username or email already exists";
    }
    
    showFormError(form, `Registration failed: ${errorMessage}`);
    showNotification(`Registration failed: ${errorMessage}`, "error");
  }
}

// Function to handle logout
async function handleLogout() {
  try {
    await fetchAPI("/auth/logout", { method: "POST" });
  } catch (error) {
    console.error("Logout error:", error);
  } finally {
    // Clear token and user state regardless of API response
    document.cookie = "token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    currentToken = null;
    currentUser = null;
    updateAuthState(null);
    showNotification("You have been logged out", "info");
  }
}

// Function to check authentication state on page load
async function checkAuthState() {
  const token = getToken();
  if (!token) {
    updateAuthState(null);
    return;
  }
  
  try {
    const response = await fetchAPI("/auth/me");
    if (response.user) {
      currentUser = response.user;
      currentToken = token;
      updateAuthState(response.user);
    } else {
      // Invalid token
      document.cookie = "token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
      updateAuthState(null);
    }
  } catch (error) {
    console.log("[ERROR]", error);
    // Error checking auth state, assume not logged in
    document.cookie = "token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    updateAuthState(null);
  }
}

// ── Utility Functions ────────────────────────────────────────────

// Function to get JWT token from cookies
function getToken() {
  const cookies = document.cookie.split("; ");
  const tokenCookie = cookies.find((row) => row.startsWith("token="));
  return tokenCookie ? tokenCookie.split("=")[1] : null;
}

// Function to make authenticated API requests
async function fetchAPI(endpoint, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...options.headers,
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: response.statusText }));
      console.error(`API Error (${response.status}): ${errorData.message}`);
      throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error("Fetch API error:", error);
    throw error; // Re-throw the error for further handling
  }
}

// Function to update dashboard stats
function updateDashboardStats() {
  if (testsCount) testsCount.textContent = dashboardStats.tests;
  if (vulnsCount) vulnsCount.textContent = dashboardStats.vulns;
  if (successRate) {
    successRate.textContent =
      dashboardStats.tests > 0
        ? `${((dashboardStats.vulns / dashboardStats.tests) * 100).toFixed(0)}%`
        : "0%";
  }

  // Update chart
  if (vulnerabilityChart) {
    vulnerabilityChart.data.datasets[0].data = [
      dashboardStats.sql,
      dashboardStats.xss,
      dashboardStats.brute,
      dashboardStats.path,
      dashboardStats.command,
      dashboardStats.scan,
    ];
    vulnerabilityChart.update();
  }
}

// Function to log activity on the dashboard
function logActivity(title, description, iconClass = "fa-info-circle", iconColor = "info") {
  if (!activityList) return;
  
  const newItem = document.createElement("div");
  newItem.className = "activity-item";
  newItem.innerHTML = `
    <div class="activity-icon ${iconColor}">
      <i class="fas ${iconClass}"></i>
    </div>
    <div class="activity-content">
      <h4 class="activity-title">${title}</h4>
      <p class="activity-description">${description}</p>
      <span class="activity-time">${new Date().toLocaleTimeString()}</span>
    </div>
  `;
  // Prepend to keep newest at the top
  if (activityList.firstChild) {
    activityList.insertBefore(newItem, activityList.firstChild);
  } else {
    activityList.appendChild(newItem);
  }

  // Limit number of log items (optional)
  while (activityList.children.length > 10) {
    activityList.removeChild(activityList.lastChild);
  }
}

// Function to initialize the dashboard chart
function initializeChart() {
  if (!vulnerabilityChartCtx) return;
  
  if (vulnerabilityChart) {
    vulnerabilityChart.destroy();
  }
  vulnerabilityChart = new Chart(vulnerabilityChartCtx, {
    type: "doughnut",
    data: {
      labels: [
        "SQL Injection",
        "XSS",
        "Brute Force",
        "Path Traversal",
        "Command Injection",
        "Scanner",
      ],
      datasets: [
        {
          label: "Vulnerabilities Found",
          data: [0, 0, 0, 0, 0, 0], // Initial data
          backgroundColor: [
            "#ff6384", // SQLi
            "#ff9f40", // XSS
            "#ffcd56", // Brute
            "#4bc0c0", // Path
            "#36a2eb", // Command
            "#9966ff", // Scanner
          ],
          borderColor: "#444",
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#ccc",
          },
        },
        title: {
          display: false,
        },
      },
    },
  });
}

// Function to update UI based on auth state
function updateAuthState(user) {
  currentUser = user;
  if (!authButtons) return;
  
  if (user) {
    // Logged in
    authButtons.innerHTML = `
      <span class="welcome-user">Welcome, ${user.username}!</span>
      <button id="logout-btn" class="btn btn-outline">Logout</button>
    `;
    document.getElementById("logout-btn").addEventListener("click", handleLogout);
    fetchUserStats(); // Fetch stats when logged in
  } else {
    // Logged out
    authButtons.innerHTML = `
      <button id="login-btn" class="btn btn-outline-primary">Login</button>
      <button id="register-btn" class="btn btn-primary">Register</button>
    `;
    
    // Re-attach event listeners after DOM update
    const newLoginBtn = document.getElementById("login-btn");
    const newRegisterBtn = document.getElementById("register-btn");
    
    if (newLoginBtn) {
      newLoginBtn.addEventListener("click", function() {
        openModal(loginModal);
      });
    }
    
    if (newRegisterBtn) {
      newRegisterBtn.addEventListener("click", function() {
        openModal(registerModal);
      });
    }
    
    // Reset stats when logged out
    dashboardStats = { tests: 0, vulns: 0, sql: 0, xss: 0, brute: 0, path: 0, command: 0, scan: 0 };
    updateDashboardStats();
    
    if (activityList) {
      activityList.innerHTML = 
        `<div class="activity-item">
           <div class="activity-icon info"><i class="fas fa-info-circle"></i></div>
           <div class="activity-content">
             <h4 class="activity-title">Welcome to SecurePen</h4>
             <p class="activity-description">Login or register to save your activity</p>
             <span class="activity-time">Just now</span>
           </div>
         </div>`;
    }
  }
}

// Function to fetch user stats and activity
async function fetchUserStats() {
  if (!currentUser) return;
  try {
    console.log("Fetching user stats for", currentUser.username);
    
    // Fetch user stats
    const statsData = await fetchAPI("/user/stats");
    if (statsData) {
      dashboardStats.tests = statsData.total_scans || 0;
      dashboardStats.vulns = statsData.total_vulnerabilities || 0;
      updateDashboardStats();
    }
    
    // Fetch activity logs
    const activityData = await fetchAPI("/user/activity");
    if (activityList) {
      activityList.innerHTML = ""; // Clear existing logs
      if (activityData.activities && activityData.activities.length > 0) {
        activityData.activities.forEach(log => {
          logActivity(log.action, log.details, getActivityIcon(log.action), getActivityColor(log.action));
        });
      } else {
        logActivity("No activity yet", "Start testing to see your activity here.");
      }
    }
    
    // Fetch scan results to populate dashboard
    const scanData = await fetchAPI("/user/scans");
    if (scanData.scans && scanData.scans.length > 0) {
      // Reset vulnerability type counts
      dashboardStats.sql = 0;
      dashboardStats.xss = 0;
      dashboardStats.brute = 0;
      dashboardStats.path = 0;
      dashboardStats.command = 0;
      dashboardStats.scan = 0;
      
      // Count vulnerabilities by type
      scanData.scans.forEach(scan => {
        if (scan.vulnerabilities_found > 0) {
          switch(scan.scan_type) {
            case 'SQL_INJECTION': dashboardStats.sql++; break;
            case 'XSS': dashboardStats.xss++; break;
            case 'BRUTE_FORCE': dashboardStats.brute++; break;
            case 'PATH_TRAVERSAL': dashboardStats.path++; break;
            case 'COMMAND_INJECTION': dashboardStats.command++; break;
            case 'FULL_SCAN': dashboardStats.scan++; break;
          }
        }
      });
      
      updateDashboardStats();
    }
  } catch (error) {
    console.error("Error fetching user stats:", error);
    showNotification("Failed to load user data", "error");
  }
}

// Helper functions for activity logs
function getActivityIcon(action) {
  switch (action) {
    case 'LOGIN': return 'fa-sign-in-alt';
    case 'REGISTER': return 'fa-user-plus';
    case 'LOGOUT': return 'fa-sign-out-alt';
    case 'SQL_TEST': return 'fa-database';
    case 'XSS_TEST': return 'fa-code';
    case 'BRUTE_TEST': return 'fa-key';
    case 'PATH_TEST': return 'fa-folder-open';
    case 'COMMAND_TEST': return 'fa-terminal';
    case 'SCAN_START': return 'fa-search';
    case 'SCAN_COMPLETE': return 'fa-check-circle';
    default: return 'fa-info-circle';
  }
}

function getActivityColor(action) {
  if (action.includes('TEST') || action.includes('SCAN')) return 'success';
  if (action.includes('LOGIN') || action.includes('REGISTER')) return 'primary';
  if (action.includes('LOGOUT')) return 'warning';
  return 'info';
}

// ── Navigation Functions ────────────────────────────────────────────

// Function to initialize navigation
function initializeNavigation() {
  // Set up navigation links
  const navLinks = [
    { link: dashboardLink, section: dashboardSection },
    { link: scannerLink, section: scannerSection },
    { link: sqlLink, section: sqlSection },
    { link: xssLink, section: xssSection },
    { link: bruteLink, section: bruteSection },
    { link: pathLink, section: pathSection },
    { link: commandLink, section: commandSection },
  ];
  
  // Add click event listeners to navigation links
  navLinks.forEach(({ link, section }) => {
    if (link && section) {
      link.addEventListener("click", (e) => {
        e.preventDefault();
        navigateTo(section.id);
      });
    }
  });
  
  // Handle hash-based navigation
  window.addEventListener("hashchange", handleHashChange);
  handleHashChange(); // Handle initial hash
}

// Function to handle hash changes
function handleHashChange() {
  const hash = window.location.hash.substring(1) || "dashboard";
  navigateTo(hash);
}

// Function to navigate to a specific section
function navigateTo(sectionId) {
  // Hide all sections
  const sections = document.querySelectorAll(".module-section");
  sections.forEach((section) => {
    section.classList.remove("active");
  });
  
  // Show the target section
  const targetSection = document.getElementById(sectionId);
  if (targetSection) {
    targetSection.classList.add("active");
    
    // Update active navigation link
    const navLinks = document.querySelectorAll(".nav-link");
    navLinks.forEach((link) => {
      link.classList.remove("active");
      if (link.getAttribute("href") === `#${sectionId}`) {
        link.classList.add("active");
      }
    });
    
    // Update URL hash without scrolling
    const scrollPosition = window.scrollY;
    window.location.hash = sectionId;
    window.scrollTo(0, scrollPosition);
    
    // Load module content if needed
    loadModuleContent(sectionId);
    
    // Update current module
    currentModule = sectionId;
  }
}

// Function to load module content
async function loadModuleContent(moduleId) {
  // Skip dashboard as it's already loaded
  if (moduleId === 'dashboard') return;
  
  // Map module IDs to API endpoints
  const moduleEndpoints = {
    'sql-injection': '/modules/sql',
    'xss': '/modules/xss',
    'brute-force': '/modules/brute-force',
    'path-traversal': '/modules/path-traversal',
    'command-injection': '/modules/command-injection',
    'scanner': '/modules/scanner'
  };
  
  const endpoint = moduleEndpoints[moduleId];
  if (!endpoint) return;
  
  const moduleSection = document.getElementById(moduleId);
  if (!moduleSection) return;
  
  // Check if content is already loaded
  if (moduleSection.dataset.loaded === 'true') return;
  
  try {
    // Show loading indicator
    moduleSection.innerHTML = `
      <div class="loading-container">
        <div class="loading-spinner"></div>
        <p>Loading module content...</p>
      </div>
    `;
    
    // Fetch module data
    const moduleData = await fetchAPI(endpoint);
    
    // Generate module content based on the data
    let moduleContent = '';
    
    switch (moduleId) {
      case 'sql-injection':
        moduleContent = generateSqlModuleContent(moduleData);
        break;
      case 'xss':
        moduleContent = generateXssModuleContent(moduleData);
        break;
      case 'brute-force':
        moduleContent = generateBruteForceModuleContent(moduleData);
        break;
      case 'path-traversal':
        moduleContent = generatePathTraversalModuleContent(moduleData);
        break;
      case 'command-injection':
        moduleContent = generateCommandInjectionModuleContent(moduleData);
        break;
      case 'scanner':
        moduleContent = generateScannerModuleContent(moduleData);
        break;
    }
    
    // Update module content
    moduleSection.innerHTML = moduleContent;
    moduleSection.dataset.loaded = 'true';
    
    // Initialize module-specific functionality
    initializeModuleHandlers(moduleId);
    
  } catch (error) {
    console.error(`Error loading ${moduleId} module:`, error);
    moduleSection.innerHTML = `
      <div class="error-container">
        <div class="error-icon">
          <i class="fas fa-exclamation-triangle"></i>
        </div>
        <h3>Error Loading Module</h3>
        <p>${error.message}</p>
        <button class="btn btn-primary retry-btn">Retry</button>
      </div>
    `;
    
    // Add retry button handler
    const retryBtn = moduleSection.querySelector('.retry-btn');
    if (retryBtn) {
      retryBtn.addEventListener('click', () => {
        moduleSection.dataset.loaded = 'false';
        loadModuleContent(moduleId);
      });
    }
  }
}

// Module content generators
function generateSqlModuleContent(data) {
  return `
    <div class="container">
      <div class="section-header">
        <h2>${data.title}</h2>
        <p class="section-description">${data.description}</p>
      </div>
      
      <div class="module-instructions">
        <h3>Instructions</h3>
        <p>${data.instructions}</p>
      </div>
      
      <div class="module-content">
        <div class="test-panel">
          <h3>Test SQL Injection</h3>
          <div class="form-group">
            <label for="sql-target">Target URL</label>
            <input type="text" id="sql-target" class="form-control" placeholder="https://example.com/login">
          </div>
          <div class="form-group">
            <label for="sql-username">Username</label>
            <input type="text" id="sql-username" class="form-control" placeholder="' OR '1'='1">
          </div>
          <div class="form-group">
            <label for="sql-password">Password</label>
            <input type="text" id="sql-password" class="form-control" placeholder="password">
          </div>
          <button id="sql-submit" class="btn btn-primary">Test Vulnerability</button>
        </div>
        
        <div id="sql-result" class="result-box" style="display: none;">
          <div class="result-header">
            <i class="fas fa-check-circle text-success"></i>
            <h3 class="result-title">SQL Injection Successful!</h3>
          </div>
          <div class="result-content">
            <h4>Query Result</h4>
            <pre id="sql-query-result" class="code-block">SELECT * FROM users WHERE username='' OR '1'='1' AND password='password'</pre>
          </div>
        </div>
      </div>
      
      <div class="module-examples">
        <h3>Example Payloads</h3>
        <div class="examples-list">
          ${data.examples.map(example => `
            <div class="example-item">
              <code>${example}</code>
              <button class="btn btn-sm btn-outline use-example" data-payload="${example}">Use</button>
            </div>
          `).join('')}
        </div>
      </div>
      
      <div class="module-test-cases">
        <h3>Common Test Cases</h3>
        <div class="test-cases-list">
          ${data.testCases.map(testCase => `
            <div class="test-case">
              <h4>${testCase.name}</h4>
              <p>${testCase.description}</p>
              <div class="payload">
                <code>${testCase.payload}</code>
                <button class="btn btn-sm btn-outline use-test-case" data-payload="${testCase.payload}">Use</button>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;
}

function generateXssModuleContent(data) {
  return `
    <div class="container">
      <div class="section-header">
        <h2>${data.title}</h2>
        <p class="section-description">${data.description}</p>
      </div>
      
      <div class="module-instructions">
        <h3>Instructions</h3>
        <p>${data.instructions}</p>
      </div>
      
      <div class="module-content">
        <div class="test-panel">
          <h3>Test XSS Vulnerability</h3>
          <div class="form-group">
            <label for="xss-target">Target URL</label>
            <input type="text" id="xss-target" class="form-control" placeholder="https://example.com/comment">
          </div>
          <div class="form-group">
            <label for="xss-name">Name (optional)</label>
            <input type="text" id="xss-name" class="form-control" placeholder="Your Name">
          </div>
          <div class="form-group">
            <label for="xss-comment">Comment/Payload</label>
            <textarea id="xss-comment" class="form-control" rows="3" placeholder="<script>alert('XSS')</script>"></textarea>
          </div>
          <button id="xss-submit" class="btn btn-primary">Test Vulnerability</button>
        </div>
        
        <div id="xss-result" class="result-box" style="display: none;">
          <div class="result-header">
            <i class="fas fa-check-circle text-success"></i>
            <h3 class="result-title">XSS Vulnerability Detected!</h3>
          </div>
          <div class="result-content">
            <h4>Rendered Output</h4>
            <div id="xss-comment-preview" class="preview-box"></div>
          </div>
        </div>
      </div>
      
      <div class="module-examples">
        <h3>Example Payloads</h3>
        <div class="examples-list">
          ${data.examples.map(example => `
            <div class="example-item">
              <code>${example.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code>
              <button class="btn btn-sm btn-outline use-example" data-payload="${example.replace(/"/g, '&quot;')}">Use</button>
            </div>
          `).join('')}
        </div>
      </div>
      
      <div class="module-test-cases">
        <h3>Common Test Cases</h3>
        <div class="test-cases-list">
          ${data.testCases.map(testCase => `
            <div class="test-case">
              <h4>${testCase.name}</h4>
              <p>${testCase.description}</p>
              <div class="payload">
                <code>${testCase.payload.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code>
                <button class="btn btn-sm btn-outline use-test-case" data-payload="${testCase.payload.replace(/"/g, '&quot;')}">Use</button>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;
}

function generateBruteForceModuleContent(data) {
  return `
    <div class="container">
      <div class="section-header">
        <h2>${data.title}</h2>
        <p class="section-description">${data.description}</p>
      </div>
      
      <div class="module-instructions">
        <h3>Instructions</h3>
        <p>${data.instructions}</p>
      </div>
      
      <div class="module-content">
        <div class="test-panel">
          <h3>Test Brute Force Attack</h3>
          <div class="form-group">
            <label for="brute-target">Target URL</label>
            <input type="text" id="brute-target" class="form-control" placeholder="https://example.com/login">
          </div>
          <div class="form-group">
            <label for="brute-username">Username</label>
            <input type="text" id="brute-username" class="form-control" placeholder="admin">
          </div>
          <div class="form-group">
            <label for="brute-passwords">Password List (one per line)</label>
            <textarea id="brute-passwords" class="form-control" rows="5" placeholder="password123&#10;admin123&#10;qwerty&#10;123456&#10;letmein"></textarea>
          </div>
          <button id="brute-submit" class="btn btn-primary">Start Brute Force</button>
        </div>
        
        <div id="brute-result" class="result-box" style="display: none;">
          <div class="result-header">
            <i class="fas fa-check-circle text-success"></i>
            <h3 class="result-title">Password Cracked!</h3>
          </div>
          <div class="result-content">
            <div class="result-item">
              <span class="result-label">Username:</span>
              <span id="brute-result-username" class="result-value">admin</span>
            </div>
            <div class="result-item">
              <span class="result-label">Password:</span>
              <span id="brute-result-password" class="result-value">admin123</span>
            </div>
            <div class="result-item">
              <span class="result-label">Attempts:</span>
              <span id="brute-result-attempts" class="result-value">3</span>
            </div>
          </div>
        </div>
      </div>
      
      <div class="module-examples">
        <h3>Example Targets</h3>
        <div class="examples-list">
          ${data.examples.map(example => `
            <div class="example-item">
              <code>${example}</code>
              <button class="btn btn-sm btn-outline use-target" data-target="${example}">Use</button>
            </div>
          `).join('')}
        </div>
      </div>
      
      <div class="module-test-cases">
        <h3>Attack Types</h3>
        <div class="test-cases-list">
          ${data.testCases.map(testCase => `
            <div class="test-case">
              <h4>${testCase.name}</h4>
              <p>${testCase.description}</p>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;
}

function generatePathTraversalModuleContent(data) {
  return `
    <div class="container">
      <div class="section-header">
        <h2>${data.title}</h2>
        <p class="section-description">${data.description}</p>
      </div>
      
      <div class="module-instructions">
        <h3>Instructions</h3>
        <p>${data.instructions}</p>
      </div>
      
      <div class="module-content">
        <div class="test-panel">
          <h3>Test Path Traversal</h3>
          <div class="form-group">
            <label for="path-target">Target URL</label>
            <input type="text" id="path-target" class="form-control" placeholder="https://example.com/download.php?file=">
          </div>
          <div class="form-group">
            <label for="path-filename">File Path</label>
            <input type="text" id="path-filename" class="form-control" placeholder="../../../etc/passwd">
          </div>
          <button id="path-submit" class="btn btn-primary">Test Vulnerability</button>
        </div>
        
        <div id="path-result" class="result-box" style="display: none;">
          <div class="result-header">
            <i class="fas fa-check-circle text-success"></i>
            <h3 class="result-title">Path Traversal Successful!</h3>
          </div>
          <div class="result-content">
            <h4>File Content</h4>
            <pre id="path-file-content" class="code-block">root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...</pre>
          </div>
        </div>
      </div>
      
      <div class="module-examples">
        <h3>Example Payloads</h3>
        <div class="examples-list">
          ${data.examples.map(example => `
            <div class="example-item">
              <code>${example}</code>
              <button class="btn btn-sm btn-outline use-example" data-payload="${example}">Use</button>
            </div>
          `).join('')}
        </div>
      </div>
      
      <div class="module-test-cases">
        <h3>Common Test Cases</h3>
        <div class="test-cases-list">
          ${data.testCases.map(testCase => `
            <div class="test-case">
              <h4>${testCase.name}</h4>
              <p>${testCase.description}</p>
              <div class="payload">
                <code>${testCase.payload}</code>
                <button class="btn btn-sm btn-outline use-test-case" data-payload="${testCase.payload}">Use</button>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;
}

function generateCommandInjectionModuleContent(data) {
  return `
    <div class="container">
      <div class="section-header">
        <h2>${data.title}</h2>
        <p class="section-description">${data.description}</p>
      </div>
      
      <div class="module-instructions">
        <h3>Instructions</h3>
        <p>${data.instructions}</p>
      </div>
      
      <div class="module-content">
        <div class="test-panel">
          <h3>Test Command Injection</h3>
          <div class="form-group">
            <label for="command-target">Target URL</label>
            <input type="text" id="command-target" class="form-control" placeholder="https://example.com/ping.php?host=">
          </div>
          <div class="form-group">
            <label for="command-host">Host/Command</label>
            <input type="text" id="command-host" class="form-control" placeholder="8.8.8.8; cat /etc/passwd">
          </div>
          <button id="command-submit" class="btn btn-primary">Test Vulnerability</button>
        </div>
        
        <div id="command-result" class="result-box" style="display: none;">
          <div class="result-header">
            <i class="fas fa-check-circle text-success"></i>
            <h3 class="result-title">Command Injection Successful!</h3>
          </div>
          <div class="result-content">
            <h4>Command Output</h4>
            <pre id="command-output" class="code-block">PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=56 time=8.127 ms
64 bytes from 8.8.8.8: icmp_seq=1 ttl=56 time=8.123 ms

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...</pre>
          </div>
        </div>
      </div>
      
      <div class="module-examples">
        <h3>Example Payloads</h3>
        <div class="examples-list">
          ${data.examples.map(example => `
            <div class="example-item">
              <code>${example}</code>
              <button class="btn btn-sm btn-outline use-example" data-payload="${example}">Use</button>
            </div>
          `).join('')}
        </div>
      </div>
      
      <div class="module-test-cases">
        <h3>Common Test Cases</h3>
        <div class="test-cases-list">
          ${data.testCases.map(testCase => `
            <div class="test-case">
              <h4>${testCase.name}</h4>
              <p>${testCase.description}</p>
              <div class="payload">
                <code>${testCase.payload}</code>
                <button class="btn btn-sm btn-outline use-test-case" data-payload="${testCase.payload}">Use</button>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;
}

function generateScannerModuleContent(data) {
  return `
    <div class="container">
      <div class="section-header">
        <h2>${data.title}</h2>
        <p class="section-description">${data.description}</p>
      </div>
      
      <div class="module-instructions">
        <h3>Instructions</h3>
        <p>${data.instructions}</p>
      </div>
      
      <div class="module-content">
        <div class="test-panel">
          <h3>Vulnerability Scanner</h3>
          <div class="form-group">
            <label for="scan-target">Target URL/IP</label>
            <input type="text" id="scan-target" class="form-control" placeholder="https://example.com">
          </div>
          <div class="form-group">
            <label>Scan Type</label>
            <div class="scan-types">
              ${data.scanTypes.map((type, index) => `
                <div class="scan-type-option">
                  <input type="radio" id="scan-type-${index}" name="scan-type" value="${type.name}" ${index === 0 ? 'checked' : ''}>
                  <label for="scan-type-${index}">
                    <span class="scan-type-name">${type.name}</span>
                    <span class="scan-type-duration">${type.duration}</span>
                    <p class="scan-type-description">${type.description}</p>
                  </label>
                </div>
              `).join('')}
            </div>
          </div>
          <button id="scan-btn" class="btn btn-primary">Start Scan</button>
        </div>
        
        <div id="scan-result" class="result-box" style="display: none;">
          <div class="result-header">
            <i class="fas fa-spinner fa-spin"></i>
            <h3 class="result-title">Scanning in Progress</h3>
          </div>
          <div class="result-content">
            <div class="progress-container">
              <div id="scan-progress" class="progress-bar" style="width: 0%;">0%</div>
            </div>
            <p id="scan-status">Initializing scan...</p>
          </div>
        </div>
        
        <div id="scan-complete" class="result-box success" style="display: none;">
          <div class="result-header">
            <i class="fas fa-check-circle text-success"></i>
            <h3 class="result-title">Scan Complete</h3>
          </div>
          <div class="result-content">
            <div id="scan-summary" class="scan-summary">
              <div class="summary-item">
                <span class="summary-label">Target:</span>
                <span class="summary-value" id="summary-target">https://example.com</span>
              </div>
              <div class="summary-item">
                <span class="summary-label">Scan Duration:</span>
                <span class="summary-value" id="summary-duration">2m 34s</span>
              </div>
              <div class="summary-item">
                <span class="summary-label">Vulnerabilities Found:</span>
                <span class="summary-value" id="summary-vulns">5</span>
              </div>
              <div class="summary-item">
                <span class="summary-label">Risk Level:</span>
                <span class="summary-value risk-high" id="summary-risk">High</span>
              </div>
            </div>
            
            <h4>Findings</h4>
            <div id="scan-findings" class="scan-findings">
              <!-- Findings will be populated here -->
            </div>
          </div>
        </div>
      </div>
      
      <div class="module-vulnerability-types">
        <h3>Vulnerability Types Detected</h3>
        <div class="vulnerability-types-list">
          ${data.vulnerabilityTypes.map(type => `
            <div class="vulnerability-type">
              <span class="vulnerability-type-name">${type}</span>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;
}

// Function to initialize module-specific handlers
function initializeModuleHandlers(moduleId) {
  switch (moduleId) {
    case 'sql-injection':
      initializeSqlModule();
      break;
    case 'xss':
      initializeXssModule();
      break;
    case 'brute-force':
      initializeBruteForceModule();
      break;
    case 'path-traversal':
      initializePathTraversalModule();
      break;
    case 'command-injection':
      initializeCommandInjectionModule();
      break;
    case 'scanner':
      initializeScannerModule();
      break;
  }
}

// Module-specific initializers
function initializeSqlModule() {
  const sqlSubmitBtn = document.getElementById("sql-submit");
  const sqlTargetInput = document.getElementById("sql-target");
  const sqlUsernameInput = document.getElementById("sql-username");
  const sqlPasswordInput = document.getElementById("sql-password");
  const sqlResultBox = document.getElementById("sql-result");
  const sqlQueryResult = document.getElementById("sql-query-result");
  
  // Example buttons
  const useExampleBtns = document.querySelectorAll('.sql-injection .use-example');
  useExampleBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      sqlUsernameInput.value = btn.dataset.payload;
    });
  });
  
  // Test case buttons
  const useTestCaseBtns = document.querySelectorAll('.sql-injection .use-test-case');
  useTestCaseBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      sqlUsernameInput.value = btn.dataset.payload;
    });
  });
  
  if (sqlSubmitBtn) {
    sqlSubmitBtn.addEventListener("click", async () => {
      const target = sqlTargetInput.value;
      const username = sqlUsernameInput.value;
      const password = sqlPasswordInput.value;
    
      if (!target || !username) {
        showNotification("Target URL and username are required", "warning");
        return;
      }
    
      if (sqlResultBox) sqlResultBox.style.display = "none";
      dashboardStats.tests++;
    
      try {
        // Simulate SQL injection test
        const success = username.includes("'") || username.includes("--") || username.includes("=");
        const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
        
        if (success) {
          if (sqlResultBox) {
            sqlResultBox.className = "result-box success";
            sqlResultBox.querySelector(".result-title").textContent = "SQL Injection Successful!";
            sqlResultBox.querySelector(".result-header i").className = "fas fa-check-circle text-success";
            if (sqlQueryResult) sqlQueryResult.textContent = query;
            sqlResultBox.style.display = "block";
          }
          
          showNotification("SQL Injection test successful!", "success");
          logActivity("SQL Test Success", `Target: ${target}, Payload: ${username}`, "fa-database", "success");
          dashboardStats.vulns++;
          dashboardStats.sql++;
          
          // Save result to backend if logged in
          if (currentUser) {
            try {
              await fetchAPI("/scan/sql", {
                method: "POST",
                body: JSON.stringify({ 
                  target, 
                  payload: username,
                  result: "Successful SQL injection",
                  vulnerabilities_found: 1
                }),
              });
            } catch (error) {
              console.error("Error saving scan result:", error);
            }
          }
        } else {
          if (sqlResultBox) {
            sqlResultBox.className = "result-box error";
            sqlResultBox.querySelector(".result-title").textContent = "SQL Injection Failed";
            sqlResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
            if (sqlQueryResult) sqlQueryResult.textContent = "No SQL injection vulnerability detected";
            sqlResultBox.style.display = "block";
          }
          
          showNotification("SQL Injection test failed or no vulnerability found", "info");
          logActivity("SQL Test Failed", `Target: ${target}, Payload: ${username}`, "fa-database", "info");
          
          // Save result to backend if logged in
          if (currentUser) {
            try {
              await fetchAPI("/scan/sql", {
                method: "POST",
                body: JSON.stringify({ 
                  target, 
                  payload: username,
                  result: "No SQL injection vulnerability detected",
                  vulnerabilities_found: 0
                }),
              });
            } catch (error) {
              console.error("Error saving scan result:", error);
            }
          }
        }
      } catch (error) {
        if (sqlResultBox) {
          sqlResultBox.className = "result-box error";
          sqlResultBox.querySelector(".result-title").textContent = "SQL Injection Error";
          sqlResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
          if (sqlQueryResult) sqlQueryResult.textContent = `Error: ${error.message}`;
          sqlResultBox.style.display = "block";
        }
        
        showNotification(`Error: ${error.message}`, "error");
        logActivity("SQL Test Error", `Target: ${target}, Error: ${error.message}`, "fa-database", "error");
      }
      
      updateDashboardStats();
    });
  }
}

function initializeXssModule() {
  // Similar implementation for XSS module
  const xssSubmitBtn = document.getElementById("xss-submit");
  if (xssSubmitBtn) {
    xssSubmitBtn.addEventListener("click", async () => {
      // XSS test implementation
      const target = document.getElementById("xss-target")?.value;
      const name = document.getElementById("xss-name")?.value;
      const comment = document.getElementById("xss-comment")?.value;
      const xssResultBox = document.getElementById("xss-result");
      const xssCommentPreview = document.getElementById("xss-comment-preview");
      
      if (!target || !comment) {
        showNotification("Target URL and comment are required", "warning");
        return;
      }
      
      if (xssResultBox) xssResultBox.style.display = "none";
      dashboardStats.tests++;
      
      try {
        // Simulate XSS test
        const success = comment.includes("<script>") || 
                       comment.includes("onerror") || 
                       comment.includes("onclick") || 
                       comment.includes("onload");
        
        if (success) {
          if (xssResultBox) {
            xssResultBox.className = "result-box success";
            xssResultBox.querySelector(".result-title").textContent = "XSS Vulnerability Detected!";
            xssResultBox.querySelector(".result-header i").className = "fas fa-check-circle text-success";
            if (xssCommentPreview) xssCommentPreview.textContent = comment;
            xssResultBox.style.display = "block";
          }
          
          showNotification("XSS vulnerability detected!", "success");
          logActivity("XSS Test Success", `Target: ${target}, Payload: ${comment.substring(0, 30)}...`, "fa-code", "success");
          dashboardStats.vulns++;
          dashboardStats.xss++;
          
          // Save result to backend if logged in
          if (currentUser) {
            try {
              await fetchAPI("/scan/xss", {
                method: "POST",
                body: JSON.stringify({ 
                  target, 
                  payload: comment,
                  result: "XSS vulnerability detected",
                  vulnerabilities_found: 1
                }),
              });
            } catch (error) {
              console.error("Error saving scan result:", error);
            }
          }
        } else {
          if (xssResultBox) {
            xssResultBox.className = "result-box error";
            xssResultBox.querySelector(".result-title").textContent = "XSS Test Failed";
            xssResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
            if (xssCommentPreview) xssCommentPreview.textContent = "No XSS vulnerability detected";
            xssResultBox.style.display = "block";
          }
          
          showNotification("XSS test failed or no vulnerability found", "info");
          logActivity("XSS Test Failed", `Target: ${target}, Payload: ${comment.substring(0, 30)}...`, "fa-code", "info");
          
          // Save result to backend if logged in
          if (currentUser) {
            try {
              await fetchAPI("/scan/xss", {
                method: "POST",
                body: JSON.stringify({ 
                  target, 
                  payload: comment,
                  result: "No XSS vulnerability detected",
                  vulnerabilities_found: 0
                }),
              });
            } catch (error) {
              console.error("Error saving scan result:", error);
            }
          }
        }
      } catch (error) {
        if (xssResultBox) {
          xssResultBox.className = "result-box error";
          xssResultBox.querySelector(".result-title").textContent = "XSS Test Error";
          xssResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
          if (xssCommentPreview) xssCommentPreview.textContent = `Error: ${error.message}`;
          xssResultBox.style.display = "block";
        }
        
        showNotification(`Error: ${error.message}`, "error");
        logActivity("XSS Test Error", `Target: ${target}, Error: ${error.message}`, "fa-code", "error");
      }
      
      updateDashboardStats();
    });
  }
  
  // Example buttons
  const useExampleBtns = document.querySelectorAll('.xss .use-example');
  useExampleBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const xssCommentInput = document.getElementById("xss-comment");
      if (xssCommentInput) xssCommentInput.value = btn.dataset.payload;
    });
  });
  
  // Test case buttons
  const useTestCaseBtns = document.querySelectorAll('.xss .use-test-case');
  useTestCaseBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const xssCommentInput = document.getElementById("xss-comment");
      if (xssCommentInput) xssCommentInput.value = btn.dataset.payload;
    });
  });
}

function initializeBruteForceModule() {
  // Implementation for Brute Force module
  const bruteSubmitBtn = document.getElementById("brute-submit");
  if (bruteSubmitBtn) {
    bruteSubmitBtn.addEventListener("click", async () => {
      // Brute force test implementation
      const target = document.getElementById("brute-target")?.value;
      const username = document.getElementById("brute-username")?.value;
      const passwordsText = document.getElementById("brute-passwords")?.value;
      const bruteResultBox = document.getElementById("brute-result");
      const bruteResultUsername = document.getElementById("brute-result-username");
      const bruteResultPassword = document.getElementById("brute-result-password");
      const bruteResultAttempts = document.getElementById("brute-result-attempts");
      
      if (!target || !username || !passwordsText) {
        showNotification("Target URL, username, and passwords are required", "warning");
        return;
      }
      
      const passwords = passwordsText.split("\n").filter(p => p.trim() !== "");
      if (passwords.length === 0) {
        showNotification("At least one password is required", "warning");
        return;
      }
      
      if (bruteResultBox) bruteResultBox.style.display = "none";
      dashboardStats.tests++;
      
      try {
        // Simulate brute force test
        let found = false;
        let foundPassword = "";
        let attempts = 0;
        
        // For demo purposes, consider some common passwords as "successful"
        const commonPasswords = ["admin123", "password123", "123456", "qwerty", "letmein"];
        
        for (const password of passwords) {
          attempts++;
          
          // Simulate a small delay to show progress
          await new Promise(resolve => setTimeout(resolve, 100));
          
          // Check if password is in our list of "successful" passwords
          if (commonPasswords.includes(password.toLowerCase())) {
            found = true;
            foundPassword = password;
            break;
          }
          
          // For demo purposes, if username is "admin" and password contains "admin", consider it successful
          if (username.toLowerCase() === "admin" && password.toLowerCase().includes("admin")) {
            found = true;
            foundPassword = password;
            break;
          }
        }
        
        if (found) {
          if (bruteResultBox) {
            bruteResultBox.className = "result-box success";
            bruteResultBox.querySelector(".result-title").textContent = "Password Cracked!";
            bruteResultBox.querySelector(".result-header i").className = "fas fa-check-circle text-success";
            if (bruteResultUsername) bruteResultUsername.textContent = username;
            if (bruteResultPassword) bruteResultPassword.textContent = foundPassword;
            if (bruteResultAttempts) bruteResultAttempts.textContent = attempts.toString();
            bruteResultBox.style.display = "block";
          }
          
          showNotification("Brute force attack successful!", "success");
          logActivity("Brute Force Success", `Target: ${target}, User: ${username}, Attempts: ${attempts}`, "fa-key", "success");
          dashboardStats.vulns++;
          dashboardStats.brute++;
          
          // Save result to backend if logged in
          if (currentUser) {
            try {
              await fetchAPI("/scan/brute-force", {
                method: "POST",
                body: JSON.stringify({ 
                  target, 
                  username,
                  result: `Password found: ${foundPassword} after ${attempts} attempts`,
                  vulnerabilities_found: 1
                }),
              });
            } catch (error) {
              console.error("Error saving scan result:", error);
            }
          }
        } else {
          if (bruteResultBox) {
            bruteResultBox.className = "result-box error";
            bruteResultBox.querySelector(".result-title").textContent = "Brute Force Failed";
            bruteResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
            if (bruteResultUsername) bruteResultUsername.textContent = username;
            if (bruteResultPassword) bruteResultPassword.textContent = "Password not found in list";
            if (bruteResultAttempts) bruteResultAttempts.textContent = attempts.toString();
            bruteResultBox.style.display = "block";
          }
          
          showNotification("Brute force attack failed", "info");
          logActivity("Brute Force Failed", `Target: ${target}, User: ${username}, Attempts: ${attempts}`, "fa-key", "info");
          
          // Save result to backend if logged in
          if (currentUser) {
            try {
              await fetchAPI("/scan/brute-force", {
                method: "POST",
                body: JSON.stringify({ 
                  target, 
                  username,
                  result: `No password found after ${attempts} attempts`,
                  vulnerabilities_found: 0
                }),
              });
            } catch (error) {
              console.error("Error saving scan result:", error);
            }
          }
        }
      } catch (error) {
        if (bruteResultBox) {
          bruteResultBox.className = "result-box error";
          bruteResultBox.querySelector(".result-title").textContent = "Brute Force Error";
          bruteResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
          if (bruteResultUsername) bruteResultUsername.textContent = username;
          if (bruteResultPassword) bruteResultPassword.textContent = `Error: ${error.message}`;
          if (bruteResultAttempts) bruteResultAttempts.textContent = "N/A";
          bruteResultBox.style.display = "block";
        }
        
        showNotification(`Error: ${error.message}`, "error");
        logActivity("Brute Force Error", `Target: ${target}, Error: ${error.message}`, "fa-key", "error");
      }
      
      updateDashboardStats();
    });
  }
  
  // Target example buttons
  const useTargetBtns = document.querySelectorAll('.brute-force .use-target');
  useTargetBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const bruteTargetInput = document.getElementById("brute-target");
      if (bruteTargetInput) bruteTargetInput.value = btn.dataset.target;
    });
  });
}

function initializePathTraversalModule() {
  // Implementation for Path Traversal module
  const pathSubmitBtn = document.getElementById("path-submit");
  if (pathSubmitBtn) {
    pathSubmitBtn.addEventListener("click", async () => {
      // Path traversal test implementation
      const target = document.getElementById("path-target")?.value;
      const filename = document.getElementById("path-filename")?.value;
      const pathResultBox = document.getElementById("path-result");
      const pathFileContent = document.getElementById("path-file-content");
      
      if (!target || !filename) {
        showNotification("Target URL and filename are required", "warning");
        return;
      }
      
      if (pathResultBox) pathResultBox.style.display = "none";
      dashboardStats.tests++;
      
      try {
        // Simulate path traversal test
        const success = filename.includes("../") || 
                       filename.includes("..\\") || 
                       filename.includes("%2e%2e") || 
                       filename.includes("file:");
        
        let content = "Access denied or file not found.";
        
        if (success) {
          // Simulate finding sensitive files
          if (filename.includes("etc/passwd") || filename.includes("passwd")) {
            content = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
... (simulated /etc/passwd content)`;
          } else if (filename.includes("windows") || filename.includes("system.ini")) {
            content = `; for 16-bit app support
[386Enh]
woafont=dosapp.fon
EGA80WOA.FON=EGA80WOA.FON
EGA40WOA.FON=EGA40WOA.FON
CGA80WOA.FON=CGA80WOA.FON
CGA40WOA.FON=CGA40WOA.FON

[drivers]
wave=mmdrv.dll
timer=timer.drv

[mci]
... (simulated system.ini content)`;
          } else {
            content = `Simulated content for file: ${filename}
This is a simulated file content for demonstration purposes.
Path traversal vulnerability detected!`;
          }
          
          if (pathResultBox) {
            pathResultBox.className = "result-box success";
            pathResultBox.querySelector(".result-title").textContent = "Path Traversal Successful!";
            pathResultBox.querySelector(".result-header i").className = "fas fa-check-circle text-success";
            if (pathFileContent) pathFileContent.textContent = content;
            pathResultBox.style.display = "block";
          }
          
          showNotification("Path traversal vulnerability detected!", "success");
          logActivity("Path Traversal Success", `Target: ${target}, Payload: ${filename}`, "fa-folder-open", "success");
          dashboardStats.vulns++;
          dashboardStats.path++;
          
          // Save result to backend if logged in
          if (currentUser) {
            try {
              await fetchAPI("/scan/path-traversal", {
                method: "POST",
                body: JSON.stringify({ 
                  target, 
                  payload: filename,
                  result: "Path traversal vulnerability detected",
                  vulnerabilities_found: 1
                }),
              });
            } catch (error) {
              console.error("Error saving scan result:", error);
            }
          }
        } else {
          if (pathResultBox) {
            pathResultBox.className = "result-box error";
            pathResultBox.querySelector(".result-title").textContent = "Path Traversal Failed";
            pathResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
            if (pathFileContent) pathFileContent.textContent = content;
            pathResultBox.style.display = "block";
          }
          
          showNotification("Path traversal test failed or no vulnerability found", "info");
          logActivity("Path Traversal Failed", `Target: ${target}, Payload: ${filename}`, "fa-folder-open", "info");
          
          // Save result to backend if logged in
          if (currentUser) {
            try {
              await fetchAPI("/scan/path-traversal", {
                method: "POST",
                body: JSON.stringify({ 
                  target, 
                  payload: filename,
                  result: "No path traversal vulnerability detected",
                  vulnerabilities_found: 0
                }),
              });
            } catch (error) {
              console.error("Error saving scan result:", error);
            }
          }
        }
      } catch (error) {
        if (pathResultBox) {
          pathResultBox.className = "result-box error";
          pathResultBox.querySelector(".result-title").textContent = "Path Traversal Error";
          pathResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
          if (pathFileContent) pathFileContent.textContent = `Error: ${error.message}`;
          pathResultBox.style.display = "block";
        }
        
        showNotification(`Error: ${error.message}`, "error");
        logActivity("Path Traversal Error", `Target: ${target}, Error: ${error.message}`, "fa-folder-open", "error");
      }
      
      updateDashboardStats();
    });
  }
  
  // Example buttons
  const useExampleBtns = document.querySelectorAll('.path-traversal .use-example');
  useExampleBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const pathFilenameInput = document.getElementById("path-filename");
      if (pathFilenameInput) pathFilenameInput.value = btn.dataset.payload;
    });
  });
  
  // Test case buttons
  const useTestCaseBtns = document.querySelectorAll('.path-traversal .use-test-case');
  useTestCaseBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const pathFilenameInput = document.getElementById("path-filename");
      if (pathFilenameInput) pathFilenameInput.value = btn.dataset.payload;
    });
  });
}

function initializeCommandInjectionModule() {
  // Implementation for Command Injection module
  const commandSubmitBtn = document.getElementById("command-submit");
  if (commandSubmitBtn) {
    commandSubmitBtn.addEventListener("click", async () => {
      // Command injection test implementation
      const target = document.getElementById("command-target")?.value;
      const host = document.getElementById("command-host")?.value;
      const commandResultBox = document.getElementById("command-result");
      const commandOutput = document.getElementById("command-output");
      
      if (!target || !host) {
        showNotification("Target URL and host/command are required", "warning");
        return;
      }
      
      if (commandResultBox) commandResultBox.style.display = "none";
      dashboardStats.tests++;
      
      try {
        // Simulate command injection test
        const success = host.includes(';') || 
                       host.includes('|') || 
                       host.includes('&') || 
                       host.includes('`') || 
                       host.includes('$(');
        
        let output = `Pinging ${host.split(';')[0].split('|')[0].split('&')[0]}...\nRequest timed out.`;
        
        if (success) {
          // Simulate output for common commands
          if (host.includes('ls') || host.includes('dir')) {
            output = `Simulating ping for ${host.split(';')[0].split('|')[0].split('&')[0]}...\n
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=56 time=8.127 ms

Simulated directory listing:
total 0
drwxr-xr-x 1 user group 0 May 25 02:00 .
drwxr-xr-x 1 user group 0 May 25 01:00 ..
-rw-r--r-- 1 user group 0 May 25 02:00 file1.txt
-rw-r--r-- 1 user group 0 May 25 02:00 file2.log
-rw-r--r-- 1 user group 0 May 25 02:00 config.php
-rw-r--r-- 1 user group 0 May 25 02:00 .env`;
          } else if (host.includes('id') || host.includes('whoami')) {
            output = `Simulating ping for ${host.split(';')[0].split('|')[0].split('&')[0]}...\n
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=56 time=8.127 ms

Simulated command output:
uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)`;
          } else if (host.includes('cat') || host.includes('type')) {
            output = `Simulating ping for ${host.split(';')[0].split('|')[0].split('&')[0]}...\n
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=56 time=8.127 ms

Simulated file content:
# Server Configuration
DB_HOST=localhost
DB_USER=admin
DB_PASS=supersecretpassword123
API_KEY=ak_live_12345abcdef
DEBUG_MODE=true`;
          } else {
            output = `Simulating ping for ${host.split(';')[0].split('|')[0].split('&')[0]}...\n
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=56 time=8.127 ms

Simulated output for injected command: ${host}
Command injection vulnerability detected!`;
          }
          
          if (commandResultBox) {
            commandResultBox.className = "result-box success";
            commandResultBox.querySelector(".result-title").textContent = "Command Injection Successful!";
            commandResultBox.querySelector(".result-header i").className = "fas fa-check-circle text-success";
            if (commandOutput) commandOutput.textContent = output;
            commandResultBox.style.display = "block";
          }
          
          showNotification("Command injection vulnerability detected!", "success");
          logActivity("Command Injection Success", `Target: ${target}, Payload: ${host}`, "fa-terminal", "success");
          dashboardStats.vulns++;
          dashboardStats.command++;
          
          // Save result to backend if logged in
          if (currentUser) {
            try {
              await fetchAPI("/scan/command-injection", {
                method: "POST",
                body: JSON.stringify({ 
                  target, 
                  payload: host,
                  result: "Command injection vulnerability detected",
                  vulnerabilities_found: 1
                }),
              });
            } catch (error) {
              console.error("Error saving scan result:", error);
            }
          }
        } else {
          if (commandResultBox) {
            commandResultBox.className = "result-box error";
            commandResultBox.querySelector(".result-title").textContent = "Command Injection Failed";
            commandResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
            if (commandOutput) commandOutput.textContent = output;
            commandResultBox.style.display = "block";
          }
          
          showNotification("Command injection test failed or no vulnerability found", "info");
          logActivity("Command Injection Failed", `Target: ${target}, Payload: ${host}`, "fa-terminal", "info");
          
          // Save result to backend if logged in
          if (currentUser) {
            try {
              await fetchAPI("/scan/command-injection", {
                method: "POST",
                body: JSON.stringify({ 
                  target, 
                  payload: host,
                  result: "No command injection vulnerability detected",
                  vulnerabilities_found: 0
                }),
              });
            } catch (error) {
              console.error("Error saving scan result:", error);
            }
          }
        }
      } catch (error) {
        if (commandResultBox) {
          commandResultBox.className = "result-box error";
          commandResultBox.querySelector(".result-title").textContent = "Command Injection Error";
          commandResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
          if (commandOutput) commandOutput.textContent = `Error: ${error.message}`;
          commandResultBox.style.display = "block";
        }
        
        showNotification(`Error: ${error.message}`, "error");
        logActivity("Command Injection Error", `Target: ${target}, Error: ${error.message}`, "fa-terminal", "error");
      }
      
      updateDashboardStats();
    });
  }
  
  // Example buttons
  const useExampleBtns = document.querySelectorAll('.command-injection .use-example');
  useExampleBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const commandHostInput = document.getElementById("command-host");
      if (commandHostInput) commandHostInput.value = btn.dataset.payload;
    });
  });
  
  // Test case buttons
  const useTestCaseBtns = document.querySelectorAll('.command-injection .use-test-case');
  useTestCaseBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const commandHostInput = document.getElementById("command-host");
      if (commandHostInput) commandHostInput.value = btn.dataset.payload;
    });
  });
}

function initializeScannerModule() {
  // Implementation for Scanner module
  const scanBtn = document.getElementById("scan-btn");
  if (scanBtn) {
    scanBtn.addEventListener("click", async () => {
      // Scanner implementation
      const target = document.getElementById("scan-target")?.value;
      const scanTypeInputs = document.querySelectorAll('input[name="scan-type"]');
      const scanResultBox = document.getElementById("scan-result");
      const scanCompleteBox = document.getElementById("scan-complete");
      const scanProgress = document.getElementById("scan-progress");
      const scanStatus = document.getElementById("scan-status");
      
      let scanType = "Quick Scan"; // Default
      scanTypeInputs.forEach(input => {
        if (input.checked) {
          scanType = input.value;
        }
      });
      
      if (!target) {
        showNotification("Target URL/IP is required", "warning");
        return;
      }
      
      // Hide complete box and show progress box
      if (scanCompleteBox) scanCompleteBox.style.display = "none";
      if (scanResultBox) {
        scanResultBox.style.display = "block";
        scanResultBox.querySelector(".result-title").textContent = "Scanning in Progress";
        scanResultBox.querySelector(".result-header i").className = "fas fa-spinner fa-spin";
      }
      
      dashboardStats.tests++;
      
      try {
        // Simulate scanning process
        const scanDuration = scanType === "Quick Scan" ? 5 : (scanType === "Full Scan" ? 15 : 10);
        const steps = 10;
        const stepTime = (scanDuration * 1000) / steps;
        
        for (let i = 1; i <= steps; i++) {
          await new Promise(resolve => setTimeout(resolve, stepTime));
          const progress = Math.round((i / steps) * 100);
          
          if (scanProgress) {
            scanProgress.style.width = `${progress}%`;
            scanProgress.textContent = `${progress}%`;
          }
          
          if (scanStatus) {
            const statusMessages = [
              "Initializing scan...",
              "Performing port scan...",
              "Checking for open services...",
              "Testing for SQL injection vulnerabilities...",
              "Testing for XSS vulnerabilities...",
              "Testing for CSRF vulnerabilities...",
              "Checking for outdated software...",
              "Testing for path traversal vulnerabilities...",
              "Testing for command injection vulnerabilities...",
              "Finalizing scan results..."
            ];
            
            scanStatus.textContent = statusMessages[i - 1];
          }
        }
        
        // Generate random number of vulnerabilities (1-8)
        const vulnsFound = Math.floor(Math.random() * 8) + 1;
        
        // Hide progress box and show complete box
        if (scanResultBox) scanResultBox.style.display = "none";
        if (scanCompleteBox) {
          scanCompleteBox.style.display = "block";
          
          // Update summary
          document.getElementById("summary-target").textContent = target;
          document.getElementById("summary-duration").textContent = `${scanDuration}s`;
          document.getElementById("summary-vulns").textContent = vulnsFound.toString();
          
          // Set risk level based on vulnerabilities found
          const riskLevel = vulnsFound <= 2 ? "Low" : (vulnsFound <= 5 ? "Medium" : "High");
          const summaryRisk = document.getElementById("summary-risk");
          if (summaryRisk) {
            summaryRisk.textContent = riskLevel;
            summaryRisk.className = `summary-value risk-${riskLevel.toLowerCase()}`;
          }
          
          // Generate findings
          const findingsContainer = document.getElementById("scan-findings");
          if (findingsContainer) {
            findingsContainer.innerHTML = "";
            
            // Possible vulnerabilities to show
            const vulnerabilities = [
              { name: "SQL Injection", severity: "High", description: "SQL injection vulnerability found in login form" },
              { name: "Cross-Site Scripting (XSS)", severity: "Medium", description: "Reflected XSS vulnerability in search parameter" },
              { name: "Insecure Direct Object References", severity: "High", description: "User IDs can be manipulated to access other user data" },
              { name: "Cross-Site Request Forgery", severity: "Medium", description: "No CSRF tokens implemented in forms" },
              { name: "Security Misconfiguration", severity: "Low", description: "Server information disclosure in HTTP headers" },
              { name: "Broken Authentication", severity: "High", description: "Weak password policy allows simple passwords" },
              { name: "Sensitive Data Exposure", severity: "Medium", description: "Passwords transmitted in plaintext" },
              { name: "Missing Security Headers", severity: "Low", description: "Content-Security-Policy header not implemented" }
            ];
            
            // Shuffle and take random vulnerabilities
            const shuffled = [...vulnerabilities].sort(() => 0.5 - Math.random());
            const selected = shuffled.slice(0, vulnsFound);
            
            // Add findings to container
            selected.forEach(vuln => {
              const finding = document.createElement("div");
              finding.className = "finding-item";
              finding.innerHTML = `
                <div class="finding-header">
                  <h4 class="finding-name">${vuln.name}</h4>
                  <span class="finding-severity severity-${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                </div>
                <p class="finding-description">${vuln.description}</p>
              `;
              findingsContainer.appendChild(finding);
            });
          }
        }
        
        showNotification(`Scan completed! Found ${vulnsFound} vulnerabilities.`, "success");
        logActivity("Scan Complete", `Target: ${target}, Type: ${scanType}, Vulnerabilities: ${vulnsFound}`, "fa-search", "success");
        dashboardStats.vulns += vulnsFound;
        dashboardStats.scan += vulnsFound;
        
        // Save result to backend if logged in
        if (currentUser) {
          try {
            await fetchAPI("/scan/full", {
              method: "POST",
              body: JSON.stringify({ 
                target, 
                scan_type: scanType,
                result: `Found ${vulnsFound} vulnerabilities`,
                vulnerabilities_found: vulnsFound
              }),
            });
          } catch (error) {
            console.error("Error saving scan result:", error);
          }
        }
      } catch (error) {
        if (scanResultBox) {
          scanResultBox.className = "result-box error";
          scanResultBox.querySelector(".result-title").textContent = "Scan Error";
          scanResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
          if (scanStatus) scanStatus.textContent = `Error: ${error.message}`;
          scanResultBox.style.display = "block";
        }
        
        showNotification(`Error: ${error.message}`, "error");
        logActivity("Scan Error", `Target: ${target}, Error: ${error.message}`, "fa-search", "error");
      }
      
      updateDashboardStats();
    });
  }
}
