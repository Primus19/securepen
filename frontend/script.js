// API base URL configuration
const API_BASE_URL = "http://ad0172da2bacb4726ab42e7c5a01cb87-3e410709a7cfeff6.elb.us-east-1.amazonaws.com/api"; // Updated to use absolute URL for production

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

const loginBtn = document.getElementById("login-btn");
const registerBtn = document.getElementById("register-btn");
const authButtons = document.querySelector(".auth-buttons");

const loginModal = document.getElementById("login-modal");
const registerModal = document.getElementById("register-modal");
const loginSubmit = document.getElementById("login-submit");
const registerSubmit = document.getElementById("register-submit");
const modalCloseBtns = document.querySelectorAll(".modal-close, .modal-close-btn");

// Dashboard elements
const testsCount = document.getElementById("tests-count");
const vulnsCount = document.getElementById("vulns-count");
const successRate = document.getElementById("success-rate");
const activityList = document.getElementById("activity-list");
const vulnerabilityChartCtx = document.getElementById("vulnerability-chart").getContext("2d");
let vulnerabilityChart;

// SQL Injection elements
const sqlTargetInput = document.getElementById("sql-target");
const sqlUsernameInput = document.getElementById("sql-username");
const sqlPasswordInput = document.getElementById("sql-password");
const sqlSubmitBtn = document.getElementById("sql-submit");
const sqlResultBox = document.getElementById("sql-result");
const sqlQueryResult = document.getElementById("sql-query-result");
const sqlGenType = document.getElementById("sql-gen-type");
const sqlGenDbms = document.getElementById("sql-gen-dbms");
const sqlGenColumn = document.getElementById("sql-gen-column");
const sqlGenBtn = document.getElementById("sql-gen-btn");
const sqlGenResultBox = document.getElementById("sql-gen-result");
const sqlGenPayload = document.getElementById("sql-gen-payload");
const sqlGenExplanation = document.getElementById("sql-gen-explanation");

// XSS elements
const xssTargetInput = document.getElementById("xss-target");
const xssNameInput = document.getElementById("xss-name");
const xssCommentInput = document.getElementById("xss-comment");
const xssSubmitBtn = document.getElementById("xss-submit");
const xssResultBox = document.getElementById("xss-result");
const xssCommentPreview = document.getElementById("xss-comment-preview");
const xssGenType = document.getElementById("xss-gen-type");
const xssGenContext = document.getElementById("xss-gen-context");
const xssGenGoal = document.getElementById("xss-gen-goal");
const xssGenBtn = document.getElementById("xss-gen-btn");
const xssGenResultBox = document.getElementById("xss-gen-result");
const xssGenPayload = document.getElementById("xss-gen-payload");
const xssGenExplanation = document.getElementById("xss-gen-explanation");

// Brute Force elements
const bruteTargetInput = document.getElementById("brute-target");
const bruteUsernameInput = document.getElementById("brute-username");
const brutePasswordsInput = document.getElementById("brute-passwords");
const bruteSubmitBtn = document.getElementById("brute-submit");
const bruteResultBox = document.getElementById("brute-result");
const bruteResultUsername = document.getElementById("brute-result-username");
const bruteResultPassword = document.getElementById("brute-result-password");
const bruteResultAttempts = document.getElementById("brute-result-attempts");
const bruteAiTargetInput = document.getElementById("brute-ai-target");
const bruteAiHintsInput = document.getElementById("brute-ai-hints");
const bruteAiComplexity = document.getElementById("brute-ai-complexity");
const bruteAiCountInput = document.getElementById("brute-ai-count");
const bruteAiGenerateBtn = document.getElementById("brute-ai-generate");
const bruteAiResultBox = document.getElementById("brute-ai-result");
const bruteAiPasswords = document.getElementById("brute-ai-passwords");
const bruteAiUseBtn = document.getElementById("brute-ai-use");

// Path Traversal elements
const pathTargetInput = document.getElementById("path-target");
const pathFilenameInput = document.getElementById("path-filename");
const pathSubmitBtn = document.getElementById("path-submit");
const pathResultBox = document.getElementById("path-result");
const pathFileContent = document.getElementById("path-file-content");
const pathGenOs = document.getElementById("path-gen-os");
const pathGenFile = document.getElementById("path-gen-file");
const pathGenCustomGroup = document.getElementById("path-gen-custom-group");
const pathGenCustomInput = document.getElementById("path-gen-custom");
const pathGenEncoding = document.getElementById("path-gen-encoding");
const pathGenBtn = document.getElementById("path-gen-btn");
const pathGenResultBox = document.getElementById("path-gen-result");
const pathGenPayload = document.getElementById("path-gen-payload");
const pathGenExplanation = document.getElementById("path-gen-explanation");

// Command Injection elements
const commandTargetInput = document.getElementById("command-target");
const commandHostInput = document.getElementById("command-host");
const commandSubmitBtn = document.getElementById("command-submit");
const commandResultBox = document.getElementById("command-result");
const commandOutput = document.getElementById("command-output");
const cmdGenOs = document.getElementById("cmd-gen-os");
const cmdGenGoal = document.getElementById("cmd-gen-goal");
const cmdGenCustomGroup = document.getElementById("cmd-gen-custom-group");
const cmdGenCustomInput = document.getElementById("cmd-gen-custom");
const cmdGenBypass = document.getElementById("cmd-gen-bypass");
const cmdGenBtn = document.getElementById("cmd-gen-btn");
const cmdGenResultBox = document.getElementById("cmd-gen-result");
const cmdGenPayload = document.getElementById("cmd-gen-payload");
const cmdGenExplanation = document.getElementById("cmd-gen-explanation");

// Scanner elements
const scanTargetInput = document.getElementById("scan-target");
const scanBtn = document.getElementById("scan-btn");
const scanResultBox = document.getElementById("scan-result");
const scanProgress = document.getElementById("scan-progress");
const scanStatus = document.getElementById("scan-status");
const scanCompleteBox = document.getElementById("scan-complete");
const scanSummary = document.getElementById("scan-summary");
const scanFindings = document.getElementById("scan-findings");
const vulnSearchInput = document.getElementById("vuln-search");
const vulnSearchBtn = document.getElementById("vuln-search-btn");
const vulnSearchResultBox = document.getElementById("vuln-search-result");
const vulnSearchFindings = document.getElementById("vuln-search-findings");

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
    showNotification(`Error: ${error.message}`, "error");
    throw error; // Re-throw the error for further handling if needed
  }
}

// Function to show notifications (replace with a proper notification system if needed)
function showNotification(message, type = "info") {
  console.log(`[${type.toUpperCase()}] ${message}`);
  // Basic alert for now, replace with a better UI element
  alert(`[${type.toUpperCase()}] ${message}`);
}

// Function to update dashboard stats
function updateDashboardStats() {
  testsCount.textContent = dashboardStats.tests;
  vulnsCount.textContent = dashboardStats.vulns;
  successRate.textContent =
    dashboardStats.tests > 0
      ? `${((dashboardStats.vulns / dashboardStats.tests) * 100).toFixed(0)}%`
      : "0%";

  // Update chart
  if (vulnerabilityChart) {
    vulnerabilityChart.data.datasets[0].data = [
      dashboardStats.sql,
      dashboardStats.xss,
      dashboardStats.brute,
      dashboardStats.path,
      dashboardStats.command,
      dashboardStats.scan, // Add scans to chart
    ];
    vulnerabilityChart.update();
  }
}

// Function to log activity on the dashboard
function logActivity(title, description, iconClass = "fa-info-circle", iconColor = "info") {
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
      <button id="login-btn" class="btn btn-outline">Login</button>
      <button id="register-btn" class="btn btn-primary">Register</button>
    `;
    document.getElementById("login-btn").addEventListener("click", () => openModal(loginModal));
    document.getElementById("register-btn").addEventListener("click", () => openModal(registerModal));
    // Reset stats when logged out
    dashboardStats = { tests: 0, vulns: 0, sql: 0, xss: 0, brute: 0, path: 0, command: 0, scan: 0 };
    updateDashboardStats();
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

// Function to fetch user stats and activity
async function fetchUserStats() {
  if (!currentUser) return;
  try {
    // In a real app, fetch stats from backend
    // For now, we just log that we would fetch
    console.log("Fetching user stats for", currentUser.username);
    // Example: Fetch activity logs
    const activityData = await fetchAPI("/user/activity");
    activityList.innerHTML = ""; // Clear existing logs
    if (activityData.logs && activityData.logs.length > 0) {
      activityData.logs.forEach(log => {
        logActivity(log.action, log.details, getActivityIcon(log.action), getActivityColor(log.action));
      });
    } else {
      logActivity("No activity yet", "Start testing to see your activity here.");
    }
    // Fetch scan results to populate dashboard (example)
    const scanData = await fetchAPI("/user/scans");
    dashboardStats = { tests: 0, vulns: 0, sql: 0, xss: 0, brute: 0, path: 0, command: 0, scan: 0 }; // Reset
    if (scanData.scans) {
      scanData.scans.forEach(scan => {
        dashboardStats.tests++;
        if (scan.severity !== 'Info' && scan.severity !== 'Low') { // Count significant vulns
          dashboardStats.vulns++;
          switch(scan.scan_type) {
            case 'SQL_INJECTION': dashboardStats.sql++; break;
            case 'XSS': dashboardStats.xss++; break;
            case 'BRUTE_FORCE': dashboardStats.brute++; break;
            case 'PATH_TRAVERSAL': dashboardStats.path++; break;
            case 'COMMAND_INJECTION': dashboardStats.command++; break;
            case 'SCANNER': dashboardStats.scan++; break; // Assuming scanner logs results
          }
        }
      });
    }
    updateDashboardStats();

  } catch (error) {
    console.error("Error fetching user stats:", error);
  }
}

function getActivityIcon(action) {
  switch (action) {
    case 'LOGIN': return 'fa-sign-in-alt';
    case 'REGISTER': return 'fa-user-plus';
    case 'SQL_TEST': return 'fa-database';
    case 'XSS_TEST': return 'fa-code';
    case 'BRUTE_TEST': return 'fa-key';
    case 'PATH_TEST': return 'fa-folder-open';
    case 'CMD_TEST': return 'fa-terminal';
    case 'SCAN_START': return 'fa-search';
    case 'SCAN_COMPLETE': return 'fa-check-circle';
    default: return 'fa-info-circle';
  }
}

function getActivityColor(action) {
  if (action.includes('TEST') || action.includes('SCAN')) return 'success';
  if (action.includes('LOGIN') || action.includes('REGISTER')) return 'primary';
  return 'info';
}

// Rest of the script.js content remains the same
// ...
