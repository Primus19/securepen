// API base URL configuration
const API_BASE_URL = "/api"; // Use relative path for same-origin requests

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

// ── Navigation ───────────────────────────────────────────────────

const sections = {
  dashboard: dashboardSection,
  scanner: scannerSection,
  "sql-injection": sqlSection,
  xss: xssSection,
  "brute-force": bruteSection,
  "path-traversal": pathSection,
  "command-injection": commandSection,
};

const navLinks = {
  dashboard: dashboardLink,
  scanner: scannerLink,
  "sql-injection": sqlLink,
  xss: xssLink,
  "brute-force": bruteLink,
  "path-traversal": pathLink,
  "command-injection": commandLink,
};

function navigateTo(sectionId) {
  // Hide all sections
  Object.values(sections).forEach((section) => {
    if (section) section.style.display = "none";
  });
  // Deactivate all nav links
  Object.values(navLinks).forEach((link) => {
    if (link) link.classList.remove("active");
  });

  // Show the target section
  if (sections[sectionId]) {
    sections[sectionId].style.display = "block";
  }
  // Activate the target nav link
  if (navLinks[sectionId]) {
    navLinks[sectionId].classList.add("active");
  }

  // Update URL hash
  window.location.hash = sectionId;

  // Special actions for dashboard
  if (sectionId === 'dashboard') {
    updateDashboardStats(); // Ensure stats are current
  }
}

// Event listeners for navigation
dashboardLink.addEventListener("click", (e) => { e.preventDefault(); navigateTo("dashboard"); });
scannerLink.addEventListener("click", (e) => { e.preventDefault(); navigateTo("scanner"); });
sqlLink.addEventListener("click", (e) => { e.preventDefault(); navigateTo("sql-injection"); });
xssLink.addEventListener("click", (e) => { e.preventDefault(); navigateTo("xss"); });
bruteLink.addEventListener("click", (e) => { e.preventDefault(); navigateTo("brute-force"); });
pathLink.addEventListener("click", (e) => { e.preventDefault(); navigateTo("path-traversal"); });
commandLink.addEventListener("click", (e) => { e.preventDefault(); navigateTo("command-injection"); });
document.getElementById('home-link').addEventListener('click', (e) => { e.preventDefault(); navigateTo('dashboard'); });
document.getElementById('get-started-btn')?.addEventListener('click', () => navigateTo('scanner'));

// Handle initial navigation based on hash or default to dashboard
function handleInitialNavigation() {
  const hash = window.location.hash.substring(1);
  if (hash && sections[hash]) {
    navigateTo(hash);
  } else {
    navigateTo("dashboard");
  }
}

// ── Modals ───────────────────────────────────────────────────────

function openModal(modal) {
  modal.style.display = "flex";
}

function closeModal(modal) {
  modal.style.display = "none";
}

modalCloseBtns.forEach((btn) => {
  btn.addEventListener("click", () => {
    closeModal(loginModal);
    closeModal(registerModal);
  });
});

window.addEventListener("click", (event) => {
  if (event.target === loginModal) {
    closeModal(loginModal);
  }
  if (event.target === registerModal) {
    closeModal(registerModal);
  }
});

// ── Authentication Handlers ────────────────────────────────────

async function handleLogin(event) {
  event.preventDefault();
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;

  if (!username || !password) {
    showNotification("Username and password are required.", "warning");
    return;
  }

  try {
    const data = await fetchAPI("/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });

    if (data.success) {
      currentToken = data.token; // Store token (in memory for this example)
      updateAuthState(data.user);
      closeModal(loginModal);
      showNotification("Login successful!", "success");
      logActivity("Login", `User ${username} logged in successfully.`, "fa-sign-in-alt", "primary");
      navigateTo('dashboard'); // Go to dashboard after login
    } else {
      showNotification(data.message || "Login failed.", "error");
    }
  } catch (error) {
    // Error already logged by fetchAPI
  }
}

async function handleRegister(event) {
  event.preventDefault();
  const username = document.getElementById("register-username").value;
  const email = document.getElementById("register-email").value;
  const password = document.getElementById("register-password").value;
  const confirmPassword = document.getElementById("register-confirm").value;

  if (!username || !email || !password || !confirmPassword) {
    showNotification("All fields are required.", "warning");
    return;
  }

  if (password !== confirmPassword) {
    showNotification("Passwords do not match.", "warning");
    return;
  }

  try {
    const data = await fetchAPI("/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password }),
    });

    if (data.success) {
      currentToken = data.token;
      updateAuthState(data.user);
      closeModal(registerModal);
      showNotification("Registration successful!", "success");
      logActivity("Register", `User ${username} registered successfully.`, "fa-user-plus", "primary");
      navigateTo('dashboard'); // Go to dashboard after registration
    } else {
      showNotification(data.message || "Registration failed.", "error");
    }
  } catch (error) {
    // Error already logged by fetchAPI
  }
}

async function handleLogout() {
  try {
    await fetchAPI("/logout", { method: "POST" });
    currentToken = null;
    document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;"; // Clear cookie
    updateAuthState(null);
    showNotification("Logout successful.", "info");
    logActivity("Logout", "User logged out.", "fa-sign-out-alt", "info");
    navigateTo('dashboard'); // Go to dashboard after logout
  } catch (error) {
    // Error already logged by fetchAPI
  }
}

async function checkAuthState() {
  try {
    const data = await fetchAPI("/user");
    if (data.success && data.user) {
      updateAuthState(data.user);
    } else {
      updateAuthState(null);
    }
  } catch (error) {
    // If /user fails (e.g., 401), assume logged out
    updateAuthState(null);
  }
}

// ── Vulnerability Module Handlers ──────────────────────────────

// SQL Injection Handler
sqlSubmitBtn.addEventListener("click", async () => {
  const target = sqlTargetInput.value;
  const username = sqlUsernameInput.value;
  const password = sqlPasswordInput.value;

  if (!target || !username || !password) {
    showNotification("Target URL, username, and password are required for SQL injection test.", "warning");
    return;
  }

  sqlResultBox.style.display = "none";
  dashboardStats.tests++;

  try {
    const data = await fetchAPI("/sql", {
      method: "POST",
      body: JSON.stringify({ target, username, password }),
    });

    if (data.success) {
      sqlResultBox.className = "result-box success";
      sqlResultBox.querySelector(".result-title").textContent = "SQL Injection Successful!";
      sqlResultBox.querySelector(".result-header i").className = "fas fa-check-circle text-success";
      sqlQueryResult.textContent = data.query || "Query not available";
      sqlResultBox.style.display = "block";
      showNotification("SQL Injection test successful!", "success");
      logActivity("SQL Test Success", `Target: ${target}, Payload: ${username}`, "fa-database", "success");
      dashboardStats.vulns++;
      dashboardStats.sql++;
    } else {
      sqlResultBox.className = "result-box error";
      sqlResultBox.querySelector(".result-title").textContent = "SQL Injection Failed";
      sqlResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
      sqlQueryResult.textContent = data.message || "Test failed.";
      sqlResultBox.style.display = "block";
      showNotification("SQL Injection test failed.", "error");
      logActivity("SQL Test Failed", `Target: ${target}, Payload: ${username}`, "fa-database", "error");
    }
  } catch (error) {
    sqlResultBox.className = "result-box error";
    sqlResultBox.querySelector(".result-title").textContent = "SQL Injection Error";
    sqlResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
    sqlQueryResult.textContent = `Error: ${error.message}`;
    sqlResultBox.style.display = "block";
    logActivity("SQL Test Error", `Target: ${target}, Error: ${error.message}`, "fa-database", "error");
  }
  updateDashboardStats();
});

// XSS Handler
xssSubmitBtn.addEventListener("click", async () => {
  const target = xssTargetInput.value;
  const name = xssNameInput.value;
  const comment = xssCommentInput.value;

  if (!target || !comment) {
    showNotification("Target URL and comment are required for XSS test.", "warning");
    return;
  }

xssResultBox.style.display = "none";
  dashboardStats.tests++;

  try {
    const data = await fetchAPI("/xss", {
      method: "POST",
      body: JSON.stringify({ target, name, comment }),
    });

    if (data.success) {
      xssResultBox.className = "result-box success";
      xssResultBox.querySelector(".result-title").textContent = "XSS Vulnerability Detected!";
      xssResultBox.querySelector(".result-header i").className = "fas fa-check-circle text-success";
      // Safely display the comment - DO NOT RENDER HTML DIRECTLY
      xssCommentPreview.textContent = data.renderedComment || comment; 
      xssResultBox.style.display = "block";
      showNotification("XSS vulnerability detected!", "success");
      logActivity("XSS Test Success", `Target: ${target}, Payload: ${comment.substring(0, 30)}...`, "fa-code", "success");
      dashboardStats.vulns++;
      dashboardStats.xss++;
      // Trigger alert if payload included alert()
      if (comment.includes("alert(")) {
        try {
          // Attempt to execute in a sandboxed way (still risky)
          // A safer approach is just to report success without execution
          // eval(comment); // Avoid eval in real applications!
          console.warn("Simulating XSS alert for payload:", comment);
          alert("Simulated XSS! Payload executed.");
        } catch (e) {
          console.error("Error simulating XSS alert:", e);
        }
      }
    } else {
      xssResultBox.className = "result-box error";
      xssResultBox.querySelector(".result-title").textContent = "XSS Test Failed";
      xssResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
      xssCommentPreview.textContent = data.message || "Test failed or no vulnerability found.";
      xssResultBox.style.display = "block";
      showNotification("XSS test failed or no vulnerability found.", "info");
      logActivity("XSS Test Failed", `Target: ${target}, Payload: ${comment.substring(0, 30)}...`, "fa-code", "info");
    }
  } catch (error) {
    xssResultBox.className = "result-box error";
    xssResultBox.querySelector(".result-title").textContent = "XSS Test Error";
    xssResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
    xssCommentPreview.textContent = `Error: ${error.message}`;
    xssResultBox.style.display = "block";
    logActivity("XSS Test Error", `Target: ${target}, Error: ${error.message}`, "fa-code", "error");
  }
  updateDashboardStats();
});

// Brute Force Handler
bruteSubmitBtn.addEventListener("click", async () => {
  const target = bruteTargetInput.value;
  const username = bruteUsernameInput.value;
  const passwords = brutePasswordsInput.value.split("\n").filter(p => p.trim() !== "");

  if (!target || !username || passwords.length === 0) {
    showNotification("Target URL, username, and at least one password are required.", "warning");
    return;
  }

  bruteResultBox.style.display = "none";
  dashboardStats.tests++;

  try {
    // Simulate brute force - in real app, backend would handle attempts
    // For demo, we assume 'admin123' is the correct password
    let found = false;
    let attempts = 0;
    for (const password of passwords) {
      attempts++;
      // Simulate check against backend (replace with actual API call)
      // const response = await fetchAPI('/brute-force-attempt', { method: 'POST', body: JSON.stringify({ target, username, password }) });
      // if (response.success) { ... }
      if (username === 'admin' && password === 'admin123') {
        found = true;
        break;
      }
      // Add a small delay to simulate network requests
      await new Promise(resolve => setTimeout(resolve, 50)); 
    }

    if (found) {
      bruteResultBox.className = "result-box success";
      bruteResultBox.querySelector(".result-title").textContent = "Password Cracked!";
      bruteResultBox.querySelector(".result-header i").className = "fas fa-check-circle text-success";
      bruteResultUsername.textContent = username;
      bruteResultPassword.textContent = "admin123"; // The found password
      bruteResultAttempts.textContent = attempts;
      bruteResultBox.style.display = "block";
      showNotification("Brute force successful!", "success");
      logActivity("Brute Force Success", `Target: ${target}, User: ${username}, Attempts: ${attempts}`, "fa-key", "success");
      dashboardStats.vulns++;
      dashboardStats.brute++;
    } else {
      bruteResultBox.className = "result-box error";
      bruteResultBox.querySelector(".result-title").textContent = "Brute Force Failed";
      bruteResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
      bruteResultUsername.textContent = username;
      bruteResultPassword.textContent = "Password not found in list.";
      bruteResultAttempts.textContent = attempts;
      bruteResultBox.style.display = "block";
      showNotification("Brute force failed.", "error");
      logActivity("Brute Force Failed", `Target: ${target}, User: ${username}, Attempts: ${attempts}`, "fa-key", "error");
    }
  } catch (error) {
      bruteResultBox.className = "result-box error";
      bruteResultBox.querySelector(".result-title").textContent = "Brute Force Error";
      bruteResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
      bruteResultUsername.textContent = username;
      bruteResultPassword.textContent = `Error: ${error.message}`;
      bruteResultAttempts.textContent = 'N/A';
      bruteResultBox.style.display = "block";
      logActivity("Brute Force Error", `Target: ${target}, Error: ${error.message}`, "fa-key", "error");
  }
  updateDashboardStats();
});

// Path Traversal Handler
pathSubmitBtn.addEventListener("click", async () => {
  const target = pathTargetInput.value;
  const filename = pathFilenameInput.value;

  if (!target || !filename) {
    showNotification("Target URL and filename are required.", "warning");
    return;
  }

  pathResultBox.style.display = "none";
  dashboardStats.tests++;

  try {
    // Simulate path traversal - backend should handle this
    // const data = await fetchAPI('/path-traversal', { method: 'POST', body: JSON.stringify({ target, filename }) });
    let success = false;
    let content = "Access denied or file not found.";
    // Basic check for common traversal patterns
    if (filename.includes("../") || filename.includes("..\\")) {
        // Simulate finding /etc/passwd
        if (filename.includes("etc/passwd")) {
            success = true;
            content = `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n... (simulated /etc/passwd content)`;
        } else {
            // Simulate generic success for other traversals
            success = true;
            content = `Simulated content for file: ${filename}`;
        }
    }

    if (success) {
      pathResultBox.className = "result-box success";
      pathResultBox.querySelector(".result-title").textContent = "Path Traversal Successful!";
      pathResultBox.querySelector(".result-header i").className = "fas fa-check-circle text-success";
      pathFileContent.textContent = content;
      pathResultBox.style.display = "block";
      showNotification("Path traversal successful!", "success");
      logActivity("Path Traversal Success", `Target: ${target}, Payload: ${filename}`, "fa-folder-open", "success");
      dashboardStats.vulns++;
      dashboardStats.path++;
    } else {
      pathResultBox.className = "result-box error";
      pathResultBox.querySelector(".result-title").textContent = "Path Traversal Failed";
      pathResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
      pathFileContent.textContent = content;
      pathResultBox.style.display = "block";
      showNotification("Path traversal failed.", "error");
      logActivity("Path Traversal Failed", `Target: ${target}, Payload: ${filename}`, "fa-folder-open", "error");
    }
  } catch (error) {
      pathResultBox.className = "result-box error";
      pathResultBox.querySelector(".result-title").textContent = "Path Traversal Error";
      pathResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
      pathFileContent.textContent = `Error: ${error.message}`;
      pathResultBox.style.display = "block";
      logActivity("Path Traversal Error", `Target: ${target}, Error: ${error.message}`, "fa-folder-open", "error");
  }
  updateDashboardStats();
});

// Command Injection Handler
commandSubmitBtn.addEventListener("click", async () => {
  const target = commandTargetInput.value;
  const host = commandHostInput.value;

  if (!target || !host) {
    showNotification("Target URL and host/command are required.", "warning");
    return;
  }

  commandResultBox.style.display = "none";
  dashboardStats.tests++;

  try {
    // Simulate command injection - backend should handle this
    // const data = await fetchAPI('/command-injection', { method: 'POST', body: JSON.stringify({ target, host }) });
    let success = false;
    let output = `Pinging ${host.split(';')[0].split('|')[0]}...\nRequest timed out.`; // Default output
    // Basic check for injection characters
    if (host.includes(';') || host.includes('|') || host.includes('&') || host.includes('`') || host.includes('$')) {
        success = true;
        // Simulate output for common commands
        if (host.includes('ls') || host.includes('dir')) {
            output = `Simulating ping for ${host.split(';')[0].split('|')[0]}...\nReply from ...\n\nSimulated directory listing:\ntotal 0\ndrwxr-xr-x 1 user group 0 May 25 02:00 .\ndrwxr-xr-x 1 user group 0 May 25 01:00 ..\n-rw-r--r-- 1 user group 0 May 25 02:00 file1.txt\n-rw-r--r-- 1 user group 0 May 25 02:00 file2.log`;
        } else if (host.includes('id') || host.includes('whoami')) {
            output = `Simulating ping for ${host.split(';')[0].split('|')[0]}...\nReply from ...\n\nSimulated command output:\nuid=1000(user) gid=1000(user) groups=1000(user)`;
        } else {
             output = `Simulating ping for ${host.split(';')[0].split('|')[0]}...\nReply from ...\n\nSimulated output for injected command: ${host}`; 
        }
    }

    if (success) {
      commandResultBox.className = "result-box success";
      commandResultBox.querySelector(".result-title").textContent = "Command Injection Successful!";
      commandResultBox.querySelector(".result-header i").className = "fas fa-check-circle text-success";
      commandOutput.textContent = output;
      commandResultBox.style.display = "block";
      showNotification("Command injection successful!", "success");
      logActivity("Command Injection Success", `Target: ${target}, Payload: ${host}`, "fa-terminal", "success");
      dashboardStats.vulns++;
      dashboardStats.command++;
    } else {
      commandResultBox.className = "result-box error";
      commandResultBox.querySelector(".result-title").textContent = "Command Injection Failed";
      commandResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
      commandOutput.textContent = output; // Show default ping output
      commandResultBox.style.display = "block";
      showNotification("Command injection failed or no vulnerability found.", "info");
      logActivity("Command Injection Failed", `Target: ${target}, Payload: ${host}`, "fa-terminal", "info");
    }
  } catch (error) {
      commandResultBox.className = "result-box error";
      commandResultBox.querySelector(".result-title").textContent = "Command Injection Error";
      commandResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
      commandOutput.textContent = `Error: ${error.message}`;
      commandResultBox.style.display = "block";
      logActivity("Command Injection Error", `Target: ${target}, Error: ${error.message}`, "fa-terminal", "error");
  }
  updateDashboardStats();
});

// ── Generator Handlers ───────────────────────────────────────── //

async function handleGeneratePayload(endpoint, params, resultBox, payloadElem, explanationElem) {
  resultBox.style.display = "none";
  try {
    const data = await fetchAPI(endpoint, {
      method: "POST",
      body: JSON.stringify(params),
    });
    if (data.success) {
      payloadElem.textContent = data.payload;
      explanationElem.textContent = data.explanation;
      resultBox.style.display = "block";
      showNotification("Payload generated successfully!", "success");
    } else {
      showNotification(data.message || "Payload generation failed.", "error");
    }
  } catch (error) {
    showNotification(`Error generating payload: ${error.message}`, "error");
  }
}

sqlGenBtn.addEventListener("click", () => {
  handleGeneratePayload("/generate/sql", 
    { 
      type: sqlGenType.value, 
      dbms: sqlGenDbms.value, 
      column: sqlGenColumn.value 
    }, 
    sqlGenResultBox, sqlGenPayload, sqlGenExplanation
  );
});

xssGenBtn.addEventListener("click", () => {
  handleGeneratePayload("/generate/xss", 
    { 
      type: xssGenType.value, 
      context: xssGenContext.value, 
      goal: xssGenGoal.value 
    }, 
    xssGenResultBox, xssGenPayload, xssGenExplanation
  );
});

pathGenBtn.addEventListener("click", () => {
  const file = pathGenFile.value === 'custom' ? pathGenCustomInput.value : pathGenFile.value;
  handleGeneratePayload("/generate/path", 
    { 
      os: pathGenOs.value, 
      file: file, 
      encoding: pathGenEncoding.value 
    }, 
    pathGenResultBox, pathGenPayload, pathGenExplanation
  );
});

// Show/hide custom path input
pathGenFile.addEventListener('change', () => {
  pathGenCustomGroup.style.display = pathGenFile.value === 'custom' ? 'block' : 'none';
});

cmdGenBtn.addEventListener("click", () => {
  const command = cmdGenGoal.value === 'custom' ? cmdGenCustomInput.value : cmdGenGoal.value;
  handleGeneratePayload("/generate/command", 
    { 
      os: cmdGenOs.value, 
      goal: cmdGenGoal.value, // Send the goal type
      command: command, // Send the actual command (custom or derived from goal)
      bypass: cmdGenBypass.value 
    }, 
    cmdGenResultBox, cmdGenPayload, cmdGenExplanation
  );
});

// Show/hide custom command input
cmdGenGoal.addEventListener('change', () => {
  cmdGenCustomGroup.style.display = cmdGenGoal.value === 'custom' ? 'block' : 'none';
});

// AI Brute Force Password Generator
bruteAiGenerateBtn.addEventListener("click", async () => {
  const targetInfo = bruteAiTargetInput.value;
  const hints = bruteAiHintsInput.value;
  const complexity = bruteAiComplexity.value;
  const count = parseInt(bruteAiCountInput.value, 10);

  if (!hints && !targetInfo) {
    showNotification("Please provide some hints or target information for the AI.", "warning");
    return;
  }

  bruteAiResultBox.style.display = "none";
  showNotification("Generating AI password list... This may take a moment.", "info");

  try {
    const data = await fetchAPI("/generate/brute-force-ai", {
      method: "POST",
      body: JSON.stringify({ targetInfo, hints, complexity, count }),
    });

    if (data.success && data.passwords) {
      bruteAiPasswords.textContent = data.passwords.join("\n");
      bruteAiResultBox.style.display = "block";
      showNotification("AI password list generated!", "success");
    } else {
      showNotification(data.message || "AI password generation failed.", "error");
    }
  } catch (error) {
    showNotification(`Error generating AI passwords: ${error.message}`, "error");
  }
});

// Use AI generated passwords in the main brute force tool
bruteAiUseBtn.addEventListener("click", () => {
  const aiPasswords = bruteAiPasswords.textContent;
  if (aiPasswords) {
    brutePasswordsInput.value = aiPasswords;
    showNotification("AI password list copied to Brute Force tool.", "info");
    // Optionally, scroll to the main brute force tool or highlight it
    brutePasswordsInput.focus();
    brutePasswordsInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
});

// ── Scanner & Vulnerability Search Handlers ─────────────────── //

scanBtn.addEventListener("click", async () => {
  const target = scanTargetInput.value;
  const scanType = document.querySelector('input[name="scan-type"]:checked').value;
  const vulnerabilities = Array.from(document.querySelectorAll('input[name^="vuln-"]:checked')).map(cb => cb.name.split('-')[1]);

  if (!target) {
    showNotification("Target URL is required for scanning.", "warning");
    return;
  }

  scanResultBox.style.display = "block";
  scanCompleteBox.style.display = "none";
  scanProgress.style.width = "0%";
  scanStatus.textContent = `Starting ${scanType} scan on ${target}...`;
  logActivity("Scan Started", `Target: ${target}, Type: ${scanType}`, "fa-search", "info");
  dashboardStats.tests++; // Count scan as a test

  try {
    // Simulate progress for demo
    let progress = 0;
    const interval = setInterval(() => {
      progress += 10;
      scanProgress.style.width = `${progress}%`;
      scanStatus.textContent = `Scanning... ${progress}% complete`;
      if (progress >= 100) {
        clearInterval(interval);
      }
    }, 300);

    const data = await fetchAPI("/scan", {
      method: "POST",
      body: JSON.stringify({ target, scanType, vulnerabilities }),
    });

    clearInterval(interval); // Ensure interval is cleared
    scanProgress.style.width = "100%";
    scanStatus.textContent = "Processing results...";

    if (data.success) {
      scanResultBox.style.display = "none";
      scanCompleteBox.style.display = "block";
      scanSummary.innerHTML = `
        <p><strong>Target:</strong> ${data.target}</p>
        <p><strong>Scan Type:</strong> ${data.scanType}</p>
        <p><strong>Vulnerabilities Found:</strong> ${data.findings.length}</p>
        <p><strong>Duration:</strong> ${data.duration || 'N/A'}</p>
      `;
      scanFindings.innerHTML = data.findings.map(finding => `
        <div class="finding-item severity-${finding.severity.toLowerCase()}">
          <h4>${finding.type} (${finding.severity})</h4>
          <p>${finding.description}</p>
          <p><strong>Location:</strong> ${finding.location || 'N/A'}</p>
        </div>
      `).join('');
      showNotification("Scan completed successfully!", "success");
      logActivity("Scan Complete", `Target: ${target}, Found: ${data.findings.length} vulns`, "fa-check-circle", "success");
      // Update dashboard stats based on findings
      data.findings.forEach(f => {
        if (f.severity !== 'Info' && f.severity !== 'Low') {
            dashboardStats.vulns++;
            dashboardStats.scan++; // Increment scanner specific count
        }
      });
    } else {
      scanResultBox.style.display = "block"; // Keep progress box visible for error
      scanResultBox.className = "result-box error";
      scanResultBox.querySelector(".result-title").textContent = "Scan Failed";
      scanResultBox.querySelector(".result-header i").className = "fas fa-times-circle text-error";
      scanStatus.textContent = data.message || "Scan failed.";
      showNotification(data.message || "Scan failed.", "error");
      logActivity("Scan Failed", `Target: ${target}, Error: ${data.message || 'Unknown'}`, "fa-search", "error");
    }
  } catch (error) {
    scanResultBox.style.display = "block";
    scanResultBox.className = "result-box error";
    scanResultBox.querySelector(".result-title").textContent = "Scan Error";
    scanResultBox.querySelector(".result-header i").className = "fas fa-exclamation-triangle text-error";
    scanStatus.textContent = `Error: ${error.message}`;
    logActivity("Scan Error", `Target: ${target}, Error: ${error.message}`, "fa-search", "error");
  }
  updateDashboardStats();
});

vulnSearchBtn.addEventListener("click", async () => {
  const query = vulnSearchInput.value;
  const filters = Array.from(document.querySelectorAll('input[name^="filter-"]:checked')).map(cb => cb.name.split('-')[1]);

  if (!query) {
    showNotification("Please enter search keywords.", "warning");
    return;
  }

  vulnSearchResultBox.style.display = "block";
  vulnSearchFindings.innerHTML = `<p>Searching for vulnerabilities related to "${query}"...</p>`;
  logActivity("Vuln Search", `Query: ${query}`, "fa-search", "info");

  try {
    const data = await fetchAPI("/search/vulnerabilities", {
      method: "POST",
      body: JSON.stringify({ query, filters }),
    });

    if (data.success && data.results) {
      if (data.results.length > 0) {
         vulnSearchFindings.innerHTML = data.results.map(result => `
          <div class="vuln-search-item">
            <h4><a href="${result.url || '#'}" target="_blank" rel="noopener noreferrer">${result.title}</a></h4>
            <p><strong>Severity:</strong> <span class="severity-${result.severity.toLowerCase()}">${result.severity}</span></p>
            <p>${result.summary}</p>
            <p><em>Source: ${result.source || 'N/A'} | Published: ${result.publishedDate || 'N/A'}</em></p>
          </div>
        `).join('');
      } else {
        vulnSearchFindings.innerHTML = `<p>No vulnerabilities found matching your criteria.</p>`;
      }
      showNotification("Vulnerability search complete.", "success");
    } else {
      vulnSearchFindings.innerHTML = `<p>Error: ${data.message || 'Search failed.'}</p>`;
      showNotification(data.message || "Vulnerability search failed.", "error");
    }
  } catch (error) {
    vulnSearchFindings.innerHTML = `<p>Error: ${error.message}</p>`;
    logActivity("Vuln Search Error", `Query: ${query}, Error: ${error.message}`, "fa-search", "error");
  }
});


// ── Initialization ─────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initializeChart();
  checkAuthState();
  handleInitialNavigation();

  // Add event listeners for auth buttons (will be replaced if logged in)
  loginBtn?.addEventListener("click", () => openModal(loginModal));
  registerBtn?.addEventListener("click", () => openModal(registerModal));
  loginSubmit?.addEventListener("click", handleLogin);
  registerSubmit?.addEventListener("click", handleRegister);
});

