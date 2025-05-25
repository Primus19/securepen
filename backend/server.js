// backend/server.js

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcrypt");
const fs = require("fs");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "securepen-secret-key-for-jwt-tokens";

// ── Middleware ────────────────────────────────────────────────
app.use(cors({
  origin: true,
  credentials: true
}));
// Use Morgan for HTTP request logging
app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());

// ── Database Setup ─────────────────────────────────────────────
// Use relative path for development and absolute path for Docker
const dbPath = process.env.NODE_ENV === 'production' ? "/app/vulnerabilities.db" : "./vulnerabilities.db";
try {
  if (!fs.existsSync(dbPath)) {
    console.log("Creating new database file:", dbPath);
    fs.closeSync(fs.openSync(dbPath, "w"));
  }
  fs.accessSync(dbPath, fs.constants.R_OK | fs.constants.W_OK);
  console.log("Database file is accessible:", dbPath);
} catch (err) {
  console.error("Database access error:", err);
  console.error("Attempting to create directory structure...");
  try {
    const path = require('path');
    const dbDir = path.dirname(dbPath);
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
      fs.closeSync(fs.openSync(dbPath, "w"));
      console.log("Successfully created database file:", dbPath);
    }
  } catch (mkdirErr) {
    console.error("Failed to create directory structure:", mkdirErr);
    process.exit(1);
  }
}

const db = new sqlite3.Database(
  dbPath,
  sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
  (err) => {
    if (err) {
      console.error("Database open error:", err);
      process.exit(1);
    }
    console.log("Connected to database:", dbPath);

    // Create users table
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         username TEXT UNIQUE,
         password TEXT,
         email TEXT,
         role TEXT DEFAULT 'user',
         created_at DATETIME DEFAULT CURRENT_TIMESTAMP
       )`,
      (err) => {
        if (err) {
          console.error("Users table creation error:", err);
          process.exit(1);
        }

        // Create scan_results table
        db.run(
          `CREATE TABLE IF NOT EXISTS scan_results (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             user_id INTEGER,
             target TEXT,
             scan_type TEXT,
             severity TEXT,
             findings TEXT,
             timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
             FOREIGN KEY (user_id) REFERENCES users(id)
           )`,
          (err) => {
            if (err) {
              console.error("Scan results table creation error:", err);
              process.exit(1);
            }

            // Create activity_logs table
            db.run(
              `CREATE TABLE IF NOT EXISTS activity_logs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 action TEXT,
                 details TEXT,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY (user_id) REFERENCES users(id)
               )`,
              (err) => {
                if (err) {
                  console.error("Activity logs table creation error:", err);
                  process.exit(1);
                }

                // Ensure admin user exists
                db.get("SELECT * FROM users WHERE username = ?", ["admin"], (err, row) => {
                  if (err) {
                    console.error("User check error:", err);
                    process.exit(1);
                  }
                  if (!row) {
                    bcrypt.hash("password123", 10, (err, hash) => {
                      if (err) {
                        console.error("Hash error:", err);
                        return;
                      }
                      db.run(
                        "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                        ["admin", hash, "admin@securepen.local", "admin"],
                        (err) => {
                          if (err) {
                            console.error("Insert user error:", err);
                          } else {
                            console.log("Admin user created");
                          }
                        }
                      );
                    });
                  } else {
                    console.log("Admin user already exists");
                  }
                });
              }
            );
          }
        );
      }
    );
  }
);

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: "Authentication required", success: false });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token", success: false });
    }
    req.user = user;
    next();
  });
};

// Admin middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: "Admin privileges required", success: false });
  }
  next();
};

// ── Routes ───────────────────────────────────────────────────────
// API Health Check
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "healthy", 
    version: "2.1.0",
    timestamp: new Date().toISOString()
  });
});

// User Registration
app.post("/api/register", (req, res) => {
  const { username, password, email } = req.body;
  
  if (!username || !password || !email) {
    return res.status(400).json({ 
      message: "Username, password, and email are required", 
      success: false 
    });
  }
  
  // Check if username already exists
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err) {
      console.error("User check error:", err);
      return res.status(500).json({ 
        message: "Database error", 
        success: false 
      });
    }
    
    if (row) {
      return res.status(409).json({ 
        message: "Username already exists", 
        success: false 
      });
    }
    
    // Hash password and create user
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        console.error("Hash error:", err);
        return res.status(500).json({ 
          message: "Password encryption error", 
          success: false 
        });
      }
      
      db.run(
        "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
        [username, hash, email, "user"],
        function(err) {
          if (err) {
            console.error("Insert user error:", err);
            return res.status(500).json({ 
              message: "User creation failed", 
              success: false 
            });
          }
          
          // Log activity
          db.run(
            "INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)",
            [this.lastID, "REGISTER", "User registration successful"],
            (err) => {
              if (err) {
                console.error("Activity log error:", err);
              }
            }
          );
          
          // Create and send JWT token
          const user = { id: this.lastID, username, role: "user" };
          const token = jwt.sign(user, JWT_SECRET, { expiresIn: '24h' });
          
          res.cookie('token', token, { 
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
          });
          
          res.status(201).json({ 
            message: "User registered successfully", 
            user: { id: this.lastID, username, email, role: "user" },
            success: true 
          });
        }
      );
    });
  });
});

// User Login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ 
      message: "Username and password are required", 
      success: false 
    });
  }
  
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      console.error("Login query error:", err);
      return res.status(500).json({ 
        message: "Database error", 
        success: false 
      });
    }
    
    if (!user) {
      return res.status(401).json({ 
        message: "Invalid username or password", 
        success: false 
      });
    }
    
    bcrypt.compare(password, user.password, (err, match) => {
      if (err) {
        console.error("Password comparison error:", err);
        return res.status(500).json({ 
          message: "Authentication error", 
          success: false 
        });
      }
      
      if (!match) {
        return res.status(401).json({ 
          message: "Invalid username or password", 
          success: false 
        });
      }
      
      // Log activity
      db.run(
        "INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)",
        [user.id, "LOGIN", "User login successful"],
        (err) => {
          if (err) {
            console.error("Activity log error:", err);
          }
        }
      );
      
      // Create and send JWT token
      const userInfo = { id: user.id, username: user.username, role: user.role };
      const token = jwt.sign(userInfo, JWT_SECRET, { expiresIn: '24h' });
      
      res.cookie('token', token, { 
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });
      
      res.json({ 
        message: "Login successful", 
        user: { id: user.id, username: user.username, email: user.email, role: user.role },
        success: true 
      });
    });
  });
});

// User Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie('token');
  res.json({ 
    message: "Logout successful", 
    success: true 
  });
});

// Get Current User
app.get("/api/user", authenticateToken, (req, res) => {
  db.get("SELECT id, username, email, role FROM users WHERE id = ?", [req.user.id], (err, user) => {
    if (err) {
      console.error("User query error:", err);
      return res.status(500).json({ 
        message: "Database error", 
        success: false 
      });
    }
    
    if (!user) {
      return res.status(404).json({ 
        message: "User not found", 
        success: false 
      });
    }
    
    res.json({ 
      user, 
      success: true 
    });
  });
});

// Get User Activity
app.get("/api/user/activity", authenticateToken, (req, res) => {
  db.all(
    "SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20",
    [req.user.id],
    (err, logs) => {
      if (err) {
        console.error("Activity logs query error:", err);
        return res.status(500).json({ 
          message: "Database error", 
          success: false 
        });
      }
      
      res.json({ 
        logs, 
        success: true 
      });
    }
  );
});

// Get User Scan Results
app.get("/api/user/scans", authenticateToken, (req, res) => {
  db.all(
    "SELECT * FROM scan_results WHERE user_id = ? ORDER BY timestamp DESC",
    [req.user.id],
    (err, scans) => {
      if (err) {
        console.error("Scan results query error:", err);
        return res.status(500).json({ 
          message: "Database error", 
          success: false 
        });
      }
      
      res.json({ 
        scans, 
        success: true 
      });
    }
  );
});

// SQL Injection vulnerability demo
app.post("/sql", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password required.", success: false });
  }
  const query =
    "SELECT * FROM users WHERE username = '" +
    username +
    "' AND password = '" +
    password +
    "'";
  db.all(query, (err, rows) => {
    if (err) {
      console.error("SQL query error:", err);
      return res
        .status(500)
        .json({ message: "Database error: " + err.message, success: false });
    }
    if (rows.length > 0) {
      return res.json({
        message: "Login successful! Query: " + query,
        success: true,
        vulnerability: "SQL Injection",
        severity: "High",
        description: "This endpoint is vulnerable to SQL injection attacks, allowing unauthorized access to the database.",
        instructions: "Try entering ' OR '1'='1 in the username field and anything in the password field. This bypasses authentication by making the WHERE clause always true."
      });
    }
    return res.json({
      message: "Login failed. Try: ' OR '1'='1",
      success: false,
    });
  });
});

app.post("/xss", (req, res) => {
  const { comment } = req.body;
  if (!comment) {
    return res
      .status(400)
      .json({ message: "Comment required.", success: false });
  }
  
  // Log the activity if user is authenticated
  const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
  if (token) {
    try {
      const user = jwt.verify(token, JWT_SECRET);
      db.run(
        "INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)",
        [user.id, "XSS_TEST", "User tested XSS vulnerability with: " + comment.substring(0, 50)],
        (err) => {
          if (err) {
            console.error("Activity log error:", err);
          }
        }
      );
    } catch (err) {
      console.error("Token verification error:", err);
    }
  }
  
  // Enhanced XSS detection - check for various script tags and event handlers
  const xssPatterns = [
    /<script>/i,
    /<script\s+/i,
    /javascript:/i,
    /onerror=/i,
    /onload=/i,
    /onclick=/i,
    /eval\(/i
  ];
  
  const detectedPattern = xssPatterns.find(pattern => pattern.test(comment));
  
  if (detectedPattern) {
    return res.json({
      message: "Stored XSS detected! Malicious pattern found.",
      success: true,
      vulnerability: "Cross-Site Scripting (XSS)",
      severity: "High",
      description: "This endpoint is vulnerable to XSS attacks, allowing execution of arbitrary JavaScript in users' browsers.",
      instructions: "XSS allows attackers to inject client-side scripts into web pages viewed by other users. Try different variations like <script>alert('XSS')</script>, <img src='x' onerror='alert(\"XSS\")'/>, or javascript:alert('XSS') to see how they might be executed.",
      detectedPattern: detectedPattern.toString()
    });
  }
  
  return res.json({
    message: "No XSS detected. Try: <script>alert('XSS')</script>",
    success: false,
    instructions: "XSS allows attackers to inject client-side scripts into web pages viewed by other users. Try using <script>alert('XSS')</script> in your input."
  });
});

app.post("/brute", (req, res) => {
  const { username, wordlist } = req.body;
  if (!username || !Array.isArray(wordlist)) {
    return res
      .status(400)
      .json({ 
        message: "Username and wordlist required.", 
        success: false,
        instructions: "Upload a wordlist (array of passwords) to test against a username. This simulates a brute force attack against a login system."
      });
  }
  
  // Log the activity if user is authenticated
  const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
  if (token) {
    try {
      const user = jwt.verify(token, JWT_SECRET);
      db.run(
        "INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)",
        [user.id, "BRUTE_FORCE_TEST", `User tested brute force with username: ${username} and ${wordlist.length} passwords`],
        (err) => {
          if (err) {
            console.error("Activity log error:", err);
          }
        }
      );
    } catch (err) {
      console.error("Token verification error:", err);
    }
  }
  
  // Rate limiting to prevent abuse
  const MAX_ATTEMPTS = 100;
  if (wordlist.length > MAX_ATTEMPTS) {
    return res.status(429).json({ 
      message: `Too many attempts. Maximum ${MAX_ATTEMPTS} passwords allowed per request.`, 
      success: false 
    });
  }
  
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err) {
      console.error("Brute force query error:", err);
      return res
        .status(500)
        .json({ message: "Database error: " + err.message, success: false });
    }
    if (!row) {
      return res.json({ message: "User not found.", success: false });
    }
    
    let i = 0;
    (function checkNext() {
      if (i >= wordlist.length) {
        return res.json({ 
          message: "No password matched.", 
          success: false,
          vulnerability: "Brute Force Attack",
          severity: "High",
          description: "This endpoint simulates a brute force attack against a login system, allowing attackers to try multiple passwords against a known username.",
          instructions: "Upload a list of passwords to try against a username. In real applications, this would be mitigated with rate limiting, account lockouts, and CAPTCHA challenges.", 
          success: false,
          attemptsUsed: wordlist.length,
          remainingAttempts: MAX_ATTEMPTS - wordlist.length
        });
      }
      bcrypt.compare(wordlist[i], row.password, (err, match) => {
        if (err) {
          console.error("Bcrypt error:", err);
          return res
            .status(500)
            .json({ message: "Bcrypt error: " + err.message, success: false });
        }
        if (match) {
          return res.json({
            message: "Password cracked!",
            password: wordlist[i],
            success: true,
            vulnerability: "Brute Force Attack",
            severity: "Critical",
            description: "This endpoint is vulnerable to brute force attacks, allowing attackers to guess passwords through repeated attempts.",
            attemptNumber: i + 1
          });
        }
        i++;
        checkNext();
      });
    })();
  });
});

// New vulnerability: Path Traversal
app.get("/file", (req, res) => {
  const filename = req.query.name;
  if (!filename) {
    return res.status(400).json({ 
      message: "Filename required.", 
      success: false 
    });
  }
  
  try {
    // Vulnerable to path traversal
    const filePath = `./files/${filename}`;
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      return res.json({
        message: "File retrieved successfully",
        content: content,
        success: true,
        vulnerability: "Path Traversal",
        severity: "High",
        description: "This endpoint is vulnerable to path traversal attacks, allowing access to files outside the intended directory."
      });
    } else {
      return res.status(404).json({ 
        message: "File not found. Try: '../server.js'", 
        success: false 
      });
    }
  } catch (err) {
    return res.status(500).json({ 
      message: "Error reading file: " + err.message, 
      success: false 
    });
  }
});

// New vulnerability: Command Injection
app.post("/ping", (req, res) => {
  const { host } = req.body;
  if (!host) {
    return res.status(400).json({ 
      message: "Host parameter required.", 
      success: false 
    });
  }
  
  // Vulnerable to command injection
  const { exec } = require('child_process');
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.json({ 
        message: "Error executing ping command", 
        error: stderr,
        success: false 
      });
    }
    return res.json({
      message: "Command executed successfully",
      output: stdout,
      success: true,
      vulnerability: "Command Injection",
      severity: "Critical",
      description: "This endpoint is vulnerable to command injection attacks, allowing execution of arbitrary system commands."
    });
  });
});

// Vulnerability scan endpoint
app.post("/api/scan", (req, res) => {
  const { target } = req.body;
  if (!target) {
    return res.status(400).json({ 
      message: "Target URL or IP required.", 
      success: false 
    });
  }
  
  // Simulate a vulnerability scan
  setTimeout(() => {
    const vulnerabilities = [
      {
        id: "CVE-2021-44228",
        name: "Log4Shell",
        severity: "Critical",
        cvss: 10.0,
        description: "Remote code execution vulnerability in Apache Log4j",
        remediation: "Update to Log4j 2.15.0 or later"
      },
      {
        id: "CVE-2021-27101",
        name: "Accellion FTA SQL Injection",
        severity: "High",
        cvss: 8.8,
        description: "SQL injection vulnerability in Accellion FTA",
        remediation: "Apply vendor patches"
      },
      {
        id: "CVE-2021-26855",
        name: "Microsoft Exchange Server SSRF",
        severity: "Critical",
        cvss: 9.8,
        description: "Server-side request forgery vulnerability in Microsoft Exchange",
        remediation: "Apply security updates from Microsoft"
      }
    ];
    
    res.json({
      target: target,
      scanId: "scan-" + Date.now(),
      timestamp: new Date().toISOString(),
      vulnerabilities: vulnerabilities,
      summary: {
        total: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === "Critical").length,
        high: vulnerabilities.filter(v => v.severity === "High").length,
        medium: vulnerabilities.filter(v => v.severity === "Medium").length,
        low: vulnerabilities.filter(v => v.severity === "Low").length
      },
      success: true
    });
  }, 2000); // Simulate 2-second scan
});

app.get("/api/ping", (req, res) => {
  res.json({ message: "pong" });
});

// ── Start Server ────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
});
