// Fixed backend/server.js for SecurePen application

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'securepen-secret-key';
const SALT_ROUNDS = 10;

// Initialize Express app
const app = express();

// Enhanced CORS configuration for deployment
app.use(cors({
  origin: '*', // Allow all origins in development
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Database setup
const dbPath = process.env.NODE_ENV === "production" ? "./vulnerabilities.db" : "./vulnerabilities.db";
let db;

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Enhanced error logging
const logError = (location, error) => {
  const logMessage = `[ERROR] ${new Date().toISOString()} - ${location}: ${error.message}\n${error.stack}\n`;
  console.error(logMessage);
  
  // Also log to file
  fs.appendFile(path.join(logsDir, 'server.log'), logMessage, (err) => {
    if (err) console.error(`Failed to write to log file: ${err.message}`);
  });
};

// Initialize database
const initializeDatabase = () => {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(dbPath, (err) => {
      if (err) {
        logError('Database initialization', err);
        return reject(err);
      }
      
      console.log(`Connected to SQLite database at ${dbPath}`);
      
      // Create tables if they don't exist
      db.serialize(() => {
        // Users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
          if (err) logError('Create users table', err);
        });
        
        // Scan results table
        db.run(`CREATE TABLE IF NOT EXISTS scan_results (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          scan_type TEXT NOT NULL,
          target TEXT NOT NULL,
          result TEXT NOT NULL,
          vulnerabilities_found INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id)
        )`, (err) => {
          if (err) logError('Create scan_results table', err);
        });
        
        // Activity logs table
        db.run(`CREATE TABLE IF NOT EXISTS activity_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          action TEXT NOT NULL,
          details TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id)
        )`, (err) => {
          if (err) logError('Create activity_logs table', err);
        });
        
        resolve();
      });
    });
  });
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    req.user = user;
    next();
  });
};

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running' });
});

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if user already exists
    db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], async (err, user) => {
      if (err) {
        logError('User lookup', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (user) {
        return res.status(409).json({ error: 'Username or email already exists' });
      }
      
      // Hash password
      try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        
        // Insert new user
        db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
          [username, email, hashedPassword], 
          function(err) {
            if (err) {
              logError('User creation', err);
              return res.status(500).json({ error: 'Database error' });
            }
            
            // Log activity
            const userId = this.lastID;
            db.run('INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
              [userId, 'REGISTER', 'User registration'],
              (err) => {
                if (err) logError('Activity logging', err);
              }
            );
            
            res.status(201).json({ message: 'User registered successfully' });
          }
        );
      } catch (err) {
        logError('Password hashing', err);
        return res.status(500).json({ error: 'Server error' });
      }
    });
  } catch (err) {
    logError('Registration', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Find user
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        logError('User lookup', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Compare password
      try {
        const match = await bcrypt.compare(password, user.password);
        
        if (!match) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
          { id: user.id, username: user.username, email: user.email },
          JWT_SECRET,
          { expiresIn: '24h' }
        );
        
        // Log activity
        db.run('INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
          [user.id, 'LOGIN', 'User login'],
          (err) => {
            if (err) logError('Activity logging', err);
          }
        );
        
        res.json({ 
          message: 'Login successful',
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email
          }
        });
      } catch (err) {
        logError('Password comparison', err);
        return res.status(500).json({ error: 'Server error' });
      }
    });
  } catch (err) {
    logError('Login', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  // Log activity
  db.run('INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
    [req.user.id, 'LOGOUT', 'User logout'],
    (err) => {
      if (err) logError('Activity logging', err);
    }
  );
  
  res.json({ message: 'Logout successful' });
});

// User routes
app.get('/api/user/stats', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get user stats
    db.get(`
      SELECT 
        COUNT(*) as total_scans,
        SUM(vulnerabilities_found) as total_vulnerabilities
      FROM scan_results
      WHERE user_id = ?
    `, [userId], (err, stats) => {
      if (err) {
        logError('User stats', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      // If no scans yet, return zeros
      if (!stats.total_scans) {
        return res.json({
          total_scans: 0,
          total_vulnerabilities: 0,
          success_rate: 0
        });
      }
      
      // Calculate success rate
      const successRate = stats.total_vulnerabilities > 0 
        ? Math.round((stats.total_vulnerabilities / stats.total_scans) * 100)
        : 0;
      
      res.json({
        total_scans: stats.total_scans || 0,
        total_vulnerabilities: stats.total_vulnerabilities || 0,
        success_rate: successRate
      });
    });
  } catch (err) {
    logError('User stats', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/user/activity', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get recent activity
    db.all(`
      SELECT action, details, created_at
      FROM activity_logs
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 10
    `, [userId], (err, activities) => {
      if (err) {
        logError('User activity', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({ activities: activities || [] });
    });
  } catch (err) {
    logError('User activity', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/user/scans', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get recent scans
    db.all(`
      SELECT scan_type, target, result, vulnerabilities_found, created_at
      FROM scan_results
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 10
    `, [userId], (err, scans) => {
      if (err) {
        logError('User scans', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({ scans: scans || [] });
    });
  } catch (err) {
    logError('User scans', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Module endpoints
app.get('/api/modules/sql', (req, res) => {
  res.json({
    title: "SQL Injection Testing",
    description: "Test for SQL injection vulnerabilities in your application",
    instructions: "Enter a URL or database query to test for SQL injection vulnerabilities",
    examples: [
      "' OR 1=1 --",
      "admin' --",
      "1'; DROP TABLE users; --"
    ],
    testCases: [
      {
        name: "Basic Authentication Bypass",
        payload: "' OR '1'='1",
        description: "Attempts to bypass login by making the WHERE clause always true"
      },
      {
        name: "Union-Based Attack",
        payload: "' UNION SELECT username, password FROM users --",
        description: "Attempts to extract data from other tables"
      },
      {
        name: "Database Schema Discovery",
        payload: "' UNION SELECT table_name, column_name FROM information_schema.columns --",
        description: "Attempts to discover database schema information"
      }
    ]
  });
});

app.get('/api/modules/xss', (req, res) => {
  res.json({
    title: "Cross-Site Scripting (XSS) Testing",
    description: "Test for XSS vulnerabilities in your application",
    instructions: "Enter a URL or input field to test for XSS vulnerabilities",
    examples: [
      "<script>alert('XSS')</script>",
      "<img src='x' onerror='alert(\"XSS\")'>",
      "<svg onload='alert(\"XSS\")'>"
    ],
    testCases: [
      {
        name: "Basic Script Injection",
        payload: "<script>alert('XSS')</script>",
        description: "Basic script tag injection to execute JavaScript"
      },
      {
        name: "Event Handler Injection",
        payload: "<img src='x' onerror='alert(\"XSS\")'>",
        description: "Uses HTML event handlers to execute JavaScript"
      },
      {
        name: "DOM-based XSS",
        payload: "<div id='test' onclick='alert(\"XSS\")'>Click me</div>",
        description: "Manipulates the DOM to execute JavaScript"
      }
    ]
  });
});

app.get('/api/modules/brute-force', (req, res) => {
  res.json({
    title: "Brute Force Testing",
    description: "Test for brute force vulnerabilities in your application",
    instructions: "Enter a URL or authentication endpoint to test for brute force vulnerabilities",
    examples: [
      "https://example.com/login",
      "https://example.com/admin",
      "https://example.com/wp-login.php"
    ],
    testCases: [
      {
        name: "Common Passwords",
        description: "Tests a list of common passwords against the target"
      },
      {
        name: "Dictionary Attack",
        description: "Uses a dictionary of common words to attempt authentication"
      },
      {
        name: "Credential Stuffing",
        description: "Tests username/password combinations from known data breaches"
      }
    ]
  });
});

app.get('/api/modules/path-traversal', (req, res) => {
  res.json({
    title: "Path Traversal Testing",
    description: "Test for path traversal vulnerabilities in your application",
    instructions: "Enter a URL or file path to test for path traversal vulnerabilities",
    examples: [
      "../../../etc/passwd",
      "..\\..\\..\\Windows\\system.ini",
      "file:///etc/passwd"
    ],
    testCases: [
      {
        name: "Basic Path Traversal",
        payload: "../../../etc/passwd",
        description: "Attempts to access system files using relative paths"
      },
      {
        name: "Encoded Path Traversal",
        payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        description: "Uses URL encoding to bypass filters"
      },
      {
        name: "Nested Traversal",
        payload: "....//....//....//etc/passwd",
        description: "Uses nested traversal sequences to bypass filters"
      }
    ]
  });
});

app.get('/api/modules/command-injection', (req, res) => {
  res.json({
    title: "Command Injection Testing",
    description: "Test for command injection vulnerabilities in your application",
    instructions: "Enter a URL or command input to test for command injection vulnerabilities",
    examples: [
      "; ls -la",
      "& dir",
      "| cat /etc/passwd"
    ],
    testCases: [
      {
        name: "Basic Command Injection",
        payload: "; ls -la",
        description: "Uses semicolon to execute additional commands"
      },
      {
        name: "Blind Command Injection",
        payload: "& ping -c 5 attacker.com",
        description: "Executes commands that may not show output but have side effects"
      },
      {
        name: "Time-based Injection",
        payload: "| sleep 10",
        description: "Uses timing to detect successful command execution"
      }
    ]
  });
});

app.get('/api/modules/scanner', (req, res) => {
  res.json({
    title: "Vulnerability Scanner",
    description: "Scan your application for multiple types of vulnerabilities",
    instructions: "Enter a URL or IP address to scan for vulnerabilities",
    scanTypes: [
      {
        name: "Quick Scan",
        description: "Performs a basic scan for common vulnerabilities",
        duration: "1-5 minutes"
      },
      {
        name: "Full Scan",
        description: "Performs a comprehensive scan for all vulnerabilities",
        duration: "10-30 minutes"
      },
      {
        name: "Custom Scan",
        description: "Allows you to select specific vulnerability types to scan for",
        duration: "Varies"
      }
    ],
    vulnerabilityTypes: [
      "SQL Injection",
      "Cross-Site Scripting (XSS)",
      "Cross-Site Request Forgery (CSRF)",
      "Insecure Direct Object References (IDOR)",
      "Security Misconfiguration",
      "Broken Authentication",
      "Sensitive Data Exposure",
      "XML External Entities (XXE)",
      "Broken Access Control",
      "Insufficient Logging & Monitoring"
    ]
  });
});

// Scan endpoints
app.post('/api/scan/sql', authenticateToken, (req, res) => {
  try {
    const { target, payload } = req.body;
    const userId = req.user.id;
    
    if (!target || !payload) {
      return res.status(400).json({ error: 'Target and payload are required' });
    }
    
    // Simulate SQL injection scan
    const vulnerabilitiesFound = Math.random() > 0.5 ? 1 : 0;
    const result = vulnerabilitiesFound 
      ? "Vulnerability found! The application is susceptible to SQL injection attacks."
      : "No vulnerabilities found. The application appears to be secure against SQL injection.";
    
    // Save scan result
    db.run('INSERT INTO scan_results (user_id, scan_type, target, result, vulnerabilities_found) VALUES (?, ?, ?, ?, ?)',
      [userId, 'SQL Injection', target, result, vulnerabilitiesFound],
      function(err) {
        if (err) {
          logError('Save scan result', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        // Log activity
        db.run('INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
          [userId, 'SCAN', 'SQL Injection scan performed'],
          (err) => {
            if (err) logError('Activity logging', err);
          }
        );
        
        res.json({
          success: true,
          vulnerabilitiesFound,
          result
        });
      }
    );
  } catch (err) {
    logError('SQL scan', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add similar endpoints for other scan types...

// Catch-all route for frontend SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Start server
const startServer = async () => {
  try {
    await initializeDatabase();
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    logError('Server startup', err);
    process.exit(1);
  }
};

startServer();
