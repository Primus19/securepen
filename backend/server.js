// Fixed backend server.js with proper CORS configuration for SecurePen application
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const morgan = require('morgan');

// Create express app
const app = express();
const PORT = process.env.PORT || 3000;

// Setup request logging
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });
app.use(morgan('combined', { stream: accessLogStream }));

// Enhanced CORS configuration - Fixed to allow credentials with specific origin
app.use(cors({
  origin: 'http://localhost:8000', // Specific origin instead of wildcard
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true // Allow credentials
}));

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from frontend directory
app.use(express.static(path.join(__dirname, '../frontend')));

// Setup database with absolute path to ensure consistency
const dbPath = path.resolve(__dirname, 'securepen.db');
console.log('Database path:', dbPath);

// Create database directory if it doesn't exist
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
  console.log(`Created database directory: ${dbDir}`);
}

// Connect to database with proper error handling
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
    process.exit(1); // Exit if database connection fails
  } else {
    console.log('Connected to the SQLite database at:', dbPath);
    setupDatabase();
  }
});

// Setup database tables with enhanced logging
function setupDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) {
        console.error('Error creating users table:', err.message);
      } else {
        console.log('Users table created or already exists');
        
        // Check if users table is empty and add a default admin user
        db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
          if (err) {
            console.error('Error checking users count:', err.message);
          } else {
            console.log('Current user count:', row.count);
            if (row.count === 0) {
              // Add default admin user for testing
              db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                ['admin', 'admin@securepen.com', 'admin123'], function(err) {
                  if (err) {
                    console.error('Error creating default admin user:', err.message);
                  } else {
                    console.log('Default admin user created with ID:', this.lastID);
                  }
                }
              );
            }
          }
        });
      }
    });

    // Tests table
    db.run(`CREATE TABLE IF NOT EXISTS tests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      module TEXT,
      result TEXT,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`, (err) => {
      if (err) {
        console.error('Error creating tests table:', err.message);
      } else {
        console.log('Tests table created or already exists');
      }
    });
  });
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  console.log('Health check requested');
  res.status(200).json({ status: 'ok', message: 'Server is running' });
});

// Authentication routes
app.post('/api/auth/register', (req, res) => {
  console.log('Registration request received:', req.body);
  
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      console.log('Missing required fields');
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Check if user already exists
    db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (err, row) => {
      if (err) {
        console.error('Database error during registration:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (row) {
        console.log('User already exists');
        return res.status(409).json({ error: 'User already exists' });
      }
      
      // Insert new user with enhanced error logging
      db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
        [username, email, password], function(err) {
          if (err) {
            console.error('Error creating user:', err.message);
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
          console.log('User registered successfully with ID:', this.lastID);
          
          // Verify user was actually created
          db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (err, user) => {
            if (err || !user) {
              console.error('User verification failed after creation:', err ? err.message : 'User not found');
              return res.status(500).json({ error: 'User creation verification failed' });
            }
            
            console.log('User verified after creation:', user.username);
            res.status(201).json({ 
              message: 'User registered successfully',
              userId: this.lastID 
            });
          });
        }
      );
    });
  } catch (error) {
    console.error('Unexpected error during registration:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', (req, res) => {
  console.log('Login request received:', req.body);
  
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Missing username or password' });
    }
    
    // Enhanced login query with better logging
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
      if (err) {
        console.error('Database error during login:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!row) {
        console.log('User not found during login attempt:', username);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Check password
      if (row.password !== password) {
        console.log('Invalid password for user:', username);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      console.log('User logged in successfully:', username);
      res.status(200).json({ 
        message: 'Login successful',
        user: {
          id: row.id,
          username: row.username,
          email: row.email
        }
      });
    });
  } catch (error) {
    console.error('Unexpected error during login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Module endpoints
app.get('/api/modules/sql', (req, res) => {
  res.json({
    title: 'SQL Injection Testing',
    description: 'Test applications for SQL injection vulnerabilities.',
    instructions: 'Enter a SQL injection payload in the input field below and click "Test".',
    examples: [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "' UNION SELECT username, password FROM users --"
    ],
    testCases: [
      {
        name: 'Basic Authentication Bypass',
        description: 'Attempts to bypass login authentication',
        payload: "' OR '1'='1"
      },
      {
        name: 'Data Extraction',
        description: 'Attempts to extract data from other tables',
        payload: "' UNION SELECT username, password FROM users --"
      },
      {
        name: 'Database Manipulation',
        description: 'Attempts to modify database structure',
        payload: "'; DROP TABLE users; --"
      }
    ]
  });
});

app.get('/api/modules/xss', (req, res) => {
  res.json({
    title: 'Cross-Site Scripting (XSS) Testing',
    description: 'Test applications for XSS vulnerabilities.',
    instructions: 'Enter an XSS payload in the input field below and click "Test".',
    examples: [
      "<script>alert('XSS')</script>",
      "<img src='x' onerror='alert(\"XSS\")'>",
      "<div onmouseover='alert(\"XSS\")'>Hover me</div>"
    ],
    testCases: [
      {
        name: 'Basic Script Injection',
        description: 'Attempts to inject and execute JavaScript',
        payload: "<script>alert('XSS')</script>"
      },
      {
        name: 'Event Handler Injection',
        description: 'Attempts to execute JavaScript via event handlers',
        payload: "<img src='x' onerror='alert(\"XSS\")'>"
      },
      {
        name: 'DOM-based XSS',
        description: 'Attempts to manipulate the DOM to execute JavaScript',
        payload: "<div onmouseover='alert(\"XSS\")'>Hover me</div>"
      }
    ]
  });
});

app.get('/api/modules/brute-force', (req, res) => {
  res.json({
    title: 'Brute Force Testing',
    description: 'Test applications for resistance to brute force attacks.',
    instructions: 'Enter a target URL and authentication parameters to test for brute force vulnerabilities.',
    examples: [
      "https://example.com/login",
      "https://example.com/admin",
      "https://example.com/wp-admin"
    ],
    testCases: [
      {
        name: 'Common Passwords',
        description: 'Tests using a list of common passwords',
        payload: "username=admin&password_list=common_passwords.txt"
      },
      {
        name: 'Dictionary Attack',
        description: 'Tests using a dictionary of potential passwords',
        payload: "username=admin&password_list=dictionary.txt"
      },
      {
        name: 'Credential Stuffing',
        description: 'Tests using known username/password combinations from data breaches',
        payload: "credential_list=breached_credentials.txt"
      }
    ]
  });
});

app.get('/api/modules/path-traversal', (req, res) => {
  res.json({
    title: 'Path Traversal Testing',
    description: 'Test applications for path traversal vulnerabilities.',
    instructions: 'Enter a path traversal payload in the input field below and click "Test".',
    examples: [
      "../../../etc/passwd",
      "..\\..\\..\\Windows\\system.ini",
      "....//....//....//etc/passwd"
    ],
    testCases: [
      {
        name: 'Unix File Access',
        description: 'Attempts to access sensitive Unix/Linux files',
        payload: "../../../etc/passwd"
      },
      {
        name: 'Windows File Access',
        description: 'Attempts to access sensitive Windows files',
        payload: "..\\..\\..\\Windows\\system.ini"
      },
      {
        name: 'Encoded Traversal',
        description: 'Attempts to bypass filters with encoded characters',
        payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
      }
    ]
  });
});

app.get('/api/modules/command-injection', (req, res) => {
  res.json({
    title: 'Command Injection Testing',
    description: 'Test applications for command injection vulnerabilities.',
    instructions: 'Enter a command injection payload in the input field below and click "Test".',
    examples: [
      "127.0.0.1; ls -la",
      "example.com && whoami",
      "localhost | cat /etc/passwd"
    ],
    testCases: [
      {
        name: 'Basic Command Injection',
        description: 'Attempts to execute basic system commands',
        payload: "127.0.0.1; ls -la"
      },
      {
        name: 'Chained Commands',
        description: 'Attempts to execute multiple commands',
        payload: "example.com && whoami"
      },
      {
        name: 'Piped Commands',
        description: 'Attempts to pipe command output',
        payload: "localhost | cat /etc/passwd"
      }
    ]
  });
});

app.get('/api/modules/scanner', (req, res) => {
  res.json({
    title: 'Vulnerability Scanner',
    description: 'Scan applications, networks, or systems for multiple types of security vulnerabilities.',
    instructions: 'Enter a target URL or IP address, select scan options, and click "Scan".',
    scanTypes: [
      {
        name: 'Quick Scan',
        description: 'Fast scan for common vulnerabilities',
        duration: '1-5 minutes'
      },
      {
        name: 'Comprehensive Scan',
        description: 'Detailed scan for a wide range of vulnerabilities',
        duration: '10-30 minutes'
      },
      {
        name: 'Advanced Scan',
        description: 'In-depth scan with custom options and thorough testing',
        duration: '30-60 minutes'
      }
    ],
    vulnerabilityTypes: [
      'SQL Injection',
      'XSS',
      'CSRF',
      'Path Traversal',
      'Command Injection',
      'Insecure Deserialization',
      'Broken Authentication',
      'Security Misconfigurations',
      'Sensitive Data Exposure',
      'XML External Entities (XXE)'
    ]
  });
});

// Test module endpoints
app.post('/api/test/sql', (req, res) => {
  const { payload, target } = req.body;
  console.log('SQL Injection test requested:', payload, target);
  
  // Simulate test result
  const vulnerable = payload.includes("'") || payload.includes(";");
  
  res.json({
    vulnerable,
    details: vulnerable ? 
      'The application appears to be vulnerable to SQL injection attacks.' : 
      'No SQL injection vulnerability detected with the provided payload.'
  });
});

app.post('/api/test/xss', (req, res) => {
  const { payload, target } = req.body;
  console.log('XSS test requested:', payload, target);
  
  // Simulate test result
  const vulnerable = payload.includes("<script>") || payload.includes("onerror=") || payload.includes("onmouseover=");
  
  res.json({
    vulnerable,
    details: vulnerable ? 
      'The application appears to be vulnerable to Cross-Site Scripting (XSS) attacks.' : 
      'No XSS vulnerability detected with the provided payload.'
  });
});

// Catch-all route for SPA
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API base URL: http://localhost:${PORT}/api`);
  console.log(`Frontend URL: http://localhost:${PORT}`);
  console.log(`Database path: ${dbPath}`);
  
  // Verify database tables after server start
  db.all("SELECT name FROM sqlite_master WHERE type='table'", (err, tables) => {
    if (err) {
      console.error('Error checking database tables:', err.message);
    } else {
      console.log('Database tables:', tables.map(t => t.name).join(', '));
    }
  });
});
