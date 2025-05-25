SecurePen 2.0 - Penetration Testing Lab

SecurePen 2.0 is a user-friendly platform for ethical hacking practice. Test vulnerabilities in a safe, local environment.
Features

Vulnerabilities: SQL Injection, XSS, Brute Force.
Modern UI: Responsive design with progress tracking.
User-Friendly: Guided tutorials and welcome modal.

Prerequisites

Docker Desktop (Windows/macOS) or Docker (Linux)
Docker Compose
Git Bash or WSL 2 (Windows)

Setup

Create Files:
Manually create the directory structure and files as described below.
Fix line endings:dos2unix securepen/frontend/* securepen/backend/* securepen/docker-compose.yml securepen/Dockerfile.frontend securepen/Dockerfile.backend securepen/README.md


Navigate to project:cd securepen




Run Application:docker-compose up -d


Access: Open http://localhost:8080.

Manual File Creation

Create directories:mkdir -p ~/securepen/frontend ~/securepen/backend
cd ~/securepen


Create files with a text editor (e.g., Notepad, VS Code, or nano):
frontend/index.html
frontend/script.js
frontend/styles.css
frontend/nginx.conf
backend/server.js
backend/package.json
docker-compose.yml
Dockerfile.frontend
Dockerfile.backend
README.md


Copy the content for each file from the provided source.
Fix line endings:sed -i 's/\r$//' frontend/* backend/* docker-compose.yml Dockerfile.frontend Dockerfile.backend README.md



Usage

Welcome Modal: Guides you on first visit.
Dashboard: View tests run, vulnerabilities exploited, success rate.
Vulnerabilities:
SQL Injection: username: ' OR '1'='1, any password.
XSS: <script>alert('XSS')</script> in comment.
Brute Force: username: admin, wordlist with password123.


Tooltips: Hover over ℹ️ for hints.

Stop
docker-compose down

Troubleshooting

Docker Issues:
Check logs: docker logs securepen-backend.
Ensure Docker Desktop is running.
Fix permissions: chmod 666 backend/vulnerabilities.db.


Network Errors:
Test backend: curl http://localhost:3000.
Change ports in docker-compose.yml (e.g., 8081:80).


Browser Issues:
Clear local storage: Developer Tools > Application > Local Storage > Clear.
Disable ad blockers for Tailwind CDN.



License
Educational use only.
