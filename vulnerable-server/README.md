# 🔓 Vulnerable Web Application

A simple web application with intentional security vulnerabilities for testing your security platform.

## 🚀 Quick Start

### 1. Setup
```bash
# Make setup script executable
chmod +x setup.sh

# Run setup
./setup.sh
```

### 2. Start the Server
```bash
# Activate virtual environment
source venv/bin/activate

# Start the server
python app.py
```

### 3. Access the Application
- **URL**: http://localhost:5000
- **Admin**: admin / admin123
- **User**: user / password123

## 🧪 Testing Vulnerabilities

### Manual Testing
Visit the application and explore different features to discover vulnerabilities:

1. **Search Page**: Try SQL injection payloads
2. **Posts**: Add posts with XSS payloads
3. **Ping**: Test command injection
4. **File Access**: Try path traversal
5. **API**: Check for information disclosure
6. **Login**: Test weak authentication
7. **Upload**: Test file upload vulnerabilities

### Automated Testing
Run the test script to automatically test all vulnerabilities:

```bash
# Install requests if not already installed
pip install requests

# Run tests
python test_attacks.py
```

## 🚨 Known Vulnerabilities

### 1. SQL Injection
- **Location**: Search page, Login page
- **Payloads**:
  - `' OR 1=1 --`
  - `' UNION SELECT * FROM users --`
  - `'; DROP TABLE posts; --`

### 2. Cross-Site Scripting (XSS)
- **Location**: Posts, Comments
- **Payloads**:
  - `<script>alert('XSS')</script>`
  - `<img src=x onerror=alert('XSS')>`
  - `<svg onload=alert('XSS')>`

### 3. Command Injection
- **Location**: Ping feature
- **Payloads**:
  - `localhost; ls -la`
  - `localhost && whoami`
  - `localhost | cat /etc/passwd`

### 4. Path Traversal
- **Location**: File access
- **Payloads**:
  - `../../../etc/passwd`
  - `..\\..\\..\\windows\\system32\\drivers\\etc\\hosts`

### 5. Information Disclosure
- **Location**: API endpoints
- **Issue**: Exposes user passwords and sensitive data

### 6. Weak Authentication
- **Location**: Login system
- **Issues**: Plain text passwords, SQL injection in login

### 7. Insecure File Upload
- **Location**: Upload feature
- **Issues**: No file type validation, no size limits

### 8. Missing CSRF Protection
- **Location**: All forms
- **Issue**: No CSRF tokens

### 9. Insecure Direct Object References (IDOR)
- **Location**: Admin panel
- **Issue**: Weak access control

## 🔧 Integration with Security Platform

### 1. Add to Your Security Platform
Update your security platform's configuration to include this vulnerable server:

```python
# In your security platform configuration
VULNERABLE_TARGETS = [
    {
        'name': 'Vulnerable Test Server',
        'url': 'http://localhost:5000',
        'description': 'Local test server with intentional vulnerabilities'
    }
]
```

### 2. Scan for Vulnerabilities
Use your security platform to scan this server:

```python
# Example scanning code
def scan_vulnerable_server():
    target = "http://localhost:5000"
    
    # Test SQL injection
    sql_payloads = ["' OR 1=1 --", "' UNION SELECT * FROM users --"]
    
    # Test XSS
    xss_payloads = ["<script>alert('XSS')</script>"]
    
    # Test command injection
    cmd_payloads = ["localhost; ls -la"]
    
    # Run scans and generate reports
    results = run_security_scans(target, sql_payloads, xss_payloads, cmd_payloads)
    return results
```

### 3. Generate CVE Reports
Create CVE entries for discovered vulnerabilities:

```python
# Example CVE creation
def create_cve_for_vulnerability(vuln_type, description, severity):
    cve_data = {
        'type': vuln_type,
        'description': description,
        'severity': severity,
        'target': 'http://localhost:5000',
        'discovered': datetime.now(),
        'status': 'open'
    }
    return cve_data
```

## 📊 Monitoring and Logging

The application includes basic logging. Check the console output for:
- Database operations
- File access attempts
- User authentication
- Error messages

## ⚠️ Security Warning

**IMPORTANT**: This application contains intentional security vulnerabilities for testing purposes only. 

- ❌ **NEVER** deploy this in production
- ❌ **NEVER** expose this to the internet
- ❌ **NEVER** use real credentials
- ✅ **ONLY** use in controlled testing environments
- ✅ **ONLY** use for security research and testing

## 🛠️ Customization

### Adding New Vulnerabilities
To add new vulnerabilities, modify `app.py`:

```python
@app.route('/new_vulnerable_endpoint')
def new_vulnerable_endpoint():
    # Add your vulnerable code here
    user_input = request.args.get('input', '')
    # VULNERABLE: No validation
    return user_input
```

### Modifying Existing Vulnerabilities
Each vulnerability is clearly marked with `# VULNERABLE:` comments in the code.

## 📝 File Structure

```
vulnerable-server/
├── app.py              # Main vulnerable application
├── requirements.txt    # Python dependencies
├── setup.sh           # Setup script
├── test_attacks.py    # Automated vulnerability tests
├── README.md          # This file
├── uploads/           # File upload directory
└── vuln_app.db        # SQLite database (created on first run)
```

## 🤝 Contributing

To add new vulnerabilities or improve the testing framework:

1. Fork the repository
2. Add your vulnerability or test
3. Update the documentation
4. Submit a pull request

## 📞 Support

For questions or issues with the vulnerable server:
- Check the console output for error messages
- Verify the server is running on port 5000
- Ensure all dependencies are installed
- Check that the database file is created properly 