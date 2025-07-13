# 🔓 WebApp + Vulnerable Server Integration Guide

Your React+FastAPI security platform is now fully integrated with a vulnerable server for live vulnerability testing and simulation!

## 🚀 Quick Start

### 1. **Start the Vulnerable Server**
```bash
cd vulnerable-server
source venv/bin/activate
python app.py
```
- Server runs at: http://localhost:5000
- Admin: `admin` / `admin123`
- User: `user` / `password123`

### 2. **Start Your Backend (FastAPI)**
```bash
cd backend
source venv/bin/activate
python main.py
```
- Backend runs at: http://localhost:8000
- API docs: http://localhost:8000/docs

### 3. **Start Your Frontend (React)**
```bash
cd project
npm run dev
```
- Frontend runs at: http://localhost:5174

## 🔧 Integration Features

### **Frontend Integration (React)**

#### **1. Direct Vulnerable Server API (`vulnAPI`)**
Located in `project/src/services/api.ts`:

```typescript
// Test SQL injection
vulnAPI.search("' OR 1=1 --")

// Test XSS
vulnAPI.addPost("XSS Test", "<script>alert('XSS')</script>")

// Test command injection
vulnAPI.ping("localhost; ls -la")

// Test information disclosure
vulnAPI.getUsers()

// Test weak authentication
vulnAPI.login("admin' --", "anything")
```

#### **2. Vulnerability Tester Component**
Access via: **Vulnerability Tester** tab in your webapp

Features:
- ✅ Automated vulnerability testing
- ✅ SQL Injection, XSS, Command Injection, Path Traversal
- ✅ Information Disclosure, Weak Auth, IDOR, File Upload
- ✅ Real-time results and vulnerability detection
- ✅ Test selection and customization

#### **3. Backend Integration API (`vulnerableServerAPI`)**
```typescript
// Start comprehensive scan
vulnerableServerAPI.startScan({
  target_url: "http://localhost:5000",
  tests: ["sql_injection", "xss", "command_injection"]
})

// Quick scan
vulnerableServerAPI.quickScan()

// Check server health
vulnerableServerAPI.checkHealth()
```

### **Backend Integration (FastAPI)**

#### **New Endpoints Added:**
- `GET /api/v1/vulnerable-server/tests` - Get available test types
- `POST /api/v1/vulnerable-server/scan` - Start vulnerability scan
- `GET /api/v1/vulnerable-server/scan/{scan_id}/status` - Get scan status
- `GET /api/v1/vulnerable-server/health` - Check vulnerable server health
- `POST /api/v1/vulnerable-server/test-specific` - Test specific vulnerability
- `GET /api/v1/vulnerable-server/quick-scan` - Quick vulnerability scan

#### **Vulnerability Detection:**
- SQL Injection detection
- XSS payload detection
- Command injection detection
- Path traversal detection
- Information disclosure detection
- Weak authentication detection
- IDOR detection

## 🧪 Testing Scenarios

### **Scenario 1: Manual Testing**
1. Go to **Vulnerability Tester** in your webapp
2. Select tests you want to run
3. Click **"Run Vulnerability Tests"**
4. View real-time results and vulnerability detection

### **Scenario 2: Automated Backend Scanning**
1. Use the FastAPI endpoints to scan the vulnerable server
2. Integrate scan results into your security reports
3. Generate CVE entries for discovered vulnerabilities

### **Scenario 3: Custom Integration**
```typescript
// Example: Integrate vulnerable server testing into your existing components
import { vulnAPI, vulnerableServerAPI } from '../services/api';

// In your component
useEffect(() => {
  // Test vulnerable server on component load
  vulnAPI.getUsers().then(data => {
    console.log('Vulnerable users exposed:', data.users);
    // Create security alert or report
  });
}, []);
```

## 🔍 Available Vulnerabilities

### **1. SQL Injection**
- **Endpoints**: `/search`, `/login`
- **Payloads**: `' OR 1=1 --`, `' UNION SELECT * FROM users --`
- **Detection**: SQL errors in response

### **2. Cross-Site Scripting (XSS)**
- **Endpoints**: `/add_post`, `/add_comment`
- **Payloads**: `<script>alert('XSS')</script>`, `<img src=x onerror=alert('XSS')>`
- **Detection**: Script tags in response

### **3. Command Injection**
- **Endpoints**: `/ping`
- **Payloads**: `localhost; ls -la`, `localhost && whoami`
- **Detection**: Command output in response

### **4. Path Traversal**
- **Endpoints**: `/file`
- **Payloads**: `../../../etc/passwd`, `/etc/passwd`
- **Detection**: System file content in response

### **5. Information Disclosure**
- **Endpoints**: `/api/users`
- **Issue**: Exposes user passwords and sensitive data
- **Detection**: Password fields in API response

### **6. Weak Authentication**
- **Endpoints**: `/login`
- **Issue**: SQL injection in login, plain text passwords
- **Detection**: Successful login with SQL injection

### **7. Insecure File Upload**
- **Endpoints**: `/upload`
- **Issue**: No file type validation
- **Detection**: File upload without restrictions

### **8. IDOR (Insecure Direct Object References)**
- **Endpoints**: `/admin`
- **Issue**: Weak access control
- **Detection**: Admin panel access without proper auth

## 📊 Integration Benefits

### **For Security Testing:**
- ✅ Real-time vulnerability simulation
- ✅ Automated attack vector testing
- ✅ Live vulnerability detection
- ✅ Comprehensive security assessment

### **For Development:**
- ✅ Test security features in your platform
- ✅ Validate vulnerability detection algorithms
- ✅ Test CVE generation and reporting
- ✅ Practice security incident response

### **For Learning:**
- ✅ Understand common attack vectors
- ✅ Learn vulnerability detection techniques
- ✅ Practice security testing methodologies
- ✅ Develop security awareness

## 🛠️ Customization

### **Adding New Vulnerabilities:**
1. Modify `vulnerable-server/app.py` to add new vulnerable endpoints
2. Update `backend/app/api/v1/endpoints/vulnerable_server.py` with new test configurations
3. Add new test cases to `project/src/components/VulnerabilityTester.tsx`

### **Custom Test Payloads:**
```typescript
// Add custom payloads to VulnerabilityTester
const customPayloads = [
  "your-custom-sql-injection-payload",
  "your-custom-xss-payload"
];
```

### **Integration with Existing Components:**
```typescript
// Example: Add vulnerable server testing to Dashboard
import { vulnAPI } from '../services/api';

// In Dashboard component
const testVulnerableServer = async () => {
  try {
    const users = await vulnAPI.getUsers();
    // Handle the vulnerable data
    setSecurityAlert(`Found ${users.users.length} exposed users`);
  } catch (error) {
    console.error('Vulnerable server test failed:', error);
  }
};
```

## 🔒 Security Notes

### **Important Warnings:**
- ⚠️ **NEVER** deploy the vulnerable server to production
- ⚠️ **NEVER** expose it to the internet
- ⚠️ **ONLY** use in controlled testing environments
- ⚠️ **ALWAYS** use isolated networks for testing

### **Best Practices:**
- ✅ Use separate virtual environments
- ✅ Run on isolated local networks
- ✅ Monitor and log all test activities
- ✅ Clean up test data regularly

## 🎯 Next Steps

1. **Test the Integration**: Use the Vulnerability Tester component
2. **Explore Backend APIs**: Check the FastAPI docs at http://localhost:8000/docs
3. **Customize Tests**: Add your own vulnerability test cases
4. **Integrate with Reports**: Use scan results in your security reports
5. **Create CVE Entries**: Generate CVE reports for discovered vulnerabilities

## 📞 Support

If you encounter issues:
1. Check that all services are running (vulnerable server, backend, frontend)
2. Verify network connectivity between services
3. Check browser console for CORS errors
4. Review backend logs for API errors

---

**Your security platform is now ready for comprehensive vulnerability testing and simulation! 🚀** 