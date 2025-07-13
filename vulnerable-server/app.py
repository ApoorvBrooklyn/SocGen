#!/usr/bin/env python3
"""
Dynamic Vulnerable Server for Security Testing
This server contains intentional security vulnerabilities and generates real-time threats
that can be detected by the main security platform.
"""

from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
from flask_cors import CORS
import sqlite3
import subprocess
import os
import pickle
import base64
import hashlib
import re
import json
import uuid
import time
import threading
import random
from datetime import datetime, timedelta
from contextlib import contextmanager

app = Flask(__name__)
app.secret_key = 'super_secret_key_123'  # Weak secret key

# Enable CORS for all routes
CORS(app, origins=["http://localhost:3000", "http://localhost:5173"], 
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True)

# Global variables to track threats and vulnerabilities
active_threats = {}
vulnerability_log = []
attack_attempts = []
exploit_activities = []

# Database lock for thread safety
db_lock = threading.Lock()

@contextmanager
def get_db_connection():
    """Context manager for database connections with proper locking"""
    with db_lock:
        conn = sqlite3.connect('vuln_app.db', timeout=30.0)
        try:
            yield conn
        finally:
            conn.close()

def execute_db_query(query, params=None, fetch=None):
    """Execute database query with retry logic and proper error handling"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if fetch == 'all':
                    result = cursor.fetchall()
                elif fetch == 'one':
                    result = cursor.fetchone()
                else:
                    result = None
                
                conn.commit()
                return result
        except sqlite3.OperationalError as e:
            if 'database is locked' in str(e) and attempt < max_retries - 1:
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
                continue
            else:
                print(f"Database error after {attempt + 1} attempts: {e}")
                raise
        except Exception as e:
            print(f"Unexpected database error: {e}")
            raise

# Initialize SQLite database
def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                session_token TEXT,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0
            )
        ''')
        
        # Create posts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                user_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_malicious BOOLEAN DEFAULT 0
            )
        ''')
        
        # Create comments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY,
                post_id INTEGER,
                content TEXT NOT NULL,
                author TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_malicious BOOLEAN DEFAULT 0
            )
        ''')
        
        # Create vulnerability_events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_events (
                id INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source_ip TEXT,
                user_agent TEXT,
                payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                cve_id TEXT,
                exploit_success BOOLEAN DEFAULT 0
            )
        ''')
        
        # Create active_threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_threats (
                id INTEGER PRIMARY KEY,
                threat_id TEXT UNIQUE NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                target_endpoint TEXT,
                payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                detection_count INTEGER DEFAULT 1,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Insert test data if not exists
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
                          ('admin', 'admin123', 'admin@test.com', True))
            cursor.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
                          ('user', 'password123', 'user@test.com', False))
            cursor.execute("INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)",
                          ('Welcome Post', '<script>alert("XSS Test")</script>', 1))
            cursor.execute("INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)",
                          ('Test Post', 'This is a test post with some content.', 2))
        
        conn.commit()

def log_vulnerability_event(event_type, severity, description, source_ip=None, user_agent=None, payload=None, cve_id=None, exploit_success=False):
    """Log vulnerability events for analysis"""
    try:
        execute_db_query(
            '''INSERT INTO vulnerability_events 
               (event_type, severity, description, source_ip, user_agent, payload, cve_id, exploit_success)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (event_type, severity, description, source_ip, user_agent, payload, cve_id, exploit_success)
        )
        
        # Add to global vulnerability log
        vulnerability_log.append({
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'description': description,
            'source_ip': source_ip,
            'user_agent': user_agent,
            'payload': payload,
            'cve_id': cve_id,
            'exploit_success': exploit_success
        })
    except Exception as e:
        print(f"Error logging vulnerability event: {e}")

def create_active_threat(threat_type, severity, description, target_endpoint, payload=None):
    """Create an active threat that can be detected"""
    threat_id = str(uuid.uuid4())
    
    try:
        execute_db_query(
            '''INSERT INTO active_threats 
               (threat_id, threat_type, severity, description, target_endpoint, payload)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (threat_id, threat_type, severity, description, target_endpoint, payload)
        )
        
        # Add to global active threats
        active_threats[threat_id] = {
            'threat_id': threat_id,
            'threat_type': threat_type,
            'severity': severity,
            'description': description,
            'target_endpoint': target_endpoint,
            'payload': payload,
            'created_at': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'detection_count': 1,
            'is_active': True
        }
        
        return threat_id
    except Exception as e:
        print(f"Error creating active threat: {e}")
        return None

def generate_cve_from_exploit(exploit_type, severity, description, payload=None):
    """Generate a CVE-like record from successful exploitation"""
    cve_id = f"CVE-2024-{random.randint(1000, 9999)}"
    
    cve_data = {
        'id': cve_id,
        'title': f"{exploit_type} Vulnerability in Vulnerable Server",
        'description': description,
        'severity': severity,
        'cvss_score': {
            'Critical': random.uniform(9.0, 10.0),
            'High': random.uniform(7.0, 8.9),
            'Medium': random.uniform(4.0, 6.9),
            'Low': random.uniform(0.1, 3.9)
        }.get(severity, 5.0),
        'published_date': datetime.now().isoformat(),
        'last_updated': datetime.now().isoformat(),
        'exploit_available': True,
        'exploit_complexity': 'Low' if severity in ['Critical', 'High'] else 'Medium',
        'affected_products': ['Vulnerable Server 1.0'],
        'attack_vector': 'Network',
        'payload': payload,
        'remediation_steps': [
            'Apply input validation',
            'Implement proper authentication',
            'Update to latest security patches',
            'Configure web application firewall'
        ],
        'business_impact': {
            'Critical': 'Complete system compromise possible',
            'High': 'Significant data breach risk',
            'Medium': 'Moderate security risk',
            'Low': 'Limited security impact'
        }.get(severity, 'Security risk identified'),
        'source': 'vulnerable-server',
        'created_at': datetime.now().isoformat()
    }
    
    return cve_data

# Background threat generator
def generate_threats():
    """Generate realistic threats in the background"""
    while True:
        try:
            # Generate SQL injection threat
            if random.random() < 0.3:  # 30% chance
                threat_id = create_active_threat(
                    'SQL Injection',
                    'High',
                    'SQL injection vulnerability detected in search functionality',
                    '/search',
                    "' OR 1=1 --"
                )
                log_vulnerability_event(
                    'SQL_INJECTION_ATTEMPT',
                    'High',
                    'SQL injection payload detected',
                    payload="' OR 1=1 --",
                    cve_id=f"CVE-2024-{random.randint(1000, 9999)}",
                    exploit_success=True
                )
            
            # Generate XSS threat
            if random.random() < 0.4:  # 40% chance
                threat_id = create_active_threat(
                    'Cross-Site Scripting',
                    'Medium',
                    'XSS vulnerability in post content',
                    '/posts',
                    '<script>alert("XSS")</script>'
                )
                log_vulnerability_event(
                    'XSS_ATTEMPT',
                    'Medium',
                    'XSS payload injected in post',
                    payload='<script>alert("XSS")</script>',
                    cve_id=f"CVE-2024-{random.randint(1000, 9999)}",
                    exploit_success=True
                )
            
            # Generate command injection threat
            if random.random() < 0.2:  # 20% chance
                threat_id = create_active_threat(
                    'Command Injection',
                    'Critical',
                    'Command injection in ping functionality',
                    '/ping',
                    'localhost; cat /etc/passwd'
                )
                log_vulnerability_event(
                    'COMMAND_INJECTION_ATTEMPT',
                    'Critical',
                    'Command injection payload executed',
                    payload='localhost; cat /etc/passwd',
                    cve_id=f"CVE-2024-{random.randint(1000, 9999)}",
                    exploit_success=True
                )
            
            # Generate information disclosure threat
            if random.random() < 0.5:  # 50% chance
                threat_id = create_active_threat(
                    'Information Disclosure',
                    'High',
                    'Sensitive user data exposed via API',
                    '/api/users',
                    None
                )
                log_vulnerability_event(
                    'INFO_DISCLOSURE',
                    'High',
                    'Sensitive user data accessed',
                    cve_id=f"CVE-2024-{random.randint(1000, 9999)}",
                    exploit_success=True
                )
            
            time.sleep(random.randint(10, 30))  # Wait 10-30 seconds before next threat
            
        except Exception as e:
            print(f"Error generating threats: {e}")
            time.sleep(5)

# Start background threat generator
threat_thread = threading.Thread(target=generate_threats, daemon=True)
threat_thread.start()

# HTML template with vulnerabilities
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .vuln-section { background: #f0f0f0; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .danger { background: #ffebee; border-left: 4px solid #f44336; }
        .warning { background: #fff3e0; border-left: 4px solid #ff9800; }
        .success { background: #e8f5e8; border-left: 4px solid #4caf50; }
        input, textarea, select { width: 100%; padding: 10px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #4CAF50; color: white; padding: 10px 20px; border: none; cursor: pointer; border-radius: 4px; }
        button:hover { background: #45a049; }
        .user-input { color: red; font-weight: bold; background: #ffe6e6; padding: 10px; border-radius: 4px; }
        .nav { background: #333; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .nav a { color: white; text-decoration: none; margin-right: 20px; }
        .nav a:hover { color: #ddd; }
        .post { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .comment { background: #f9f9f9; padding: 10px; margin: 5px 0; border-radius: 4px; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 Vulnerable Web Application</h1>
        <p><strong>WARNING:</strong> This application contains intentional security vulnerabilities for testing!</p>
        
        <div class="nav">
            <a href="/">🏠 Home</a>
            <a href="/login">🔐 Login</a>
            <a href="/register">📝 Register</a>
            <a href="/posts">📄 Posts</a>
            <a href="/search">🔍 Search</a>
            <a href="/admin">⚙️ Admin</a>
            <a href="/upload">📁 Upload</a>
            <a href="/api/users">🔌 API</a>
            <a href="/ping">🏓 Ping</a>
            <a href="/file">📂 File</a>
            <a href="/comments">💬 Comments</a>
        </div>
        
        <div class="content">
            {% block content %}{% endblock %}
        </div>
        
        <div class="vuln-section danger">
            <h3>🚨 Known Vulnerabilities:</h3>
            <ul>
                <li><strong>SQL Injection:</strong> Search, login, comments</li>
                <li><strong>XSS:</strong> Posts, comments, user input display</li>
                <li><strong>Command Injection:</strong> Ping feature</li>
                <li><strong>Path Traversal:</strong> File access</li>
                <li><strong>Weak Authentication:</strong> Plain text passwords</li>
                <li><strong>Insecure File Upload:</strong> No validation</li>
                <li><strong>Information Disclosure:</strong> API exposes sensitive data</li>
                <li><strong>CSRF:</strong> No CSRF protection</li>
                <li><strong>IDOR:</strong> Direct object references</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE, title="Home", content="""
        <h2>Welcome to the Vulnerable Web Application</h2>
        <p>This application is designed for security testing and contains intentional vulnerabilities.</p>
        
        <div class="vuln-section warning">
            <h3>🧪 Test Features:</h3>
            <ul>
                <li><a href="/search?q=test">🔍 Search with SQL Injection</a></li>
                <li><a href="/posts">📄 View posts with XSS</a></li>
                <li><a href="/ping?host=localhost">🏓 Ping with Command Injection</a></li>
                <li><a href="/file?path=/etc/passwd">📂 File access with Path Traversal</a></li>
                <li><a href="/api/users">🔌 API with Information Disclosure</a></li>
                <li><a href="/comments">💬 Comments with XSS</a></li>
                <li><a href="/admin">⚙️ Admin panel with weak access control</a></li>
            </ul>
        </div>
        
        <div class="vuln-section success">
            <h3>🎯 Test Credentials:</h3>
            <ul>
                <li><strong>Admin:</strong> admin / admin123</li>
                <li><strong>User:</strong> user / password123</li>
            </ul>
        </div>
    """)

# SQL Injection vulnerability
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Check for SQL injection attempts
    sql_injection_patterns = ["'", "OR", "UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE", "--", ";"]
    is_sql_injection = any(pattern.upper() in query.upper() for pattern in sql_injection_patterns)
    
    if is_sql_injection:
        # Log SQL injection attempt
        log_vulnerability_event(
            'SQL_INJECTION_ATTEMPT',
            'High',
            f'SQL injection attempt detected in search query',
            source_ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            payload=query,
            cve_id=f"CVE-2024-{random.randint(1000, 9999)}",
            exploit_success=True
        )
        
        # Create active threat
        create_active_threat(
            'SQL Injection',
            'High',
            'SQL injection vulnerability exploited in search functionality',
            '/search',
            query
        )
    
    # VULNERABLE: Direct string concatenation in SQL
    if query:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            sql = f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
            try:
                cursor.execute(sql)
                posts = cursor.fetchall()
            except:
                posts = []
    else:
        posts = []
    
    content = """
        <h2>Search Results for: {{ query }}</h2>
        <form method="GET">
            <input type="text" name="q" value="{{ query }}" placeholder="Search posts...">
            <button type="submit">Search</button>
        </form>
        
        <div class="user-input">
            <h3>Your search query: {{ query }}</h3>
        </div>
        
        <h3>Results:</h3>
        <ul>
        {% for post in posts %}
            <li><strong>{{ post[1] }}</strong> - {{ post[2][:100] }}...</li>
        {% endfor %}
        </ul>
    """
    return render_template_string(HTML_TEMPLATE, title="Search Results", content=content, posts=posts, query=query)

# XSS vulnerability
@app.route('/posts')
def posts():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM posts ORDER BY created_at DESC")
        posts = cursor.fetchall()
    return render_template_string(HTML_TEMPLATE, title="Posts", content="""
        <h2>Posts</h2>
        <div class="posts">
        {% for post in posts %}
            <div class="post">
                <h3>{{ post[1] }}</h3>
                <p>{{ post[2] | safe }}</p>
                <small>Posted by user ID: {{ post[3] }} | Created: {{ post[4] }}</small>
            </div>
        {% endfor %}
        </div>
        
        <h3>Add New Post</h3>
        <form method="POST" action="/add_post">
            <input type="text" name="title" placeholder="Post title">
            <textarea name="content" placeholder="Post content"></textarea>
            <button type="submit">Add Post</button>
        </form>
    """, posts=posts)

@app.route('/add_post', methods=['POST'])
def add_post():
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    
    # Check for XSS attempts
    xss_patterns = ["<script", "javascript:", "onerror", "onload", "alert(", "document.cookie", "eval("]
    is_xss = any(pattern.lower() in content.lower() or pattern.lower() in title.lower() for pattern in xss_patterns)
    
    if is_xss:
        # Log XSS attempt
        log_vulnerability_event(
            'XSS_ATTEMPT',
            'Medium',
            f'XSS payload detected in post content',
            source_ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            payload=content,
            cve_id=f"CVE-2024-{random.randint(1000, 9999)}",
            exploit_success=True
        )
        
        # Create active threat
        create_active_threat(
            'Cross-Site Scripting',
            'Medium',
            'XSS vulnerability exploited in post content',
            '/add_post',
            content
        )
    
    # VULNERABLE: No input validation or sanitization
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO posts (title, content, user_id, is_malicious) VALUES (?, ?, ?, ?)", (title, content, 1, is_xss))
    return redirect(url_for('posts'))

# Command Injection vulnerability
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    
    # Check for command injection attempts
    command_injection_patterns = [";", "&&", "||", "|", "`", "$", "cat", "ls", "pwd", "whoami", "id", "uname", "nc", "wget", "curl"]
    is_command_injection = any(pattern in host for pattern in command_injection_patterns)
    
    if is_command_injection:
        # Log command injection attempt
        log_vulnerability_event(
            'COMMAND_INJECTION_ATTEMPT',
            'Critical',
            f'Command injection attempt detected in ping functionality',
            source_ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            payload=host,
            cve_id=f"CVE-2024-{random.randint(1000, 9999)}",
            exploit_success=True
        )
        
        # Create active threat
        create_active_threat(
            'Command Injection',
            'Critical',
            'Command injection vulnerability exploited in ping functionality',
            '/ping',
            host
        )
    
    # VULNERABLE: Command injection
    try:
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
        output = result
    except:
        output = f"Failed to ping {host}"
    
    content = """
        <h2>Ping Results</h2>
        <form method="GET">
            <input type="text" name="host" value="{{ host }}" placeholder="Host to ping">
            <button type="submit">Ping</button>
        </form>
        
        <div class="user-input">
            <h3>Pinging: {{ host }}</h3>
        </div>
        
        <pre>{{ output }}</pre>
    """
    return render_template_string(HTML_TEMPLATE, title="Ping Results", content=content, host=host, output=output)

# Path Traversal vulnerability
@app.route('/file')
def read_file():
    file_path = request.args.get('path', '/etc/passwd')
    
    # VULNERABLE: Path traversal
    try:
        with open(file_path, 'r') as f:
            content_file = f.read()
    except:
        content_file = f"Error reading file: {file_path}"
    
    content = """
        <h2>File Content</h2>
        <form method="GET">
            <input type="text" name="path" value="{{ file_path }}" placeholder="File path">
            <button type="submit">Read File</button>
        </form>
        
        <div class="user-input">
            <h3>Reading: {{ file_path }}</h3>
        </div>
        
        <pre>{{ content_file }}</pre>
    """
    return render_template_string(HTML_TEMPLATE, title="File Content", content=content, file_path=file_path, content_file=content_file)

# Weak authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Check for SQL injection in login
        sql_injection_patterns = ["'", "OR", "UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE", "--", ";"]
        is_sql_injection = any(pattern.upper() in username.upper() or pattern.upper() in password.upper() for pattern in sql_injection_patterns)
        
        if is_sql_injection:
            # Log SQL injection attempt in login
            log_vulnerability_event(
                'SQL_INJECTION_LOGIN_ATTEMPT',
                'Critical',
                f'SQL injection attempt detected in login form',
                source_ip=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                payload=f"username: {username}, password: {password}",
                cve_id=f"CVE-2024-{random.randint(1000, 9999)}",
                exploit_success=True
            )
            
            # Create active threat
            create_active_threat(
                'SQL Injection',
                'Critical',
                'SQL injection vulnerability exploited in login form',
                '/login',
                f"username: {username}, password: {password}"
            )
        
        # VULNERABLE: Weak authentication with SQL injection
        with get_db_connection() as conn:
            cursor = conn.cursor()
            sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            cursor.execute(sql)
            user = cursor.fetchone()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[4]
            
            # Log successful login
            log_vulnerability_event(
                'AUTHENTICATION_SUCCESS',
                'Low',
                f'User {username} successfully logged in',
                source_ip=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                exploit_success=False
            )
            
            return redirect(url_for('home'))
        else:
            error = "Invalid credentials"
            
            # Log failed login attempt
            log_vulnerability_event(
                'AUTHENTICATION_FAILURE',
                'Medium',
                f'Failed login attempt for username: {username}',
                source_ip=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                payload=f"username: {username}",
                exploit_success=False
            )
    else:
        error = ""
    
    content = """
        <h2>Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
        <p style="color: red;">{{ error }}</p>
    """
    return render_template_string(HTML_TEMPLATE, title="Login", content=content, error=error)

# Insecure file upload
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file.filename:
                # VULNERABLE: No file type validation
                filename = file.filename
                file.save(f"uploads/{filename}")
                message = f"File {filename} uploaded successfully!"
            else:
                message = "No file selected"
        else:
            message = "No file uploaded"
    else:
        message = ""
    
    content = """
        <h2>File Upload</h2>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file">
            <button type="submit">Upload</button>
        </form>
        <p>{{ message }}</p>
    """
    return render_template_string(HTML_TEMPLATE, title="File Upload", content=content, message=message)

# Information disclosure
@app.route('/api/users')
def api_users():
    # Log information disclosure attempt
    log_vulnerability_event(
        'INFO_DISCLOSURE_ATTEMPT',
        'High',
        'Sensitive user data accessed via API endpoint',
        source_ip=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        cve_id=f"CVE-2024-{random.randint(1000, 9999)}",
        exploit_success=True
    )
    
    # Create active threat
    create_active_threat(
        'Information Disclosure',
        'High',
        'Sensitive user data exposed via API endpoint',
        '/api/users',
        'User passwords and sensitive data exposed'
    )
    
    # VULNERABLE: Information disclosure
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
    
    user_data = []
    for user in users:
        user_data.append({
            'id': user[0],
            'username': user[1],
            'password': user[2],  # Exposing passwords!
            'email': user[3],
            'is_admin': user[4]
        })
    
    return jsonify({'users': user_data})

# Admin panel with weak access control
@app.route('/admin')
def admin():
    # VULNERABLE: Weak access control
    if session.get('is_admin'):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users")
            users = cursor.fetchall()
        
        content = """
            <h2>Admin Panel</h2>
            <h3>All Users:</h3>
            <ul>
            {% for user in users %}
                <li>{{ user[1] }} ({{ user[3] }}) - Password: {{ user[2] }}</li>
            {% endfor %}
            </ul>
        """
        return render_template_string(HTML_TEMPLATE, title="Admin Panel", content=content, users=users)
    else:
        return render_template_string(HTML_TEMPLATE, title="Access Denied", content="""
            <h2>Access Denied</h2>
            <p>You need admin privileges to access this page.</p>
        """)

# Comments with XSS
@app.route('/comments')
def comments():
    post_id = request.args.get('post_id', 1)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM comments WHERE post_id = ? ORDER BY created_at DESC", (post_id,))
        comments = cursor.fetchall()
    
    content = """
        <h2>Comments</h2>
        <div class="comments">
        {% for comment in comments %}
            <div class="comment">
                <strong>{{ comment[3] }}</strong> says:
                <p>{{ comment[2] | safe }}</p>
                <small>{{ comment[4] }}</small>
            </div>
        {% endfor %}
        </div>
        
        <h3>Add Comment</h3>
        <form method="POST" action="/add_comment">
            <input type="hidden" name="post_id" value="{{ post_id }}">
            <input type="text" name="author" placeholder="Your name">
            <textarea name="content" placeholder="Comment content"></textarea>
            <button type="submit">Add Comment</button>
        </form>
    """
    return render_template_string(HTML_TEMPLATE, title="Comments", content=content, comments=comments, post_id=post_id)

@app.route('/add_comment', methods=['POST'])
def add_comment():
    post_id = request.form.get('post_id', 1)
    author = request.form.get('author', 'Anonymous')
    content = request.form.get('content', '')
    
    # VULNERABLE: No input validation or sanitization
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO comments (post_id, content, author) VALUES (?, ?, ?)", (post_id, content, author))
    return redirect(url_for('comments', post_id=post_id))

# Health check endpoint
@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'vulnerable-server'
    })

# API endpoints for the main project to scan and detect vulnerabilities
@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """API endpoint to get current vulnerabilities"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM vulnerability_events ORDER BY created_at DESC LIMIT 50')
        events = cursor.fetchall()
    
    vulnerabilities = []
    for event in events:
        vulnerabilities.append({
            'id': event[0],
            'event_type': event[1],
            'severity': event[2],
            'description': event[3],
            'source_ip': event[4],
            'user_agent': event[5],
            'payload': event[6],
            'created_at': event[7],
            'cve_id': event[8],
            'exploit_success': event[9]
        })
    
    return jsonify({
        'vulnerabilities': vulnerabilities,
        'total_count': len(vulnerabilities),
        'active_threats': len(active_threats),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/threats')
def get_active_threats():
    """API endpoint to get active threats"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM active_threats WHERE is_active = 1 ORDER BY created_at DESC')
        threats = cursor.fetchall()
    
    active_threats_list = []
    for threat in threats:
        active_threats_list.append({
            'id': threat[0],
            'threat_id': threat[1],
            'threat_type': threat[2],
            'severity': threat[3],
            'description': threat[4],
            'target_endpoint': threat[5],
            'payload': threat[6],
            'created_at': threat[7],
            'last_seen': threat[8],
            'detection_count': threat[9],
            'is_active': threat[10]
        })
    
    return jsonify({
        'active_threats': active_threats_list,
        'total_count': len(active_threats_list),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/generate_cve')
def generate_cve():
    """API endpoint to generate a CVE from current threats"""
    if not active_threats:
        return jsonify({'error': 'No active threats to generate CVE from'}), 404
    
    # Select a random active threat
    threat_id = random.choice(list(active_threats.keys()))
    threat = active_threats[threat_id]
    
    # Generate CVE from the threat
    cve_data = generate_cve_from_exploit(
        threat['threat_type'],
        threat['severity'],
        threat['description'],
        threat['payload']
    )
    
    return jsonify({
        'cve': cve_data,
        'source_threat': threat,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/scan_status')
def scan_status():
    """API endpoint for scan status"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Get recent vulnerability events
        cursor.execute('SELECT event_type, severity, COUNT(*) FROM vulnerability_events WHERE created_at > datetime("now", "-1 hour") GROUP BY event_type, severity')
        recent_events = cursor.fetchall()
        
        # Get active threats count
        cursor.execute('SELECT COUNT(*) FROM active_threats WHERE is_active = 1')
        active_threat_count = cursor.fetchone()[0]
    
    return jsonify({
        'status': 'vulnerable',
        'active_threats': active_threat_count,
        'recent_events': [{'type': e[0], 'severity': e[1], 'count': e[2]} for e in recent_events],
        'vulnerabilities_found': len(vulnerability_log),
        'last_scan': datetime.now().isoformat(),
        'risk_score': min(100, active_threat_count * 15 + len(vulnerability_log) * 2)
    })

@app.route('/api/exploit_test', methods=['POST'])
def exploit_test():
    """API endpoint to test specific exploits"""
    data = request.get_json()
    exploit_type = data.get('exploit_type')
    payload = data.get('payload')
    
    if not exploit_type or not payload:
        return jsonify({'error': 'Missing exploit_type or payload'}), 400
    
    # Log the exploit attempt
    log_vulnerability_event(
        f'{exploit_type.upper()}_TEST',
        'High',
        f'Exploit test for {exploit_type}',
        source_ip=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        payload=payload,
        exploit_success=True
    )
    
    # Create active threat
    threat_id = create_active_threat(
        exploit_type,
        'High',
        f'Exploit test: {exploit_type}',
        '/api/exploit_test',
        payload
    )
    
    # Generate CVE
    cve_data = generate_cve_from_exploit(
        exploit_type,
        'High',
        f'Exploit test vulnerability: {exploit_type}',
        payload
    )
    
    return jsonify({
        'success': True,
        'exploit_type': exploit_type,
        'payload': payload,
        'threat_id': threat_id,
        'cve_generated': cve_data,
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    # Create uploads directory
    os.makedirs('uploads', exist_ok=True)
    
    # Initialize database
    init_db()
    
    print("🚀 Vulnerable Server Starting...")
    print("📍 URL: http://localhost:5000")
    print("🔓 Admin: admin / admin123")
    print("👤 User: user / password123")
    print("⚠️  WARNING: This server contains intentional vulnerabilities!")
    
    app.run(host='0.0.0.0', port=5000, debug=True) 