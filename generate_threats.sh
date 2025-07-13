#!/bin/bash

echo "🔥 Generating Multiple Real-Time Threats..."

# SQL Injection Threats
echo "🔴 Generating SQL Injection Threats..."
curl -s "http://localhost:5000/search?q=' OR 1=1 --" > /dev/null
curl -s "http://localhost:5000/search?q=' UNION SELECT * FROM users --" > /dev/null
curl -s "http://localhost:5000/search?q='; DROP TABLE posts; --" > /dev/null

# XSS Threats
echo "🟡 Generating XSS Threats..."
curl -s -X POST "http://localhost:5000/add_post" -H "Content-Type: application/x-www-form-urlencoded" -d "title=XSS Test 1&content=<script>alert('XSS 1')</script>" > /dev/null
curl -s -X POST "http://localhost:5000/add_post" -H "Content-Type: application/x-www-form-urlencoded" -d "title=XSS Test 2&content=<img src=x onerror=alert('XSS 2')>" > /dev/null
curl -s -X POST "http://localhost:5000/add_post" -H "Content-Type: application/x-www-form-urlencoded" -d "title=XSS Test 3&content=<svg onload=alert('XSS 3')>" > /dev/null

# Command Injection Threats
echo "🟠 Generating Command Injection Threats..."
curl -s "http://localhost:5000/ping?host=localhost; whoami" > /dev/null
curl -s "http://localhost:5000/ping?host=localhost && cat /etc/passwd" > /dev/null
curl -s "http://localhost:5000/ping?host=localhost | ls -la" > /dev/null

# Information Disclosure Threats
echo "🔵 Generating Information Disclosure Threats..."
curl -s "http://localhost:5000/api/users" > /dev/null
curl -s "http://localhost:5000/admin" > /dev/null

# Path Traversal Threats
echo "🟣 Generating Path Traversal Threats..."
curl -s "http://localhost:5000/file?path=/etc/passwd" > /dev/null
curl -s "http://localhost:5000/file?path=../../../etc/shadow" > /dev/null
curl -s "http://localhost:5000/file?path=../../../../etc/hosts" > /dev/null

# Custom API Threats
echo "🟢 Generating Custom API Threats..."
curl -s -X POST "http://localhost:5000/api/exploit_test" -H "Content-Type: application/json" -d '{"exploit_type": "Custom XSS", "payload": "<script>alert(\"Bulk Attack 1\")</script>"}' > /dev/null
curl -s -X POST "http://localhost:5000/api/exploit_test" -H "Content-Type: application/json" -d '{"exploit_type": "Custom SQLi", "payload": "OR 1=1 --"}' > /dev/null
curl -s -X POST "http://localhost:5000/api/exploit_test" -H "Content-Type: application/json" -d '{"exploit_type": "Custom CMD", "payload": "whoami"}' > /dev/null

# Check results
echo "✅ Threat generation complete!"
echo "📊 Current active threats:"
curl -s http://localhost:5000/api/threats | jq '.active_threats | length'
echo "📊 Total vulnerabilities:"
curl -s http://localhost:5000/api/vulnerabilities | jq '.vulnerabilities | length' 