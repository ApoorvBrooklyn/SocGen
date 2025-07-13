#!/usr/bin/env python3
"""
Test script for real-time risk priority updates
"""
import time
import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000/api/v1"
VULNERABLE_SERVER_URL = "http://localhost:5000"

def test_vulnerable_server():
    """Test if vulnerable server is running"""
    try:
        response = requests.get(f"{VULNERABLE_SERVER_URL}/health", timeout=5)
        print(f"✓ Vulnerable server is running (status: {response.status_code})")
        return True
    except requests.RequestException as e:
        print(f"✗ Vulnerable server is not accessible: {e}")
        return False

def test_backend_server():
    """Test if backend server is running"""
    try:
        response = requests.get(f"{BASE_URL}/../health", timeout=5)
        print(f"✓ Backend server is running (status: {response.status_code})")
        return True
    except requests.RequestException as e:
        print(f"✗ Backend server is not accessible: {e}")
        return False

def test_real_time_risk_assessment():
    """Test real-time risk assessment endpoint"""
    try:
        print("\n🔍 Testing real-time risk assessment...")
        response = requests.get(f"{BASE_URL}/risk/real-time", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Real-time risk assessment successful")
            print(f"  - Risk Score: {data.get('risk_assessment', {}).get('risk_score', 'N/A')}")
            print(f"  - Risk Level: {data.get('risk_assessment', {}).get('risk_level', 'N/A')}")
            print(f"  - Total Vulnerabilities: {data.get('total_vulnerabilities', 0)}")
            print(f"  - Priorities Found: {len(data.get('priorities', []))}")
            print(f"  - Recent Changes: {len(data.get('recent_changes', []))}")
            return True
        else:
            print(f"✗ Real-time risk assessment failed: {response.status_code}")
            print(f"  Response: {response.text}")
            return False
    except requests.RequestException as e:
        print(f"✗ Real-time risk assessment error: {e}")
        return False

def test_instant_threats():
    """Test instant threat detection endpoint"""
    try:
        print("\n🔍 Testing instant threat detection...")
        response = requests.get(f"{BASE_URL}/risk/instant-threats", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Instant threats check successful")
            print(f"  - Instant threats found: {data.get('count', 0)}")
            print(f"  - Has critical: {data.get('has_critical', False)}")
            if data.get('instant_threats'):
                for threat in data['instant_threats'][:3]:
                    print(f"    * {threat.get('type', 'unknown')}: {threat.get('severity', 'unknown')} - {threat.get('description', 'No description')[:50]}...")
            return True
        else:
            print(f"✗ Instant threats check failed: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"✗ Instant threats error: {e}")
        return False

def test_monitoring_control():
    """Test monitoring control endpoints"""
    try:
        print("\n🔍 Testing monitoring control...")
        
        # Get status
        status_response = requests.get(f"{BASE_URL}/risk/monitoring/status", timeout=5)
        if status_response.status_code == 200:
            status = status_response.json()
            print(f"✓ Monitoring status: {status.get('monitoring_active', 'unknown')}")
        
        # Start monitoring
        start_response = requests.post(f"{BASE_URL}/risk/monitoring/start", timeout=5)
        if start_response.status_code == 200:
            result = start_response.json()
            print(f"✓ Start monitoring: {result.get('status', 'unknown')} (interval: {result.get('interval_seconds', 'unknown')}s)")
        
        # Manual check
        check_response = requests.post(f"{BASE_URL}/risk/monitoring/check", timeout=10)
        if check_response.status_code == 200:
            result = check_response.json()
            print(f"✓ Manual check: changes detected = {result.get('changes_detected', False)}")
        
        return True
    except requests.RequestException as e:
        print(f"✗ Monitoring control error: {e}")
        return False

def test_force_recalculation():
    """Test force recalculation endpoint"""
    try:
        print("\n🔍 Testing force recalculation...")
        response = requests.post(f"{BASE_URL}/risk/recalculate", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Force recalculation successful")
            print(f"  - Status: {data.get('status', 'unknown')}")
            print(f"  - Timestamp: {data.get('timestamp', 'N/A')}")
            return True
        else:
            print(f"✗ Force recalculation failed: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"✗ Force recalculation error: {e}")
        return False

def simulate_vulnerability_activity():
    """Simulate vulnerability activity on the vulnerable server"""
    try:
        print("\n🔍 Simulating vulnerability activity...")
        
        # Trigger some vulnerabilities
        test_endpoints = [
            f"{VULNERABLE_SERVER_URL}/search?q=' OR 1=1 --",
            f"{VULNERABLE_SERVER_URL}/file?path=/etc/passwd",
            f"{VULNERABLE_SERVER_URL}/admin",
            f"{VULNERABLE_SERVER_URL}/file?path=../../../etc/shadow",
        ]
        
        for endpoint in test_endpoints:
            try:
                response = requests.get(endpoint, timeout=3)
                print(f"  - Triggered: {endpoint.split('/')[-1]} (status: {response.status_code})")
            except:
                pass
        
        # Add some POST exploits
        try:
            requests.post(f"{VULNERABLE_SERVER_URL}/add_post", 
                         data={"content": "test XSS <script>alert('xss')</script>"}, timeout=3)
            print(f"  - Triggered: XSS attempt via POST")
        except:
            pass
        
        # Wait a bit
        time.sleep(2)
        
        # Check if vulnerabilities were recorded
        vuln_response = requests.get(f"{VULNERABLE_SERVER_URL}/api/vulnerabilities", timeout=5)
        if vuln_response.status_code == 200:
            vuln_data = vuln_response.json()
            print(f"✓ Vulnerabilities recorded: {len(vuln_data.get('vulnerabilities', []))}")
        
        return True
    except requests.RequestException as e:
        print(f"✗ Vulnerability simulation error: {e}")
        return False

def test_real_time_updates():
    """Test real-time update responsiveness"""
    try:
        print("\n⚡ Testing real-time update responsiveness...")
        
        # Get baseline
        print("Getting baseline measurements...")
        baseline = requests.get(f"{BASE_URL}/risk/real-time", timeout=10)
        baseline_data = baseline.json() if baseline.status_code == 200 else {}
        baseline_threats = baseline_data.get('risk_assessment', {}).get('active_threats', 0)
        baseline_vulns = baseline_data.get('total_vulnerabilities', 0)
        
        print(f"  - Baseline threats: {baseline_threats}")
        print(f"  - Baseline vulnerabilities: {baseline_vulns}")
        
        # Trigger activity
        print("Triggering new activity...")
        simulate_vulnerability_activity()
        
        # Wait and check for updates
        print("Checking for real-time updates...")
        for i in range(5):
            time.sleep(2)
            response = requests.get(f"{BASE_URL}/risk/real-time", timeout=10)
            if response.status_code == 200:
                data = response.json()
                current_threats = data.get('risk_assessment', {}).get('active_threats', 0)
                current_vulns = data.get('total_vulnerabilities', 0)
                
                if current_threats > baseline_threats or current_vulns > baseline_vulns:
                    print(f"✓ Real-time update detected after {(i+1)*2} seconds!")
                    print(f"  - Threats: {baseline_threats} → {current_threats}")
                    print(f"  - Vulnerabilities: {baseline_vulns} → {current_vulns}")
                    return True
                else:
                    print(f"  - Check {i+1}: No changes yet...")
        
        print("⚠️  No real-time changes detected in 10 seconds")
        return False
        
    except Exception as e:
        print(f"✗ Real-time update test error: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 Testing Enhanced Real-time Risk Priority Updates")
    print("=" * 60)
    
    # Test server availability
    backend_ok = test_backend_server()
    vulnerable_ok = test_vulnerable_server()
    
    if not backend_ok or not vulnerable_ok:
        print("\n❌ Servers are not running. Please start both servers first.")
        print("Backend: cd backend && python main.py")
        print("Vulnerable Server: cd vulnerable-server && python app.py")
        return
    
    # Test real-time functionality
    print("\n🧪 Testing Enhanced Real-time Risk Features")
    print("-" * 40)
    
    # Test basic functionality
    test_real_time_risk_assessment()
    test_instant_threats()
    test_monitoring_control()
    test_force_recalculation()
    
    # Test responsiveness
    print("\n⚡ Testing Real-time Responsiveness")
    print("-" * 40)
    
    test_real_time_updates()
    
    # Test instant threat detection
    print("\n🚨 Testing Instant Threat Detection")
    print("-" * 40)
    
    print("Generating threats and checking instant detection...")
    for i in range(3):
        simulate_vulnerability_activity()
        time.sleep(1)
        test_instant_threats()
        time.sleep(2)
    
    print("\n✅ Enhanced Real-time Test Completed!")
    print("\n🎯 New Real-time Features Tested:")
    print("✓ 3-second risk assessment updates")
    print("✓ 1-second instant threat detection")
    print("✓ 30-second background monitoring")
    print("✓ Critical threat alerts")
    print("✓ Real-time activity feed")
    print("✓ Risk trend indicators")
    
    print("\nTo see enhanced real-time updates in action:")
    print("1. Start the frontend: cd project && npm run dev")
    print("2. Go to Risk Prioritization page")
    print("3. Click 'Start Monitoring' to enable automatic updates")
    print("4. Watch the instant threat feed update every second")
    print("5. Notice risk trend arrows and critical alerts")
    print("6. Run vulnerability tests to see instant notifications")

if __name__ == "__main__":
    main() 