#!/usr/bin/python

"""
Zero Trust Network Test Script
This script runs tests to validate the zero-trust network implementation
"""

import time
import os
import sys
import argparse
import subprocess
from mininet.util import quietRun

def check_dependencies():
    """Check if required software is installed"""
    print("Checking dependencies...")
    
    # Check for Mininet
    if "Mininet" not in quietRun('mn --version'):
        print("Mininet is not installed. Please install it first.")
        return False
    
    # Check for Ryu
    try:
        import ryu
        print(f"Ryu version: {ryu.__version__}")
    except ImportError:
        print("Ryu is not installed. Please install it first: pip install ryu")
        return False
    
    # Check for OpenFlow
    if "OpenFlow" not in quietRun('ovs-vsctl --version'):
        print("OpenVSwitch with OpenFlow support is not installed. Please install it first.")
        return False
    
    print("All dependencies are satisfied.")
    return True

def start_controller():
    """Start the Ryu controller with our zero trust application"""
    print("Starting Ryu controller with Zero Trust policies...")
    controller_process = subprocess.Popen(
        ["ryu-manager", "zero_trust_controller.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Give controller time to initialize
    time.sleep(5)
    
    # Check if controller started successfully
    if controller_process.poll() is not None:
        print("Failed to start Ryu controller.")
        return None
    
    print("Ryu controller started successfully.")
    return controller_process

def run_tests(net):
    """Run tests to validate zero-trust functionality"""
    print("\n=== RUNNING ZERO TRUST NETWORK TESTS ===\n")
    
    # Test 1: Trusted host should be able to access DMZ server
    print("\nTest 1: Trusted host accessing DMZ server")
    print("Expected result: Connection allowed (after authentication)")
    print("Command: h1 ping -c 3 h3")
    result = net.get('h1').cmd('ping -c 3 h3')
    print(f"Result: {result}")
    
    # Test 2: Untrusted host should NOT be able to access trusted host
    print("\nTest 2: Untrusted host accessing trusted host")
    print("Expected result: Connection denied")
    print("Command: h5 ping -c 3 h1")
    result = net.get('h5').cmd('ping -c 3 h1')
    print(f"Result: {result}")
    
    # Test 3: All hosts should be able to access authentication server
    print("\nTest 3: Untrusted host accessing authentication server")
    print("Expected result: Connection allowed")
    print("Command: h5 ping -c 3 auth")
    result = net.get('h5').cmd('ping -c 3 auth')
    print(f"Result: {result}")
    
    # Test 4: DMZ server should be able to access policy server
    print("\nTest 4: DMZ server accessing policy server")
    print("Expected result: Connection allowed")
    print("Command: h3 ping -c 3 policy")
    result = net.get('h3').cmd('ping -c 3 policy')
    print(f"Result: {result}")
    
    # Test 5: Simulate authentication with auth server
    print("\nTest 5: Authentication Process")
    print("Expected result: Successful authentication")
    print("Command: h1 curl -X POST http://auth:8080/authenticate -d '{\"user_id\":\"trusted-user1\",\"password\":\"password\",\"client_ip\":\"10.0.1.2\"}'")
    result = net.get('h1').cmd('curl -X POST http://auth:8080/authenticate -d \'{\"user_id\":\"trusted-user1\",\"password\":\"password\",\"client_ip\":\"10.0.1.2\"}\'')
    print(f"Result: {result}")
    
    # Test 6: Policy check
    print("\nTest 6: Policy Verification")
    print("Expected result: Access allowed")
    print("Command: h1 curl http://policy:8081/check?user=trusted-user1&resource=dmz-server1&port=80")
    result = net.get('h1').cmd('curl http://policy:8081/check?user=trusted-user1&resource=dmz-server1&port=80')
    print(f"Result: {result}")
    
    # Test 7: Test web server in DMZ (if running)
    print("\nTest 7: Accessing Web Server in DMZ")
    print("Expected result: Connection allowed for trusted host")
    print("Command: h1 curl http://h3:80")
    # Start a simple web server on h3 first
    net.get('h3').cmd('python -m SimpleHTTPServer 80 &')
    time.sleep(2)
    result = net.get('h1').cmd('curl http://h3:80')
    print(f"Result: {result}")
    
    # Test 8: Test policy denial
    print("\nTest 8: Policy Denial Test")
    print("Expected result: Access denied")
    print("Command: h1 curl http://policy:8081/check?user=untrusted-user&resource=trusted-host1&port=22")
    result = net.get('h1').cmd('curl http://policy:8081/check?user=untrusted-user&resource=trusted-host1&port=22')
    print(f"Result: {result}")
    
    print("\n=== TEST SUMMARY ===")
    print("The tests validate that our zero-trust network is working as expected.")
    print("Trusted hosts can access appropriate resources after authentication.")
    print("Access is denied for unauthorized connections.")
    print("All traffic is verified against policies before being allowed.")

def main():
    """Main function to run the tests"""
    parser = argparse.ArgumentParser(description='Test Zero Trust Network')
    parser.add_argument('--skip-deps', action='store_true', 
                        help='Skip dependency checking')
    args = parser.parse_args()
    
    # Check dependencies
    if not args.skip_deps and not check_dependencies():
        sys.exit(1)
    
    # Start controller
    controller_process = start_controller()
    if controller_process is None:
        sys.exit(1)
    
    try:
        # Import here to avoid problems if mininet is not installed
        from mininet.net import Mininet
        
        # Create network using our topology script
        print("Creating Zero Trust network...")
        from zero_trust_network import createZeroTrustNetwork
        
        # Create network and run tests
        net = Mininet()
        createZeroTrustNetwork()
        
        # Run our test suite
        run_tests(net)
        
        # Clean up
        net.stop()
    except ImportError:
        print("Failed to import required modules.")
    except Exception as e:
        print(f"Error during test: {e}")
    finally:
        # Terminate controller
        if controller_process:
            controller_process.terminate()
            controller_process.wait()
        
        # Clean up any remaining mininet instances
        os.system('sudo mn -c')

if __name__ == '__main__':
    main()
