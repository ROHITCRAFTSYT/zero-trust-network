#!/usr/bin/python

"""
Zero Trust Network Utilities
These utilities can be used to simulate and test the zero-trust network
"""

import http.server
import socketserver
import json
import time
import hashlib
import random
import threading
import requests

# =====================================================
# Authentication Server Implementation
# =====================================================
class AuthServiceHandler(http.server.SimpleHTTPRequestHandler):
    """
    Simulates an authentication service for zero-trust networking
    This would be a more sophisticated service in production
    """
    # Dictionary to store active sessions
    sessions = {}
    
    def do_POST(self):
        """Handle authentication requests"""
        if self.path == '/authenticate':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            auth_request = json.loads(post_data.decode('utf-8'))
            
            # In a real implementation, validate credentials securely
            # For this prototype, we'll simply authenticate known users
            
            user_id = auth_request.get('user_id')
            password = auth_request.get('password')
            client_ip = auth_request.get('client_ip')
            
            # Simple validation - in production this would be much more robust
            if user_id and password:
                # Generate authentication token (would be more secure in production)
                token = hashlib.sha256(f"{user_id}{time.time()}{random.random()}".encode()).hexdigest()
                
                # Store session info
                self.sessions[token] = {
                    'user_id': user_id,
                    'client_ip': client_ip,
                    'timestamp': time.time(),
                    'expiry': time.time() + 3600  # 1 hour expiry
                }
                
                # Return authentication token
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {
                    'status': 'success',
                    'token': token,
                    'expiry': self.sessions[token]['expiry']
                }
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {'status': 'error', 'message': 'Invalid credentials'}
                self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_GET(self):
        """Handle token validation requests"""
        if self.path.startswith('/validate'):
            # Extract token from URL query parameter
            token = self.path.split('=')[1] if '=' in self.path else None
            
            if token and token in self.sessions:
                session = self.sessions[token]
                
                # Check if token is expired
                if time.time() > session['expiry']:
                    # Remove expired session
                    del self.sessions[token]
                    
                    self.send_response(401)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = {'status': 'error', 'message': 'Token expired'}
                    self.wfile.write(json.dumps(response).encode())
                else:
                    # Valid token
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = {
                        'status': 'success',
                        'user_id': session['user_id'],
                        'client_ip': session['client_ip']
                    }
                    self.wfile.write(json.dumps(response).encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {'status': 'error', 'message': 'Invalid token'}
                self.wfile.write(json.dumps(response).encode())
        else:
            # Serve files for other paths
            super().do_GET()

# =====================================================
# Policy Server Implementation
# =====================================================
class PolicyServiceHandler(http.server.SimpleHTTPRequestHandler):
    """
    Simulates a policy service for zero-trust networking
    Determines what resources a user can access
    """
    # Simple policy database (would be more sophisticated in production)
    policy_db = {
        # Trusted zone policies
        'trusted-user1': {
            'allowed_resources': ['dmz-server1', 'dmz-server2'],
            'allowed_ports': [80, 443, 22]
        },
        'trusted-user2': {
            'allowed_resources': ['dmz-server1'],
            'allowed_ports': [80, 443]
        },
        
        # DMZ zone policies
        'dmz-service1': {
            'allowed_resources': ['dmz-server2'],
            'allowed_ports': [3306]  # MySQL
        },
        
        # Untrusted zone policies
        'untrusted-user': {
            'allowed_resources': ['dmz-server1'],
            'allowed_ports': [80, 443]
        }
    }
    
    def do_GET(self):
        """Handle policy lookup requests"""
        if self.path.startswith('/policy'):
            # Extract user ID from URL query parameter
            user_id = self.path.split('=')[1] if '=' in self.path else None
            
            if user_id and user_id in self.policy_db:
                # Return policy for user
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {
                    'status': 'success',
                    'policy': self.policy_db[user_id]
                }
                self.wfile.write(json.dumps(response).encode())
            else:
                # User not found, return default deny policy
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {
                    'status': 'success',
                    'policy': {
                        'allowed_resources': [],
                        'allowed_ports': []
                    }
                }
                self.wfile.write(json.dumps(response).encode())
        elif self.path.startswith('/check'):
            # Extract parameters from query string
            params = self.path.split('?')[1] if '?' in self.path else ''
            param_dict = {}
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=')
                    param_dict[key] = value
            
            user_id = param_dict.get('user')
            resource = param_dict.get('resource')
            port = int(param_dict.get('port', 0))
            
            # Check if access is allowed
            allowed = False
            if user_id in self.policy_db:
                policy = self.policy_db[user_id]
                if (resource in policy['allowed_resources'] and
                    port in policy['allowed_ports']):
                    allowed = True
            
            # Return decision
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                'status': 'success',
                'allowed': allowed
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            # Serve files for other paths
            super().do_GET()

# =====================================================
# Client Authentication Helper
# =====================================================
def authenticate_client(auth_server, user_id, password, client_ip):
    """
    Helper function to authenticate a client with the auth server
    Returns an authentication token if successful
    """
    auth_data = {
        'user_id': user_id,
        'password': password,
        'client_ip': client_ip
    }
    
    try:
        response = requests.post(f"http://{auth_server}/authenticate", 
                                json=auth_data, 
                                timeout=5)
        
        if response.status_code == 200:
            return response.json().get('token')
        else:
            print(f"Authentication failed: {response.json().get('message')}")
            return None
    except Exception as e:
        print(f"Authentication error: {e}")
        return None

# =====================================================
# Connection Wrapper with Zero Trust
# =====================================================
def zero_trust_connect(auth_server, policy_server, user_id, password, 
                      source_ip, dest_ip, dest_port):
    """
    Establishes a connection using zero-trust principles:
    1. Authenticate user
    2. Check policy
    3. Create connection only if allowed
    """
    # Step 1: Authenticate
    token = authenticate_client(auth_server, user_id, password, source_ip)
    if not token:
        print("Zero Trust: Authentication failed")
        return False
    
    # Step 2: Check policy
    try:
        policy_url = f"http://{policy_server}/check?user={user_id}&resource={dest_ip}&port={dest_port}"
        response = requests.get(policy_url, timeout=5)
        
        if response.status_code == 200:
            allowed = response.json().get('allowed', False)
            if allowed:
                print(f"Zero Trust: Access allowed to {dest_ip}:{dest_port}")
                
                # In a real implementation, you would establish the connection here
                # For this prototype, we just simulate success
                return True
            else:
                print(f"Zero Trust: Access denied to {dest_ip}:{dest_port}")
                return False
        else:
            print(f"Zero Trust: Policy check failed")
            return False
    except Exception as e:
        print(f"Zero Trust: Policy check error: {e}")
        return False

# =====================================================
# Start Services
# =====================================================
def start_auth_server(port=8080):
    """Start the authentication server on the specified port"""
    handler = AuthServiceHandler
    server = socketserver.TCPServer(("", port), handler)
    print(f"Authentication server started on port {port}")
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server

def start_policy_server(port=8081):
    """Start the policy server on the specified port"""
    handler = PolicyServiceHandler
    server = socketserver.TCPServer(("", port), handler)
    print(f"Policy server started on port {port}")
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server

if __name__ == '__main__':
    # Start servers
    auth_server = start_auth_server(8080)
    policy_server = start_policy_server(8081)
    
    # Keep main thread running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down servers")
        auth_server.shutdown()
        policy_server.shutdown()
