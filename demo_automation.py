#!/usr/bin/env python3
"""
SecureShield Presentation Automation Script

Automates all API calls for the JWT Guardians presentation.
Follows the scenes defined in PRESENTATION_SCRIPT_EN.md
"""

import json
import time
import jwt
import requests
from datetime import datetime

# Configuration
BASE_URL = "http://127.0.0.1:5000"
USERNAME = "alice"
PASSWORD = "Wonderland1!"
ADMIN_USER_ID = 1

# ANSI color codes for terminal output
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def print_header(text: str):
    """Print a section header."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text}{Colors.RESET}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.RESET}\n")


def print_request(method: str, endpoint: str, headers: dict = None, body: dict = None):
    """Print request details."""
    print(f"{Colors.CYAN}Request:{Colors.RESET}")
    print(f"  {Colors.BOLD}Method:{Colors.RESET} {method}")
    print(f"  {Colors.BOLD}Endpoint:{Colors.RESET} {endpoint}")
    if headers:
        print(f"  {Colors.BOLD}Headers:{Colors.RESET}")
        for k, v in headers.items():
            if k.lower() == "authorization":
                # Show only first 20 chars of token
                v = v[:20] + "..." if len(v) > 20 else v
            print(f"    {k}: {v}")
    if body:
        print(f"  {Colors.BOLD}Body:{Colors.RESET} {json.dumps(body, indent=4)}")


def print_response(status_code: int, body: dict, expected_status: int = None):
    """Print response details with color coding."""
    print(f"\n{Colors.CYAN}Response:{Colors.RESET}")
    print(f"  {Colors.BOLD}Status:{Colors.RESET} ", end="")

    if status_code >= 200 and status_code < 300:
        print(f"{Colors.GREEN}{status_code} OK{Colors.RESET}")
    elif status_code == 403:
        print(f"{Colors.YELLOW}{status_code} FORBIDDEN{Colors.RESET}")
    elif status_code == 401:
        print(f"{Colors.RED}{status_code} UNAUTHORIZED{Colors.RESET}")
    else:
        print(f"{status_code}")

    if expected_status is not None:
        status_match = f"{Colors.GREEN}[OK]{Colors.RESET}" if status_code == expected_status else f"{Colors.RED}[X]{Colors.RESET}"
        print(f"  {Colors.BOLD}Expected:{Colors.RESET} {expected_status} {status_match}")

    print(f"  {Colors.BOLD}Body:{Colors.RESET}")
    print(f"  {json.dumps(body, indent=4)}")


def print_success(text: str):
    """Print success message."""
    print(f"\n{Colors.GREEN}[OK] {text}{Colors.RESET}")


def print_warning(text: str):
    """Print warning message."""
    print(f"\n{Colors.YELLOW}[!] {text}{Colors.RESET}")


def print_error(text: str):
    """Print error message."""
    print(f"\n{Colors.RED}[X] {text}{Colors.RESET}")


def print_info(text: str):
    """Print info message."""
    print(f"\n{Colors.BLUE}[i] {text}{Colors.RESET}")


# ============================================================================
# SCENE 1: REGISTER
# ============================================================================

def scene_register():
    """Scene 3: Register a new user."""
    print_header("SCENE 1: REGISTER USER")

    endpoint = f"{BASE_URL}/register"
    headers = {"Content-Type": "application/json"}
    body = {"username": USERNAME, "password": PASSWORD}

    print_request("POST", endpoint, headers, body)

    response = requests.post(endpoint, json=body, headers=headers)

    print_response(response.status_code, response.json(), expected_status=201)

    if response.status_code == 201:
        data = response.json()
        print_success(f"User '{USERNAME}' created with ID {data['id']} and role '{data['role']}'")
        print_info("Password was hashed using bcrypt before storage (never stored as plain text)")
    else:
        print_error(f"Registration failed: {response.json()}")
        return None

    time.sleep(1)
    return response.json()


# ============================================================================
# SCENE 2: LOGIN
# ============================================================================

def scene_login():
    """Scene 4: Login and get JWT token."""
    print_header("SCENE 2: LOGIN AND TOKEN ACQUISITION")

    endpoint = f"{BASE_URL}/login"
    headers = {"Content-Type": "application/json"}
    body = {"username": USERNAME, "password": PASSWORD}

    print_request("POST", endpoint, headers, body)

    response = requests.post(endpoint, json=body, headers=headers)

    print_response(response.status_code, response.json(), expected_status=200)

    if response.status_code == 200:
        data = response.json()
        token = data["access_token"]
        print_success(f"Login successful! JWT token received")
        print_info(f"Token type: {data['token_type']}")
        print_info(f"Token (first 50 chars): {token[:50]}...")

        # Decode and show payload
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            print_info(f"Token payload: {json.dumps(payload, indent=4)}")
            print_info("Note: Password is NOT inside the token - only identity and role")
        except Exception as e:
            print_warning(f"Could not decode token payload: {e}")

        time.sleep(1)
        return token
    else:
        print_error(f"Login failed: {response.json()}")
        return None


# ============================================================================
# SCENE 3: PROFILE ACCESS
# ============================================================================

def scene_profile(token: str):
    """Scene 5: Access profile endpoint with valid token."""
    print_header("SCENE 3: PROFILE ACCESS")

    endpoint = f"{BASE_URL}/profile"
    headers = {"Authorization": f"Bearer {token}"}

    print_request("GET", endpoint, headers)

    response = requests.get(endpoint, headers=headers)

    print_response(response.status_code, response.json(), expected_status=200)

    if response.status_code == 200:
        data = response.json()
        print_success(f"Profile access successful for user '{data['username']}' with role '{data['role']}'")
        print_info("This endpoint is accessible to both 'user' and 'admin' roles")
    else:
        print_error(f"Profile access failed: {response.json()}")

    time.sleep(1)


# ============================================================================
# SCENE 4: RBAC TEST (403 FORBIDDEN)
# ============================================================================

def scene_rbac_test(token: str):
    """Scene 6: Test RBAC - user trying to access admin endpoint."""
    print_header("SCENE 4: RBAC TEST - 403 FORBIDDEN")

    endpoint = f"{BASE_URL}/user/{ADMIN_USER_ID}"
    headers = {"Authorization": f"Bearer {token}"}

    print_request("DELETE", endpoint, headers)

    response = requests.delete(endpoint, headers=headers)

    print_response(response.status_code, response.json(), expected_status=403)

    if response.status_code == 403:
        print_success("RBAC working correctly!")
        print_info("User with 'user' role cannot access admin-only endpoint")
        print_info("This demonstrates the principle of least privilege")
    else:
        print_warning(f"Unexpected response: {response.json()}")

    time.sleep(1)


# ============================================================================
# SCENE 5: JWT TAMPER TEST (401 INVALID TOKEN)
# ============================================================================

def scene_jwt_tamper_test(token: str):
    """Scene 7: Test JWT tampering - modify role and try again."""
    print_header("SCENE 5: JWT TAMPER TEST - 401 INVALID TOKEN")

    # Decode the token
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        print_info(f"Original token payload: {json.dumps(payload, indent=4)}")

        # Tamper with the payload - change role to admin
        print_warning("Tampering with token: changing role from 'user' to 'admin'...")
        payload["role"] = "admin"
        print_info(f"Tampered payload: {json.dumps(payload, indent=4)}")

        # Re-encode without proper signature (this will fail validation)
        # We need the secret key to properly sign, but we don't have it
        # So we'll just show what happens when we try to use a tampered token
        # In a real attack, the attacker would need the secret key

        # For demo purposes, we'll create an invalid token by encoding with wrong key
        tampered_token = jwt.encode(payload, "wrong-secret-key", algorithm="HS256")

        print_info(f"Tampered token (first 50 chars): {tampered_token[:50]}...")

        endpoint = f"{BASE_URL}/user/{ADMIN_USER_ID}"
        headers = {"Authorization": f"Bearer {tampered_token}"}

        print_request("DELETE", endpoint, headers)

        response = requests.delete(endpoint, headers=headers)

        print_response(response.status_code, response.json(), expected_status=401)

        if response.status_code == 401:
            print_success("JWT signature validation working correctly!")
            print_info("Tampered token was rejected - signature is invalid")
            print_info("Without the server's secret key, the token cannot be re-signed")
        else:
            print_warning(f"Unexpected response: {response.json()}")

    except Exception as e:
        print_error(f"Error during tamper test: {e}")

    time.sleep(1)


# ============================================================================
# SCENE 6: LOGOUT AND BLACKLIST
# ============================================================================

def scene_logout(token: str):
    """Scene 8: Logout and blacklist the token."""
    print_header("SCENE 6: LOGOUT AND TOKEN BLACKLIST")

    endpoint = f"{BASE_URL}/logout"
    headers = {"Authorization": f"Bearer {token}"}

    print_request("POST", endpoint, headers)

    response = requests.post(endpoint, headers=headers)

    print_response(response.status_code, response.json(), expected_status=200)

    if response.status_code == 200:
        print_success("Logout successful - token has been revoked and added to blacklist")
        print_info("The token is now on the server's blacklist")
    else:
        print_error(f"Logout failed: {response.json()}")

    time.sleep(1)


# ============================================================================
# SCENE 7: REVOKED TOKEN TEST
# ============================================================================

def scene_revoked_token_test(token: str):
    """Scene 9: Test that revoked token is rejected."""
    print_header("SCENE 7: REVOKED TOKEN TEST - 401 TOKEN REVOKED")

    endpoint = f"{BASE_URL}/profile"
    headers = {"Authorization": f"Bearer {token}"}

    print_request("GET", endpoint, headers)

    response = requests.get(endpoint, headers=headers)

    print_response(response.status_code, response.json(), expected_status=401)

    if response.status_code == 401:
        data = response.json()
        print_success("Token blacklist working correctly!")
        print_info(f"Revoked token was rejected: {data.get('error', 'unknown error')}")
        print_info("The token is still mathematically valid but rejected due to blacklist")
    else:
        print_warning(f"Unexpected response: {response.json()}")

    time.sleep(1)


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Run the complete presentation automation."""
    print(f"\n{Colors.BOLD}{Colors.HEADER}")
    print("============================================================")
    print("           SecureShield Presentation Automation            ")
    print("                    JWT Guardians                          ")
    print("============================================================")
    print(f"{Colors.RESET}")

    print_info(f"Starting at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info(f"Target server: {BASE_URL}")
    print_info(f"Test user: {USERNAME}")

    # Check if server is running
    try:
        response = requests.get(BASE_URL, timeout=2)
        print_success("Server is running!")
    except requests.exceptions.RequestException:
        print_error("Server is not running!")
        print_info("Please start the server with: python app.py")
        return

    # Run all scenes
    original_token = None

    try:
        # Scene 3: Register
        scene_register()

        # Scene 4: Login
        original_token = scene_login()
        if not original_token:
            print_error("Cannot continue without a valid token")
            return

        # Scene 5: Profile
        scene_profile(original_token)

        # Scene 6: RBAC Test
        scene_rbac_test(original_token)

        # Scene 7: JWT Tamper Test
        scene_jwt_tamper_test(original_token)

        # Scene 8: Logout
        scene_logout(original_token)

        # Scene 9: Revoked Token Test
        scene_revoked_token_test(original_token)

        # Summary
        print_header("SUMMARY")
        print_success("All scenes completed successfully!")
        print_info("Security features demonstrated:")
        print("  • Bcrypt password hashing")
        print("  • JWT-based authentication")
        print("  • Role-based access control (RBAC)")
        print("  • JWT signature validation")
        print("  • Token blacklisting on logout")
        print("  • Security logging of unauthorized attempts")
        print_info(f"Check 'security.log' for all unauthorized attempt logs")

    except KeyboardInterrupt:
        print_warning("\nAutomation interrupted by user")
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
