# tests/test_auth.py
import pytest
import requests
import logging # Import logging

# Note: These tests rely on fixtures defined in conftest.py

def test_valid_login_superuser(api_url, superuser_credentials, request_timeout):
    """
    Ensure the superuser can log in and receives a valid token.
    """
    user, passwd = superuser_credentials
    logging.info(f"[TEST] Attempting valid login for superuser: {user}") # Use logging
    resp = requests.post(
        f"{api_url}/login",
        json={"username": user, "password": passwd},
        timeout=request_timeout
    )
    logging.info(f"  `-> Received status {resp.status_code}. Asserting it's 200.") # Use logging
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "token" in data, "Response JSON should contain a 'token' field"
    assert isinstance(data["token"], str) and len(data["token"]) > 10, "Token seems invalid or too short"
    logging.info(f"  `-> Superuser login successful, token received.") # Use logging

def test_valid_login_apiuser(api_url, apiuser_credentials, request_timeout):
    """
    Ensure a normal API user can log in and receives a valid token.
    """
    user, passwd = apiuser_credentials
    logging.info(f"[TEST] Attempting valid login for apiuser: {user}") # Use logging
    resp = requests.post(
        f"{api_url}/login",
        json={"username": user, "password": passwd},
        timeout=request_timeout
    )
    logging.info(f"  `-> Received status {resp.status_code}. Asserting it's 200.") # Use logging
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "token" in data, "Response JSON should contain a 'token' field"
    assert isinstance(data["token"], str) and len(data["token"]) > 10, "Token seems invalid or too short"
    logging.info(f"  `-> Apiuser login successful, token received.") # Use logging

def test_invalid_login(api_url, request_timeout):
    """
    Login should fail with incorrect credentials (expecting 401).
    """
    logging.info(f"[TEST] Attempting invalid login (wrong user/pass).") # Use logging
    resp = requests.post(
        f"{api_url}/login",
        json={"username": "nonexistent_user_!@#$", "password": "wrong_password_$%^"},
        timeout=request_timeout
    )
    logging.info(f"  `-> Received status {resp.status_code}. Asserting it's 401.") # Use logging
    assert resp.status_code == 401, f"Expected 401 Unauthorized, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "error" in data, "Error response should contain an 'error' field"
    logging.info(f"  `-> Invalid login correctly resulted in 401.") # Use logging

def test_unauthorized_user_login(api_url, unauth_user_credentials, request_timeout):
    """
    Attempt login with a user who exists but is not in any valid API group.
    Expect 401 Unauthorized based on current server logic.
    """
    user, passwd = unauth_user_credentials
    logging.info(f"[TEST] Attempting login for unauthorized user: {user} (expecting 401).") # Use logging
    resp = requests.post(
        f"{api_url}/login",
        json={"username": user, "password": passwd},
        timeout=request_timeout
    )
    logging.info(f"  `-> Received status {resp.status_code}. Asserting it's 401.") # Use logging
    assert resp.status_code == 401, f"Expected 401 Unauthorized for user not in allowed groups, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "error" in data, "Response JSON should contain an 'error' field"
    logging.info(f"  `-> Unauthorized user login correctly resulted in 401.") # Use logging