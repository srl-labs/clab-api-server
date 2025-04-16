# tests/conftest.py
import os
import pytest
import requests
import time
import random
import string
import logging # Import logging
from dotenv import load_dotenv

# Load environment variables from .env file in the same directory as conftest.py
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# --- Basic API and Timeout Fixtures ---
@pytest.fixture(scope="session")
def api_url():
    return os.getenv("API_URL", "http://127.0.0.1:8080")

@pytest.fixture(scope="session")
def request_timeout():
    return int(os.getenv("PYTEST_TIMEOUT_REQUEST", "15"))

@pytest.fixture(scope="session")
def deploy_timeout():
    return int(os.getenv("PYTEST_TIMEOUT_DEPLOY", "240"))

@pytest.fixture(scope="session")
def cleanup_timeout():
    return int(os.getenv("PYTEST_TIMEOUT_CLEANUP", "180"))

@pytest.fixture(scope="session")
def lab_stabilize_pause():
    return int(os.getenv("PYTEST_STABILIZE_PAUSE", "10"))

# --- Credential Fixtures ---
@pytest.fixture(scope="session")
def superuser_credentials():
    return (
        os.getenv("SUPERUSER_USER", "root"),
        os.getenv("SUPERUSER_PASS", "rootpassword"),
    )

@pytest.fixture(scope="session")
def apiuser_credentials():
    return (
        os.getenv("APIUSER_USER", "test"),
        os.getenv("APIUSER_PASS", "test"),
    )

@pytest.fixture(scope="session")
def unauth_user_credentials():
    return (
        os.getenv("UNAUTH_USER", "test2"),
        os.getenv("UNAUTH_PASS", "test2"),
    )

# --- Token and Header Fixtures ---
@pytest.fixture
def superuser_token(api_url, superuser_credentials, request_timeout):
    user, passwd = superuser_credentials
    resp = requests.post(
        f"{api_url}/login",
        json={"username": user, "password": passwd},
        timeout=request_timeout
    )
    resp.raise_for_status()
    data = resp.json()
    return data["token"]

@pytest.fixture
def apiuser_token(api_url, apiuser_credentials, request_timeout):
    user, passwd = apiuser_credentials
    resp = requests.post(
        f"{api_url}/login",
        json={"username": user, "password": passwd},
        timeout=request_timeout
    )
    resp.raise_for_status()
    data = resp.json()
    return data["token"]

@pytest.fixture
def unauth_user_token(api_url, unauth_user_credentials, request_timeout):
    user, passwd = unauth_user_credentials
    return (user, passwd)

@pytest.fixture
def auth_headers(apiuser_token):
    return {"Authorization": f"Bearer {apiuser_token}"}

@pytest.fixture
def apiuser_headers(auth_headers):
    return auth_headers

@pytest.fixture
def superuser_headers(superuser_token):
    return {"Authorization": f"Bearer {superuser_token}"}


# --- Topology and Lab Name Fixtures ---
@pytest.fixture(scope="session")
def simple_topology_content():
    content = os.getenv("PYTEST_SIMPLE_TOPOLOGY_CONTENT")
    if not content or "{lab_name}" not in content:
        pytest.fail("PYTEST_SIMPLE_TOPOLOGY_CONTENT env var is missing or doesn't contain '{lab_name}' placeholder.")
    return content

@pytest.fixture(scope="session")
def lab_name_prefix():
    return os.getenv("PYTEST_LAB_NAME_PREFIX", "pytest")

# --- Helper Function ---
def random_suffix(length=5):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# --- Ephemeral Lab Fixtures (Setup/Teardown) ---

@pytest.fixture
def ephemeral_lab(request, api_url, auth_headers, superuser_headers, simple_topology_content, lab_name_prefix, deploy_timeout, lab_stabilize_pause, cleanup_timeout):
    """
    Fixture to create a temporary lab using apiuser credentials and ensure its destruction using superuser credentials.
    Yields the name of the created lab.
    """
    suffix = random_suffix()
    lab_name = f"{lab_name_prefix}-eph-{suffix}"
    logging.info(f"---> [SETUP] Creating ephemeral lab: {lab_name} (as apiuser)")

    topology_yaml = simple_topology_content.format(lab_name=lab_name)
    deploy_url = f"{api_url}/api/v1/labs"
    req_body = {"topologyContent": topology_yaml}

    try:
        resp = requests.post(deploy_url, json=req_body, headers=auth_headers, timeout=deploy_timeout) # Create as apiuser
        resp.raise_for_status()
        logging.info(f"  `-> [SETUP] Lab '{lab_name}' created successfully.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to create ephemeral lab '{lab_name}': {e}\nResponse: {e.response.text if e.response else 'No Response'}")
        pytest.fail(f"Failed to create ephemeral lab '{lab_name}': {e}")

    time.sleep(lab_stabilize_pause)
    yield lab_name

    logging.info(f"<--- [TEARDOWN] Cleaning up ephemeral lab: {lab_name} (as superuser)")
    destroy_url = f"{api_url}/api/v1/labs/{lab_name}"
    params = {"cleanup": "true"}
    try:
        # Use SUPERUSER headers for teardown to guarantee cleanup
        resp_del = requests.delete(destroy_url, headers=superuser_headers, params=params, timeout=cleanup_timeout)
        if resp_del.status_code == 404:
            logging.warning(f"  `-> [TEARDOWN] Warning: Lab '{lab_name}' not found during cleanup.")
        elif resp_del.status_code != 200:
            logging.warning(f"  `-> [TEARDOWN] Warning: Failed cleanup for lab '{lab_name}'. Status: {resp_del.status_code}, Response: {resp_del.text}")
        else:
            logging.info(f"  `-> [TEARDOWN] Lab '{lab_name}' cleaned up successfully.")
        cleanup_pause_duration = request.config.getoption("--cleanup-pause", default=3)
        time.sleep(cleanup_pause_duration)
    except requests.exceptions.RequestException as e:
        logging.warning(f"  `-> [TEARDOWN] Warning: Exception during lab cleanup for '{lab_name}': {e}")


@pytest.fixture
def superuser_lab(request, api_url, superuser_headers, simple_topology_content, lab_name_prefix, deploy_timeout, lab_stabilize_pause, cleanup_timeout):
    """
    Fixture to create a temporary lab as superuser and ensure its destruction (also as superuser).
    Yields the name of the created lab.
    """
    suffix = random_suffix()
    lab_name = f"{lab_name_prefix}-su-eph-{suffix}"
    logging.info(f"---> [SETUP-SU] Creating superuser ephemeral lab: {lab_name}")

    topology_yaml = simple_topology_content.format(lab_name=lab_name)
    deploy_url = f"{api_url}/api/v1/labs"
    req_body = {"topologyContent": topology_yaml}

    try:
        resp = requests.post(deploy_url, json=req_body, headers=superuser_headers, timeout=deploy_timeout)
        resp.raise_for_status()
        logging.info(f"  `-> [SETUP-SU] Lab '{lab_name}' created successfully.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to create superuser ephemeral lab '{lab_name}': {e}\nResponse: {e.response.text if e.response else 'No Response'}")
        pytest.fail(f"Failed to create superuser ephemeral lab '{lab_name}': {e}")

    time.sleep(lab_stabilize_pause)
    yield lab_name

    logging.info(f"<--- [TEARDOWN-SU] Cleaning up superuser ephemeral lab: {lab_name}")
    destroy_url = f"{api_url}/api/v1/labs/{lab_name}"
    params = {"cleanup": "true"}
    try:
        # Superuser headers are already used here
        resp_del = requests.delete(destroy_url, headers=superuser_headers, params=params, timeout=cleanup_timeout)
        if resp_del.status_code == 404:
            logging.warning(f"  `-> [TEARDOWN-SU] Warning: Lab '{lab_name}' not found during cleanup.")
        elif resp_del.status_code != 200:
            logging.warning(f"  `-> [TEARDOWN-SU] Warning: Failed cleanup for lab '{lab_name}'. Status: {resp_del.status_code}, Response: {resp_del.text}")
        else:
            logging.info(f"  `-> [TEARDOWN-SU] Lab '{lab_name}' cleaned up successfully.")
        cleanup_pause_duration = request.config.getoption("--cleanup-pause", default=3)
        time.sleep(cleanup_pause_duration)
    except requests.exceptions.RequestException as e:
        logging.warning(f"  `-> [TEARDOWN-SU] Warning: Exception during superuser lab cleanup for '{lab_name}': {e}")


@pytest.fixture
def apiuser_lab(ephemeral_lab):
    """Alias for ephemeral_lab created by the default API user (apiuser)."""
    return ephemeral_lab

# --- Pytest Hooks ---
def pytest_addoption(parser):
    parser.addoption(
        "--cleanup-pause", action="store", default=3, type=int, help="Seconds to pause after lab cleanup."
    )

def pytest_configure(config):
    pass