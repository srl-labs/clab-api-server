# tests/test_labs.py
import requests
import time

# Note: These tests rely on fixtures defined in conftest.py

def test_list_labs_includes_created(api_url, auth_headers, apiuser_lab):
    """
    Verify a newly created lab (via fixture) appears in the labs list for the user.
    """
    lab_name = apiuser_lab # Get the lab name from the fixture
    print(f"\n[TEST] Verifying lab '{lab_name}' is in the list for the owner.")

    list_url = f"{api_url}/api/v1/labs"
    resp = requests.get(list_url, headers=auth_headers, timeout=15)
    assert resp.status_code == 200, f"Expected 200 listing labs, got {resp.status_code}: {resp.text}"

    labs_data = resp.json()
    assert isinstance(labs_data, dict), "Expected labs list to be a dictionary"
    assert lab_name in labs_data, f"Lab '{lab_name}' created by fixture was not found in /api/v1/labs output for the user"
    assert len(labs_data[lab_name]) > 0, f"Lab '{lab_name}' should have container entries"
    print(f"  `-> Lab '{lab_name}' found in list.")

def test_inspect_created_lab(api_url, auth_headers, apiuser_lab):
    """
    Test inspecting the lab created by the fixture.
    """
    lab_name = apiuser_lab
    print(f"\n[TEST] Inspecting details for lab '{lab_name}'.")
    inspect_url = f"{api_url}/api/v1/labs/{lab_name}"
    resp = requests.get(inspect_url, headers=auth_headers, timeout=15)
    assert resp.status_code == 200, f"Expected 200 inspecting lab '{lab_name}', got {resp.status_code}: {resp.text}"
    lab_details = resp.json()
    assert isinstance(lab_details, list), "Expected inspect output to be a list of containers"
    assert len(lab_details) > 0, "Inspect output should contain container details"
    assert lab_details[0].get("lab_name") == lab_name
    print(f"  `-> Inspection successful for '{lab_name}'.")


def test_create_duplicate_lab_fails(api_url, auth_headers, apiuser_lab, simple_topology_content, deploy_timeout):
    """
    Attempt to create a lab with the same name as an existing lab (created by fixture).
    Expect a 409 Conflict without reconfigure=true.
    """
    lab_name = apiuser_lab # Lab already exists thanks to the fixture
    print(f"\n[TEST] Attempting to create duplicate lab '{lab_name}' (expecting 409).")

    # Prepare request body again
    topology_yaml = simple_topology_content.format(lab_name=lab_name)
    deploy_url = f"{api_url}/api/v1/labs"
    req_body = {
        "topologyContent": topology_yaml,
    }

    # Attempt to deploy again
    resp = requests.post(deploy_url, json=req_body, headers=auth_headers, timeout=deploy_timeout)
    print(f"  `-> Received status {resp.status_code}. Asserting it's 409.")
    assert resp.status_code == 409, f"Expected 409 Conflict when creating duplicate lab '{lab_name}', got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "error" in data
    assert f"Lab '{lab_name}' already exists" in data["error"]

def test_reconfigure_lab_owner_succeeds(api_url, auth_headers, apiuser_lab, simple_topology_content, deploy_timeout, lab_stabilize_pause):
    """
    Attempt to re-deploy a lab with the same name using reconfigure=true by the owner.
    Expect a 200 OK.
    """
    lab_name = apiuser_lab # Lab already exists
    print(f"\n[TEST] Attempting to reconfigure owned lab '{lab_name}' (expecting 200).")

    topology_yaml = simple_topology_content.format(lab_name=lab_name)
    deploy_url = f"{api_url}/api/v1/labs"
    req_body = {"topologyContent": topology_yaml}
    params = {"reconfigure": "true"}

    # Attempt to re-deploy
    resp = requests.post(deploy_url, json=req_body, headers=auth_headers, params=params, timeout=deploy_timeout)
    print(f"  `-> Received status {resp.status_code}. Asserting it's 200.")
    assert resp.status_code == 200, f"Expected 200 OK when reconfiguring owned lab '{lab_name}', got {resp.status_code}: {resp.text}"

    print(f"  `-> Pausing for stabilization after reconfigure...")
    time.sleep(lab_stabilize_pause)

def test_reconfigure_lab_non_owner_fails(api_url, apiuser_headers, superuser_lab, simple_topology_content, deploy_timeout):
    """
    Attempt to re-deploy a lab owned by the superuser using reconfigure=true as a normal user.
    Expect a 403 Forbidden.
    """
    lab_name = superuser_lab # Lab exists, owned by superuser
    print(f"\n[TEST] Attempting non-owner reconfigure on lab '{lab_name}' (expecting 403).")

    topology_yaml = simple_topology_content.format(lab_name=lab_name)
    deploy_url = f"{api_url}/api/v1/labs"
    req_body = {"topologyContent": topology_yaml}
    params = {"reconfigure": "true"}

    # Attempt to re-deploy using normal apiuser headers
    resp = requests.post(deploy_url, json=req_body, headers=apiuser_headers, params=params, timeout=deploy_timeout)
    print(f"  `-> Received status {resp.status_code}. Asserting it's 403.")
    assert resp.status_code == 403, f"Expected 403 Forbidden when non-owner reconfiguring lab '{lab_name}', got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "error" in data
    assert "Reconfigure permission denied" in data["error"]

def test_reconfigure_lab_superuser_succeeds(api_url, superuser_headers, apiuser_lab, simple_topology_content, deploy_timeout, lab_stabilize_pause):
    """
    Attempt to re-deploy a lab owned by a normal user using reconfigure=true as a superuser.
    Expect a 200 OK.
    """
    lab_name = apiuser_lab # Lab exists, owned by apiuser
    print(f"\n[TEST] Attempting superuser reconfigure on lab '{lab_name}' (expecting 200).")

    topology_yaml = simple_topology_content.format(lab_name=lab_name)
    deploy_url = f"{api_url}/api/v1/labs"
    req_body = {"topologyContent": topology_yaml}
    params = {"reconfigure": "true"}

    # Attempt to re-deploy using superuser headers
    resp = requests.post(deploy_url, json=req_body, headers=superuser_headers, params=params, timeout=deploy_timeout)
    print(f"  `-> Received status {resp.status_code}. Asserting it's 200.")
    assert resp.status_code == 200, f"Expected 200 OK when superuser reconfiguring lab '{lab_name}', got {resp.status_code}: {resp.text}"

    print(f"  `-> Pausing for stabilization after superuser reconfigure...")
    time.sleep(lab_stabilize_pause)

def test_list_labs_superuser(api_url, superuser_headers, apiuser_lab, superuser_lab):
    """
    Verify superuser sees labs owned by others.
    Fixtures ensure both labs exist concurrently for this test.
    """
    apiuser_created_lab = apiuser_lab
    superuser_created_lab = superuser_lab
    print(f"\n[TEST] Verifying superuser sees labs '{apiuser_created_lab}' and '{superuser_created_lab}'.")

    list_url = f"{api_url}/api/v1/labs"
    resp = requests.get(list_url, headers=superuser_headers, timeout=15)
    assert resp.status_code == 200, f"Expected 200 listing labs as superuser, got {resp.status_code}: {resp.text}"

    labs_data = resp.json()
    assert isinstance(labs_data, dict)
    assert apiuser_created_lab in labs_data, f"Superuser should see lab '{apiuser_created_lab}' created by apiuser"
    assert superuser_created_lab in labs_data, f"Superuser should see lab '{superuser_created_lab}' created by superuser"
    print(f"  `-> Superuser list check successful.")

def test_list_labs_apiuser_filters(api_url, apiuser_headers, apiuser_lab, superuser_lab):
    """
    Verify normal apiuser only sees their own labs.
    Fixtures ensure both labs exist concurrently for this test.
    """
    apiuser_created_lab = apiuser_lab
    superuser_created_lab = superuser_lab
    print(f"\n[TEST] Verifying apiuser sees '{apiuser_created_lab}' but NOT '{superuser_created_lab}'.")

    list_url = f"{api_url}/api/v1/labs"
    resp = requests.get(list_url, headers=apiuser_headers, timeout=15)
    assert resp.status_code == 200, f"Expected 200 listing labs as apiuser, got {resp.status_code}: {resp.text}"

    labs_data = resp.json()
    assert isinstance(labs_data, dict)
    assert apiuser_created_lab in labs_data, f"Apiuser should see their own lab '{apiuser_created_lab}'"
    assert superuser_created_lab not in labs_data, f"Apiuser should NOT see lab '{superuser_created_lab}' owned by superuser"
    print(f"  `-> Apiuser list filtering check successful.")

# --- Placeholder for future tests ---
# def test_deploy_from_url(...): pass
# def test_deploy_from_archive(...): pass
# def test_inspect_non_existent_lab(...): pass
# def test_inspect_other_user_lab_permission(...): pass
# def test_destroy_non_existent_lab(...): pass
# def test_destroy_other_user_lab_permission(...): pass
# def test_exec_command(...): pass
# def test_save_config(...): pass
# def test_tools_endpoints_permissions(...): pass