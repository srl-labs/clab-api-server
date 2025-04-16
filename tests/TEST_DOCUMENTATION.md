# Containerlab API Tests Documentation

This document explains the test suite for the Containerlab API server. The tests verify authentication and lab management functionality, ensuring that permissions, ownership validation, and multi-user segregation work as expected.

## Setup and Configuration

The test suite uses a configuration structure (`TestConfig`) that loads values from environment variables or defaults:

- **API URL**: Location of the API server to test against
- **User credentials**: For superuser, API user, and unauthorized user
- **Timeouts**: For various operations (request, deploy, cleanup)
- **Lab configuration**: Naming and topology content

## Authentication Tests (`auth_test.go`)

| Test Name | Description | Expected Result |
|-----------|-------------|-----------------|
| `TestLoginSuperuser` | Attempts to log in using the superuser credentials | Successful login with valid token |
| `TestLoginAPIUser` | Attempts to log in using the API user credentials | Successful login with valid token |
| `TestInvalidLogin` | Attempts to log in with non-existent user and incorrect password | 401 Unauthorized with error message |
| `TestUnauthorizedUserLogin` | Attempts to log in with a user that exists but is not in required groups | 401 Unauthorized with error message |

### Authentication Test Details

1. **`TestLoginSuperuser`**
   - Logs in with the superuser credentials
   - Verifies a non-empty token is returned
   - Checks that the token has reasonable length

2. **`TestLoginAPIUser`**
   - Logs in with the API user credentials
   - Verifies a non-empty token is returned
   - Checks that the token has reasonable length

3. **`TestInvalidLogin`**
   - Attempts login with a non-existent username and incorrect password
   - Verifies a 401 Unauthorized status code is returned
   - Checks for an error message in the response body

4. **`TestUnauthorizedUserLogin`**
   - Attempts login with a real user that is not in any of the required groups
   - Verifies a 401 Unauthorized status code is returned
   - Checks for an error message in the response body

## Lab Management Tests (`labs_test.go`)

| Test Name | Description | Expected Result |
|-----------|-------------|-----------------|
| `TestListLabsIncludesCreated` | Creates a lab and checks if it appears in the list of labs for the owner | Lab is present in the list |
| `TestInspectCreatedLab` | Creates a lab and checks detailed inspection | Successful inspection with correct lab details |
| `TestCreateDuplicateLabFails` | Attempts to create a lab with the same name as an existing one | 409 Conflict with error about existing lab |
| `TestReconfigureLabOwnerSucceeds` | Attempts to reconfigure a lab as its owner | 200 OK with successful reconfiguration |
| `TestReconfigureLabNonOwnerFails` | Attempts to reconfigure a lab as a user who doesn't own it | 403 Forbidden with permission denied message |
| `TestReconfigureLabSuperuserSucceeds` | Attempts to reconfigure a lab owned by another user as superuser | 200 OK with successful reconfiguration |
| `TestListLabsSuperuser` | Checks if superuser can see labs created by both themselves and other users | Both labs are visible to superuser |
| `TestListLabsAPIUserFilters` | Checks if regular API user can only see their own labs | Only user's own labs are visible, superuser labs are filtered out |

### Lab Management Test Details

1. **`TestListLabsIncludesCreated`**
   - Creates a lab using the API user credentials
   - Lists all labs for the user
   - Verifies the newly created lab appears in the list
   - Checks that the lab has container entries

2. **`TestInspectCreatedLab`**
   - Creates a lab using the API user credentials
   - Inspects the lab details
   - Verifies the inspection returns detailed information
   - Checks that the lab name matches what was created

3. **`TestCreateDuplicateLabFails`**
   - Creates a lab using the API user credentials
   - Attempts to create another lab with the same name
   - Verifies a 409 Conflict status code is returned
   - Checks for an error message indicating the lab already exists

4. **`TestReconfigureLabOwnerSucceeds`**
   - Creates a lab using the API user credentials
   - Attempts to reconfigure the lab as the same user
   - Verifies a 200 OK status code is returned
   - Checks that the reconfiguration is successful

5. **`TestReconfigureLabNonOwnerFails`**
   - Creates a lab as the superuser
   - Attempts to reconfigure the lab as the API user
   - Verifies a 403 Forbidden status code is returned
   - Checks for a permission denied error message

6. **`TestReconfigureLabSuperuserSucceeds`**
   - Creates a lab as the API user
   - Attempts to reconfigure the lab as the superuser
   - Verifies a 200 OK status code is returned
   - Checks that the reconfiguration is successful

7. **`TestListLabsSuperuser`**
   - Creates one lab as the API user and another as the superuser
   - Lists all labs using the superuser credentials
   - Verifies both labs appear in the list

8. **`TestListLabsAPIUserFilters`**
   - Creates one lab as the API user and another as the superuser
   - Lists all labs using the API user credentials
   - Verifies only the lab created by the API user appears in the list
   - Checks that the superuser's lab is filtered out

## Helper Functions

The test suite includes several helper functions to facilitate testing:

### Lab Lifecycle Helpers

- **`setupEphemeralLab`**: Creates a test lab that's automatically cleaned up after the test
- **`setupSuperuserLab`**: Creates a test lab as superuser that's automatically cleaned up
- **`createLab`**: Deploys a lab with the specified topology
- **`destroyLab`**: Destroys a lab and optionally cleans up its directory

### Authentication Helpers

- **`login`**: Handles authentication and token retrieval
- **`getAuthHeaders`**: Creates HTTP headers with the appropriate Authorization token

### HTTP Request Helper

- **`doRequest`**: Generic HTTP request helper with logging
- **`logHeaders`**: Logs HTTP headers with sensitive information masked
- **`logBody`**: Logs request/response bodies with potential masking for sensitive data

## Test Environment

The tests require a running Containerlab API server and appropriate user accounts:

1. A superuser account that is a member of the configured superuser group
2. An API user account that is a member of the configured API user group
3. An unauthorized user account that exists but is not a member of any required group

## Configuration via Environment Variables

The test suite can be configured using environment variables:

```
API_URL=http://127.0.0.1:8080
SUPERUSER_USER=root
SUPERUSER_PASS=rootpassword
APIUSER_USER=test
APIUSER_PASS=test
UNAUTH_USER=test2
UNAUTH_PASS=test2
GOTEST_TIMEOUT_REQUEST=15s
GOTEST_TIMEOUT_DEPLOY=240s
GOTEST_TIMEOUT_CLEANUP=180s
GOTEST_STABILIZE_PAUSE=10s
GOTEST_CLEANUP_PAUSE=3s
GOTEST_LAB_NAME_PREFIX=gotest
GOTEST_SIMPLE_TOPOLOGY_CONTENT=...
```

The GOTEST_SIMPLE_TOPOLOGY_CONTENT must contain a `{lab_name}` placeholder that will be replaced with a generated lab name during testing.

## Running the Tests

To run the entire test suite:

```bash
go test -v ./tests_go
```

To run specific tests:

```bash
go test -v ./tests_go -run TestLoginSuperuser
```

The `-v` flag provides verbose output, which is useful for debugging.