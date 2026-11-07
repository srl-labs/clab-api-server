---
description: Who can sign in, how roles work, and how to manage users.
---

# Users and sign-in

The server has no user database of its own. It signs in Linux accounts on the host with their passwords, and uses Linux groups as roles.
{ .lead }

## Roles

| Role | Linux group | Can |
| --- | --- | --- |
| User | `API_USER_GROUP` (default `clab_api`) | Work with own labs and [shared labs](shared-labs.md). |
| Superuser | `SUPERUSER_GROUP` (default `clab_admins`) | Work with every lab, and manage users. |

Accounts in neither group cannot sign in.

```bash
sudo usermod -aG clab_api alice
sudo usermod -aG clab_admins bob
```

Superuser rights follow the group on every request. Taking someone out of `clab_api` stops new sign-ins; tokens they already have work until they expire.

## Sign in

`POST /login` takes a user name and password, checks them with PAM (the `login` service), and returns a JWT:

```bash
curl -sk -X POST https://localhost:8090/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"..."}'
```

Tokens are signed with `JWT_SECRET` and expire after `JWT_EXPIRATION`, or after `sessionDuration` if the request sets it. Changing `JWT_SECRET` signs everyone out.

## Manage users over the API

Superusers can manage Linux accounts through `/api/v1/users`: list, create, update, and delete them, and set their groups. Every user can read and update their own account, and change their own password with `PUT /api/v1/users/{username}/password`.

## Where a user's labs live

Each user has a workspace: `~/.clab/` by default, or `$CLAB_LABS_ROOT/<username>/` when [`CLAB_LABS_ROOT`](../reference/configuration.md) is set. Files in it belong to the user. See [Workspaces and topology files](workspaces.md).
