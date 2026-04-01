#!/usr/bin/env python3
"""
CloudProwl - Microsoft Service Access Enumerator

Takes a refresh token and uses roadtx to exchange it against major Microsoft
service audiences, then queries enumeration endpoints to confirm real access.

Usage:
    python3 cloudprowl.py <refresh_token>
"""

import json
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
import uuid

CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

BANNER = r"""
  ░░░░░░ ░░       ░░░░░░  ░░    ░░ ░░░░░░
 ░░      ░░      ░░    ░░ ░░    ░░ ░░   ░░
 ░░      ░░      ░░    ░░ ░░    ░░ ░░   ░░
 ░░      ░░      ░░    ░░ ░░    ░░ ░░   ░░
  ░░░░░░ ░░░░░░░  ░░░░░░   ░░░░░░  ░░░░░░

 ░░░░░░  ░░░░░░   ░░░░░░  ░░     ░░ ░░
 ░░   ░░ ░░   ░░ ░░    ░░ ░░     ░░ ░░
 ░░░░░░  ░░░░░░  ░░    ░░ ░░  ░  ░░ ░░
 ░░      ░░   ░░ ░░    ░░ ░░ ░░░ ░░ ░░
 ░░      ░░   ░░  ░░░░░░   ░░░ ░░░  ░░░░░░░
"""

SERVICES = [
    {
        "name": "Microsoft Graph",
        "resource": "https://graph.microsoft.com",
        "enum_url": "https://graph.microsoft.com/v1.0/me",
        "description": "User profile, mail, groups, directory objects",
        "context": "Enumerate users, groups, mail, OneDrive files, app registrations, service principals",
    },
    {
        "name": "Azure Resource Manager",
        "resource": "https://management.azure.com",
        "enum_url": "https://management.azure.com/subscriptions?api-version=2022-12-01",
        "description": "Azure subscriptions and resources",
        "context": "Enumerate VMs, networking, RBAC assignments, Key Vaults, Storage Accounts, and all resources in accessible subscriptions",
    },
    {
        "name": "Power Platform (BAP)",
        "resource": "https://api.bap.microsoft.com",
        "enum_url": "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments?api-version=2020-10-01",
        "description": "Power Apps, Power Automate environments",
        "context": "Enumerate environments, connectors, and pivot to Dataverse for data plane access",
    },
    {
        "name": "Dataverse",
        "description": "Data backend for Power Platform environments",
        "context": "Canvas apps, model-driven apps, flows, and custom tables with business data, credentials, or secrets",
        "bap_enum": True,
    },
    {
        "name": "Power Apps",
        "resource": "https://service.powerapps.com",
        "enum_url": "https://api.powerapps.com/providers/Microsoft.PowerApps/apps?api-version=2016-11-01",
        "description": "Power Apps applications",
        "context": "Apps may expose business logic, service connections, and data through embedded connectors",
    },
    {
        "name": "Microsoft Flow",
        "resource": "https://service.flow.microsoft.com",
        "enum_url": "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments?api-version=2016-11-01",
        "description": "Power Automate flows",
        "context": "Flows may contain hardcoded credentials, service connections, and automation logic to hijack",
    },
    {
        "name": "Azure DevOps",
        "resource": "https://app.vssps.visualstudio.com",
        "enum_url": "https://app.vssps.visualstudio.com/_apis/accounts?api-version=7.0",
        "description": "Azure DevOps organizations and projects",
        "context": "Source code repos, CI/CD pipelines, service connections, variable groups with secrets",
    },
    {
        "name": "Microsoft Teams",
        "resource": "https://api.spaces.skype.com",
        "enum_url": "https://teams.microsoft.com/api/mt/part/emea-03/beta/users/tenants",
        "description": "Teams chats, channels, meetings",
        "context": "Chat history, shared files in channels, meeting recordings, and sensitive internal communications",
    },
    {
        "name": "Outlook / Exchange Online",
        "resource": "https://outlook.office365.com",
        "enum_url": "https://outlook.office365.com/api/v2.0/me",
        "description": "Mail, calendar, contacts",
        "context": "Email access for password reset interception, sensitive comms, calendar intelligence for social engineering",
    },
]


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[38;2;0;127;255m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def check_dependencies():
    """Check and install required dependencies."""
    if shutil.which("roadtx"):
        return

    print(f"  {Colors.YELLOW}[*] roadtx not found, installing...{Colors.RESET}")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "roadtx", "--break-system-packages", "-q"],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if shutil.which("roadtx"):
            print(f"  {Colors.GREEN}[+] roadtx installed successfully{Colors.RESET}")
        else:
            # May need to check pip scripts path
            result = subprocess.run(
                [sys.executable, "-m", "pip", "show", "roadtx"],
                capture_output=True, text=True
            )
            print(f"  {Colors.GREEN}[+] roadtx installed (you may need to add pip scripts to PATH){Colors.RESET}")
    except subprocess.CalledProcessError as e:
        print(f"  {Colors.RED}[!] Failed to install roadtx: {e.stderr[:100]}{Colors.RESET}")
        print(f"  {Colors.RED}[!] Install manually: pip install roadtx{Colors.RESET}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"  {Colors.RED}[!] Timeout installing roadtx{Colors.RESET}")
        sys.exit(1)
    print()


def roadtx_get_token(refresh_token, resource):
    """Use roadtx to exchange refresh token for an access token.
    Returns (access_token, new_refresh_token, tenant_id, error)."""
    try:
        result = subprocess.run(
            [
                "roadtx", "auth",
                "--refresh-token", refresh_token,
                "-c", CLIENT_ID,
                "-r", resource,
                "--tokens-stdout",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        print(f"\n  {Colors.RED}[!] roadtx not found even after install attempt{Colors.RESET}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        return None, None, None, "Timeout"

    stdout = result.stdout.strip()
    if not stdout:
        err_msg = result.stderr.strip() or "No output from roadtx"
        return None, None, None, err_msg[:120]

    try:
        auth = json.loads(stdout)
        access_token = auth.get("accessToken")
        new_refresh = auth.get("refreshToken")
        tenant_id = auth.get("tenantId")
        if access_token:
            return access_token, new_refresh, tenant_id, None
        return None, None, None, "No access token in response"
    except json.JSONDecodeError as e:
        return None, None, None, f"Failed to parse roadtx output: {str(e)[:80]}"


def query_service(url, access_token, extra_headers=None):
    """Query a service enumeration endpoint and return status + response."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "x-ms-client-request-id": str(uuid.uuid4()),
    }
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, method="GET", headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body_bytes = resp.read().decode()
            try:
                body = json.loads(body_bytes)
            except json.JSONDecodeError:
                body = body_bytes
            return resp.status, body, None
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
            return e.code, body, None
        except (json.JSONDecodeError, Exception):
            return e.code, None, str(e)
    except Exception as e:
        return None, None, str(e)


def enumerate_dataverse(refresh_token, bap_environments):
    """Chains off BAP: for each environment with a Dataverse instance, exchange RT
    for a Dataverse-scoped token and probe the data plane."""
    env_results = []

    for env in bap_environments:
        props = env.get("properties", {})
        linked = props.get("linkedEnvironmentMetadata", {})
        instance_api_url = linked.get("instanceApiUrl", "")
        env_name = props.get("displayName", env.get("name", "N/A"))
        env_type = props.get("environmentType", "unknown")

        if not instance_api_url:
            env_results.append({
                "name": env_name,
                "type": env_type,
                "access": None,
                "detail": "No Dataverse instance provisioned",
            })
            continue

        # Exchange refresh token for Dataverse-scoped token
        dv_token, new_rt, _, token_err = roadtx_get_token(refresh_token, instance_api_url + "/")
        if new_rt:
            refresh_token = new_rt

        if not dv_token:
            env_results.append({
                "name": env_name,
                "type": env_type,
                "instance_url": instance_api_url,
                "access": False,
                "detail": f"Token exchange failed: {token_err[:80] if token_err else 'unknown'}",
            })
            continue

        # Probe Dataverse data plane
        findings = []
        odata_headers = {"OData-MaxVersion": "4.0", "OData-Version": "4.0"}

        # Canvas apps
        canvas_url = f"{instance_api_url}/api/data/v9.2/canvasapps?$select=displayname,canvasappid"
        status, body, err = query_service(canvas_url, dv_token, odata_headers)
        if status == 200 and isinstance(body, dict):
            apps = body.get("value", [])
            if apps:
                app_names = [a.get("displayname", "unnamed") for a in apps[:5]]
                findings.append(f"Canvas apps: {', '.join(app_names)}")

        # Model-driven apps
        model_url = f"{instance_api_url}/api/data/v9.2/appmodules?$select=name,uniquename"
        status, body, err = query_service(model_url, dv_token, odata_headers)
        if status == 200 and isinstance(body, dict):
            apps = body.get("value", [])
            if apps:
                app_names = [a.get("name", "unnamed") for a in apps[:5]]
                findings.append(f"Model-driven apps: {', '.join(app_names)}")

        # Unmanaged solutions
        sol_url = f"{instance_api_url}/api/data/v9.2/solutions?$select=friendlyname,uniquename&$filter=ismanaged eq false"
        status, body, err = query_service(sol_url, dv_token, odata_headers)
        if status == 200 and isinstance(body, dict):
            sols = body.get("value", [])
            if sols:
                sol_names = [s.get("friendlyname", s.get("uniquename", "unnamed")) for s in sols[:5]]
                findings.append(f"Unmanaged solutions: {', '.join(sol_names)}")

        env_results.append({
            "name": env_name,
            "type": env_type,
            "instance_url": instance_api_url,
            "access": True,
            "findings": findings,
        })

    return env_results, refresh_token


def summarize_response(service_name, status, body, tenant_id=None):
    """Extract a contextual summary based on the specific service."""
    if body is None:
        return "No response body"

    if isinstance(body, dict) and "error" in body:
        err = body["error"]
        if isinstance(err, dict):
            return f"Error: {err.get('code', 'unknown')} - {err.get('message', 'no message')[:120]}"
        return f"Error: {err}"

    items = []
    if isinstance(body, dict) and "value" in body and isinstance(body["value"], list):
        items = body["value"]

    if service_name == "Microsoft Graph":
        upn = body.get("userPrincipalName", "N/A")
        display = body.get("displayName", "N/A")
        tid = f", Tenant: {tenant_id}" if tenant_id else ""
        return f"Authenticated as {display} ({upn}){tid}"

    if service_name == "Azure Resource Manager":
        if not items:
            return "No subscriptions found"
        subs = []
        for s in items[:3]:
            sid = s.get("subscriptionId", "N/A")
            name = s.get("displayName", "unnamed")
            subs.append(f"{name} ({sid})")
        suffix = f" ... +{len(items) - 3} more" if len(items) > 3 else ""
        return f"Subscriptions: {', '.join(subs)}{suffix}"

    if service_name == "Power Platform (BAP)":
        if not items:
            return "No environments found"
        envs = []
        for e in items[:3]:
            props = e.get("properties", {})
            name = props.get("displayName", e.get("name", "N/A"))
            env_type = props.get("environmentType", "unknown")
            envs.append(f"{name} ({env_type})")
        suffix = f" ... +{len(items) - 3} more" if len(items) > 3 else ""
        return f"Environments: {', '.join(envs)}{suffix}"

    if service_name == "Power Apps":
        if not items:
            return "No apps found"
        apps = []
        for a in items[:3]:
            props = a.get("properties", {})
            name = props.get("displayName", a.get("name", "N/A"))
            apps.append(name)
        suffix = f" ... +{len(items) - 3} more" if len(items) > 3 else ""
        return f"Apps: {', '.join(apps)}{suffix}"

    if service_name == "Microsoft Flow":
        if not items:
            return "No environments found"
        envs = []
        for e in items[:3]:
            props = e.get("properties", {})
            name = props.get("displayName", e.get("name", "N/A"))
            envs.append(name)
        suffix = f" ... +{len(items) - 3} more" if len(items) > 3 else ""
        return f"Environments: {', '.join(envs)}{suffix}"

    if service_name == "Azure DevOps":
        if isinstance(body, dict) and "value" in body:
            orgs = []
            for o in items[:3]:
                name = o.get("accountName", o.get("AccountName", "N/A"))
                orgs.append(name)
            suffix = f" ... +{len(items) - 3} more" if len(items) > 3 else ""
            return f"Organizations: {', '.join(orgs)}{suffix}"
        if isinstance(body, list):
            orgs = [o.get("accountName", "N/A") for o in body[:3]]
            return f"Organizations: {', '.join(orgs)}"
        return f"Response received ({status})"

    if service_name == "Microsoft Teams":
        if isinstance(body, list) and body:
            tenants = []
            for t in body[:3]:
                name = t.get("tenantName", t.get("displayName", t.get("name", "N/A")))
                tenants.append(name)
            return f"Teams enabled - Tenant(s): {', '.join(tenants)}"
        if isinstance(body, dict):
            if "tenantId" in body:
                name = body.get("tenantName", body.get("displayName", body.get("tenantId")))
                return f"Teams enabled - Tenant: {name}"
            if "userId" in body or "userPrincipalName" in body:
                return f"Teams enabled for {body.get('userPrincipalName', body.get('userId', 'this user'))}"
            return "Teams license active - user can access chats, channels, and shared files"
        return "Teams license active - user can access chats, channels, and shared files"

    if service_name == "Outlook / Exchange Online":
        if isinstance(body, dict):
            email = body.get("EmailAddress", body.get("Mail", "N/A"))
            display = body.get("DisplayName", body.get("displayName", "N/A"))
            return f"Mailbox: {display} ({email})"
        return "Mailbox access confirmed"

    # Fallback
    if items:
        return f"{len(items)} item(s) returned"
    return f"Response received ({status})"


def has_real_access(status, body):
    """Determine if the response indicates actual permissioned access."""
    if status is None:
        return False
    if status == 200:
        if isinstance(body, dict):
            if "error" in body:
                return False
            if "value" in body and isinstance(body["value"], list) and len(body["value"]) == 0:
                return None  # Ambiguous
            return True
        if isinstance(body, list):
            return True if body else None
        return True
    return False


def print_dataverse_results(svc, env_results):
    """Print results for Dataverse enumeration."""
    if not env_results:
        print(f"        Access: {Colors.YELLOW}No Power Platform environments to probe{Colors.RESET}")
        print()
        return

    any_access = False
    for env in env_results:
        env_label = f"{env['name']} ({env['type']})"

        if env.get("access") is None:
            print(f"        Env:    {Colors.DIM}{env_label}{Colors.RESET} -> {env.get('detail', 'No Dataverse')}")
            continue

        if not env.get("access"):
            print(f"        Env:    {Colors.RED}{env_label}{Colors.RESET} -> {env.get('detail', 'Access denied')}")
            continue

        any_access = True
        instance = env.get("instance_url", "")
        print(f"        Env:    {Colors.GREEN}{env_label}{Colors.RESET}")
        print(f"                Instance: {instance}")
        findings = env.get("findings", [])
        if findings:
            for f in findings:
                print(f"                {f}")
        else:
            print(f"                Data plane accessible (no apps or solutions found)")

    if any_access:
        print(f"        {Colors.BLUE}Impact: {svc['context']}{Colors.RESET}")

    print()


def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python3 cloudprowl.py <refresh_token>")
        sys.exit(1)

    refresh_token = sys.argv[1].strip()
    if not refresh_token:
        print("[!] Empty refresh token provided")
        sys.exit(1)

    print(f"{Colors.BLUE}{BANNER}{Colors.RESET}")

    check_dependencies()

    # State tracked across services
    bap_environments = []
    tenant_id = None

    for i, svc in enumerate(SERVICES, 1):
        name = svc["name"]
        print(f"  [{i:2d}/{len(SERVICES)}] {Colors.BOLD}{name}{Colors.RESET}")
        print(f"        {Colors.DIM}{svc['description']}{Colors.RESET}")

        # Dataverse: chains off BAP, no direct token exchange needed here
        if svc.get("bap_enum"):
            if not bap_environments:
                print(f"        Access: {Colors.RED}Skipped{Colors.RESET} - No Power Platform environments discovered")
                print()
                continue

            env_results, refresh_token = enumerate_dataverse(refresh_token, bap_environments)
            print_dataverse_results(svc, env_results)
            continue

        # Standard: token exchange + direct enumeration
        access_token, new_refresh, tid, token_err = roadtx_get_token(refresh_token, svc["resource"])
        if access_token:
            print(f"        Token: {Colors.GREEN}Obtained{Colors.RESET}")
            if new_refresh:
                refresh_token = new_refresh
            if tid and not tenant_id:
                tenant_id = tid
        else:
            print(f"        Token: {Colors.RED}Failed{Colors.RESET} - {token_err}")
            print()
            continue

        status, body, query_err = query_service(svc["enum_url"], access_token)

        if query_err and status is None:
            print(f"        Access: {Colors.RED}Query failed{Colors.RESET} - {query_err[:100]}")
            print()
            continue

        # Store BAP environments for Dataverse
        if name == "Power Platform (BAP)" and status == 200 and isinstance(body, dict):
            bap_environments = body.get("value", [])

        access = has_real_access(status, body)
        summary = summarize_response(name, status, body, tenant_id=tenant_id)

        if access is True:
            print(f"        Access: {Colors.GREEN}{Colors.BOLD}CONFIRMED ({status}){Colors.RESET}")
            print(f"        Detail: {summary}")
            print(f"        {Colors.BLUE}Impact: {svc['context']}{Colors.RESET}")
        elif access is None:
            print(f"        Access: {Colors.YELLOW}AMBIGUOUS ({status}){Colors.RESET}")
            print(f"        Detail: {summary}")
        else:
            print(f"        Access: {Colors.RED}DENIED ({status}){Colors.RESET}")
            print(f"        Detail: {summary}")

        print()


if __name__ == "__main__":
    main()
