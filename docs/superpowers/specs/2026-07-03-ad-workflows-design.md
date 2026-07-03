# AD Testing Workflows for Osmedeus

## Overview

Add Windows Active Directory security testing capabilities to the osmedeus-workflow repository. This introduces a new AD testing pipeline alongside the existing web recon pipeline.

## Target Type

IP/CIDR — AD servers are addressed by IP, not domain name. Follows the existing `cidr.yaml` pattern.

## Modules (common/)

### ad-enum.yaml
- **Tools**: netexec smb, ldapsearch, enum4linux-ng
- **Purpose**: Basic AD discovery — find DCs, enumerate users/groups/computers, check null sessions, dump password policy
- **Outputs**: Domain info JSON, user/group/computer lists, password policy, SMB signing status

### ad-kerberos.yaml
- **Tools**: impacket-GetNPUsers, impacket-GetUserSPNs, kerbrute
- **Purpose**: Kerberos attack primitives — AS-REP roasting (no pre-auth users), Kerberoasting (service accounts), user enumeration via Kerberos
- **Outputs**: AS-REP roastable users list, Kerberoastable accounts list, valid usernames list

### ad-ldap.yaml
- **Tools**: ldapsearch, netexec ldap
- **Purpose**: LDAP interrogation — anonymous bind testing, domain info extraction, LDAP signing requirements
- **Outputs**: LDAP domain dump JSON, LDAP signing status

### ad-smb.yaml
- **Tools**: netexec smb, smbclient, smbmap
- **Purpose**: SMB enumeration — share listing, null session access, SMB signing check, anonymous access
- **Outputs**: SMB shares list, signing status, accessible shares

### ad-lateral.yaml (extensive only)
- **Tools**: netexec winrm, netexec wmi, evil-winrm, impacket-psexec
- **Purpose**: Lateral movement primitives — WinRM/WMI access checks, admin access validation
- **Outputs**: Accessible hosts per protocol, admin access list

## Flows

| Flow | Includes | Use case |
|------|----------|----------|
| `ad-standard.yaml` | enum → kerberos → ldap → smb | Routine AD assessment |
| `ad-extensive.yaml` | All of standard + lateral | Full AD penetration test |

## Fragments (fragments/do-ad-*.yaml)

Single-target (do-*) variants of each module for use in CIDR-style flows.

## File Naming Convention

- `common/ad-<phase>.yaml` — reusable modules
- `fragments/do-ad-<phase>.yaml` — single-target variants
- `ad-<variant>.yaml` — flow definitions

## Dependencies (commands:)

netexec, impacket, kerbrute, ldapsearch, enum4linux-ng, smbclient, smbmap

## Pipeline Flow

```
Target IP/CIDR
  → ad-enum (domain discovery, user/group enumeration)
    → ad-kerberos (AS-REP, Kerberoasting)
    → ad-ldap (LDAP interrogation)
    → ad-smb (SMB shares, signing)
  → ad-lateral [extensive only] (WinRM/WMI access checks)
```
