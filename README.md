# Threat Hunting: Identifying Brute Force Attempts on Exposed VM

_**Project Overview**_:

During this lab, I conducted a threat hunt on a VM (`windows-target-1`) that was unintentionally exposed to the internet.


**Objective:** Investigate potential brute-force login attempts and validate whether any unauthorized access occurred.

> **Hypothesis:** During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have brute-force logged into some of them, especially since some older devices lacked account lockout policies for excessive failed login attempts.
---
<p align="center">
  <img src="https://github.com/user-attachments/assets/c7c19510-a053-419c-a6ff-96b3c80082c3" width="500" height="500" />
</p>


# Technologies Utilized
- **Microsoft Defener for Endpoint (MDE)**
- **Kusto Query Lnguage (KQL)**
- **Virtual Machin (VM): Windows OS**
- **Microsoft Azure**

---

## Table of Contents
- [Preparation Phase](#preparation-phase)
- [Data Collection Phase](#data-collection-phase)
- [Data Analysis Phase](#data-analysis-phase)
- [Investigation Phase](#investigation-phase)
- [Response Phase](#response-phase)
- [Documentation Phase](#documentation-phase)
- [Improvement Phase](#improvement-phase)
- [Summary](#summary)
- [Technologies Used](#technologies-used)
- [Skills Highlighted](#skills-highlighted)

---

## Preparation Phase

- Defined a clear objective and hypothesis.
- Targeted investigation at exposed devices.

---

## Data Collection Phase

- Collected data from:
  - `DeviceInfo`
  - `DeviceLogonEvents`
- Focused on logons from external sources.

---

## Data Analysis Phase

**Queries and Key Findings:**

- **Internet Exposure Check:**
  ```kusto
  DeviceInfo
  | where DeviceName == "windows-target-1"
  | where IsInternetFacing == "true"
  | order by Timestamp desc
  ```
  > Finding: `windows-target-1` was exposed up until `2025-04-25T17:28:30Z`.

- **Failed Logon Attempts:**
  ```kusto
  DeviceLogonEvents
  | where DeviceName == "windows-target-1"
  | where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
  | where ActionType == "LogonFailed"
  | where isnotempty(RemoteIP)
  | summarize Attempts = count() by ActionType, RemoteIP, DeviceName
  | order by Attempts
  ```
  > Finding: IP `197.210.194.246` failed login 65 times.

- **Successful Logon Attempts:**
  ```kusto
  let RemoteIPsInQuestion = dynamic(["197.210.194.240","135.125.90.97","180.193.221.205","118.107.40.165","178.20.129.235"]);
  DeviceLogonEvents
  | where DeviceName == "windows-target-1"
  | where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
  | where ActionType == "LogonSuccess"
  | where RemoteIP has_any(RemoteIPsInQuestion)
  ```
  > Finding: No successful unauthorized logins.

- **Legitimate Logons:**
  ```kusto
  DeviceLogonEvents
  | where DeviceName == "windows-target-1"
  | where ActionType == "LogonSuccess"
  | where AccountName in ("umfd-1", "dwm-1", "umfd-0", "dwm-0")
  ```
  > Finding: Only legitimate system accounts logged in.

---

## Investigation Phase

- Brute-force attempts identified.
- No unauthorized access confirmed.
- Linked findings to MITRE ATT&CK tactics:
  - **T1190** - Exploit Public-Facing Application
  - **T1110** - Brute Force
  - **T1078** - Valid Accounts

---

## Response Phase

- Hardened NSG rules to restrict RDP access.
- Recommended implementing:
  - Account lockout policies.
  - Multi-Factor Authentication (MFA).

---

## Documentation Phase

- Documented:
  - Hypothesis
  - Queries used
  - Key findings
  - Response actions

---

## Improvement Phase

**Lessons Learned:**

- Perform proactive internet exposure audits.
- Harden default configurations.
- Enforce security policies like lockout thresholds and MFA.

---

## Summary

The VM was exposed to the internet and faced multiple brute-force login attempts, but no successful unauthorized access was identified. This project demonstrated the value of structured threat hunting, proactive security measures, and the importance of continuous improvement.

---

## Technologies Used

- Microsoft Sentinel (Azure SIEM)
- Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- Windows Server 2019

---

## Skills Highlighted

- Threat Hunting Methodology
- Log Collection and Analysis
- Brute Force Attack Detection
- KQL Scripting
- Network Security Hardening
- Incident Documentation and Response

---

> **Note:** This lab is part of my hands-on cybersecurity analyst training projects to develop threat detection and incident response skills.

---

### Connect with Me
- [LinkedIn Profile](#) *(Insert your LinkedIn link here)*
