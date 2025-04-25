# Threat Hunting: Identifying Brute Force Attempts on Exposed VM 
<p align="center">
  ** IN PROGRESS **
</p>

_**Project Overview**_:

In this threat hunting lab, I investigated a **Windows Virtual Machine (VM)** (`windows-target-1`) that was unintentionally exposed to the internet, using **Microsoft Defender for Endpoint**. I developed a hypothesis that **brute-force login attempts** may have occurred and used **KQL** to analyze logon activity. My investigation revealed multiple failed login attempts from suspicious external IP addresses, but no signs of successful unauthorized access. As a result, I recommended and implemented stronger access controls, including **restricting RDP access**, updating **Network Security Group (NSG) rules**, and **enabling account lockout policies** to prevent future exposure and attacks.

> **Hypothesis:** During the time the device was unknowingly exposed to the internet, it’s possible that someone could have brute-force logged into it, especially since some older devices lacked account lockout policies for excessive failed login attempts.
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

---

## Preparation Phase

- **Defined a clear objective and hypothesis**
  - **Hypothesis:** During the time the device was unknowingly exposed to the internet, it’s possible that someone could have brute-force logged into it, especially since some older devices lacked account lockout policies for excessive failed login attempts.
- **Targeted investigation at exposed devices**
  - (`DeviceName`) == (`windows-target-1`)

---

## Data Collection Phase

- During this phase, I gathered relevent data from logs, network traffic, and endpoints. I inspected the logs to see which devices have been exposed to the internet and have received eessive ailed lonin attempts.
- Collected data from:
  - `DeviceInfo`
  - `DeviceLogonEvents`
- Focused on logons from external sources.

---

## Data Analysis Phase

**Queries and Key Findings:**

- **Internet Exposure Check:** This query retrieves all records from the `DeviceInfo` table for `windows-target-1` where it’s marked as internet-facing, then sorts those entries by timestamp (newest first). It shows exactly when—and for how long—the VM was exposed to external networks.

  ```kusto
  DeviceInfo
  | where DeviceName == "windows-target-1"
  | where IsInternetFacing == "true"
  | order by Timestamp desc
  ```
  > Finding: `windows-target-1` was exposed to the internet for over one week and up until current time : `2025-04-25T17:28:30Z`.

- **Failed Logon Attempts:** I wanted to see how many attempts have been made to the target machine. The query identifies and counts failed login attempts to the target machine by various bad actors, filtering by logon types such as "Network," "Interactive," "RemoteInteractive," and "Unlock," and summarizing the attempts by RemoteIP. The results are ordered by the number of attempts.  
  ```kusto
  DeviceLogonEvents
  | where DeviceName == "windows-target-1"
  | where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
  | where ActionType == "LogonFailed"
  | where isnotempty(RemoteIP)
  | summarize Attempts = count() by ActionType, RemoteIP, DeviceName
  | order by Attempts
  ```
  <p align="center">
  <img src="https://github.com/user-attachments/assets/a390c103-100b-4105-a12d-2515ad7862d3" />
</p>

   > **Finding**: Several bad actors have been discovere attempting to login to the target machine. The IP `197.210.194.246` attempted to brute-force the machine 65 times. You can see a number of other IPs attempting to login to (`windows-target-1`)




- **Successful Logon Attempts:** Based on the above failled attempts, I wanted to see if any of those IPs have successfully logined into the exposed machine. This query defines a list of the top five IPs with the highest failed login counts, then checks the `DeviceLogonEvents` table for any successful logons from those same IPs on `windows-target-1`. It’s used to verify whether any of the top brute-force offenders ever managed to gain access.
  
  ```kusto
  let RemoteIPsInQuestion = dynamic(["197.210.194.240","135.125.90.97","180.193.221.205","118.107.40.165","178.20.129.235"]);
  DeviceLogonEvents
  | where DeviceName == "windows-target-1"
  | where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
  | where ActionType == "LogonSuccess"
  | where RemoteIP has_any(RemoteIPsInQuestion)
  ```
<p align="center">
  <img src="https://github.com/user-attachments/assets/50c552e3-b7f4-49f5-812c-0ed1935630f2"/>
</p>

  > Finding: No results were returned, indicating that none of the top five IPs with the most failed login attempts ever achieved a successful login to `windows-target-1`. This confirms that, despite repeated brute-force attempts, the VM remained secure against those specific sources.




- **Legitimate Logons:** Now I wanted to see if there were any successful logons and who who logged on. The first query fetched all successful logon events for `windows-target-1`, showing which accounts had accessed the VM over the previous 30 days. The second query fetches the number of failled logons for the authroize accounts. By reviewing these legitimate logons, I confirmed that no unexpected or unauthorized access occurred during the exposure period. A brute force attempt did not take place, and a 1-time password guess is unlikeley. 

  ```kusto
  DeviceLogonEvents
  | where DeviceName == "windows-target-1"
  | where ActionType == "LogonSuccess"
  ```
<p align="center">
  <img src="https://github.com/user-attachments/assets/e080db58-6f06-4b45-b652-929b3a224204" />
</p>

 ```kusto
  DeviceLogonEvents
  | where DeviceName == "windows-target-1"
  | where ActionType == "LogonSuccess"
  | where AccountName in ("umfd-1", "dwm-1", "umfd-0", "dwm-0")

  ```
<p align="center">
  <img src="https://github.com/user-attachments/assets/50c552e3-b7f4-49f5-812c-0ed1935630f2"/>
</p>

  > Finding: Only legitimate authorized accounts logged in. Those accounts had zero (0) failed logons.  Accounts: "umfd-1", "dwm-1", "umfd-0", "dwm-0"


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





