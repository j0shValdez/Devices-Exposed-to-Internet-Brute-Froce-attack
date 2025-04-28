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
- **Endpoint Detection and Response (ERD): Microsoft Defener for Endpoint (MDE)**
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
  - **Objective:** Investigate whether any unauthorized or suspicious logon activity occure on the exposed machine while it was unintentionaly accessible from the internet.
- **Targeted investigation at exposed devices**
  - (`DeviceName`) == (`windows-target-1`)

- **Why defining a clear objective and hypothesis is important**:
  - Having a clear objective and hypothesis in threat hunting ensures that the investigation is focused, efficient, and evidence-driven. Without a defined starting point, threat hunting efforts can become random and disorganized, wasting time and resources. A well-crafted hypothesis helps guide the search for potential threats based on actual risks or behaviors observed in the environment. Threat hunting can be approached in many ways but a generalized process usually looks like:
    - Create Hypotheses
    - Investigation
    - TTPs Identification
    - Resonse and Mitigation
    - Learning and Immproving

  
---

## Data Collection Phase

- During this phase, I gathered relevent data from logs, network traffic, and endpoints. I inspected the logs to see which devices have been exposed to the internet and have received exssive failed lonin attempts.
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




- **Legitimate Logons:** Now I wanted to see if there were any successful logons and who logged on. The first query fetched all successful logon events for `windows-target-1`, showing which accounts had accessed the VM over the previous 30 days. The second query fetches the number of failled logons for the authroized accounts. By reviewing these legitimate logons, I confirmed that no unexpected or unauthorized access occurred during the exposure period. A brute force attempt did not take place, and a 1-time password guess is unlikeley. 

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

- Based on the data collected and analyzed, brute-force attempts were identified on the exposed machine. Although no unauthorized access was confirmed several MITRE ATT&CK techniques were relevant to the findings.
- No unauthorized access confirmed.
- Linked findings to **MITRE ATT&CK** tactics:
  - **T1190** - Exploit Public-Facing Application
    - Adversaries attempt to exploite weaknesses in the internet-facing systems or services to gain unauthroized access. The VM in question was unintentionally exposed to the internet, increasing the risks of external explitation.
    - ![image](https://github.com/user-attachments/assets/e89b5727-6dde-425f-b569-f68413984328)

  - **T1110** - Brute Force
    - Adversaries try to guess valid creentials through repeate login attempts. Numberous failed login attempts were detected from multiple external IPs, fitting the brute-force attack pattern.
    - ![image](https://github.com/user-attachments/assets/fab6042a-d3f5-4064-a325-115fc10381d6)

  - **T1078** - Valid Accounts
    - Adversaries may leverage valid credentials to access systems. Althrough multiple brute-force attemtps occured in the above threat hunt, no unauthorized successful logins were found. Only legitimate logons were observed indicating no account compromise.

    - ![image](https://github.com/user-attachments/assets/0ec92136-b3fb-4bb8-a8d4-312a08cadf7d)



---

## Response Phase

During the investigation, it was comfirmed that the machine in question had been unintentionally exposed to the public internet. While this exposure was intentional for the purposes of this lab, in a real-world scenario, virtual machines should never be publically accessile without strict security controls. 

To remediate the exposure and reduce the attack surface, I simulated the implementation of several critical security measure:
- **Hardened the Network Security Group (NSG):**
  - Restrict inbound Remomte Desktop Protocol (RDP) traffic to trusted IP addresses only (no open RDP to the public internet)
  - Go to **Azure Portal** → **Virtual Machines** → Select **windows-target-1**.
    - Navigated to the **Networking** tab.
    - Under **Network Settings**, located the attached **Network Security Group (NSG)**.
    - Add a new inbound security rule:
      - **Destination Port:** 3389 (RDP)
      - **Source IP Addresses:** Only allowed trusted internal IP(s).
      - **Action:** Allow
      - **Priority:** Lower than the default deny rule (e.g., priority 300).
  - Deleted or disabled any existing rules allowing RDP access from **Any** (`0.0.0.0/0`).

- **Implemented Account Lokout Policies:**
  - Prevent brute-force attacks by locking accounts after a set number of failed login attempts
  - On the VM (Windows Server):
  - Opened **Group Policy Editor** (`gpedit.msc`) and navigated to:
    - **Computer Configuration** → **Windows Settings** → **Security Settings** → **Account Policies** → **Account Lockout Policy**.
  - Configured the following:
    - **Account lockout threshold:** (4 invalid attempts)
    - **Account lockout duration:** (10 minutes)
    - **Reset account lockout counter after:** (10 minutes)
    - **Allow Administrator account lockout:** Enabled (recommended for stronger security)
  - Apply and refresh Group Policy.
  - ![image](https://github.com/user-attachments/assets/6f79952d-fdc1-4347-8187-9a529aaf9dd4)

- **Implemented Multi-Factor Authenication (MFA):**
  - Strengthen login security by requiring a second form of authentication
  - I logged into the Azure Portal and navigated to **Entra ID** (formerly Azure AD).
    - Under **Security**, I selected **Conditional Access** and clicked **+ New policy**.
    - I targeted the appropriate **users/groups** and added **Azure Management** under **Cloud apps**.
    - In **Access controls**, I chose **Require multi-factor authentication**.
  - I enabled the policy and verified that MFA was enforced on all login attempts for `windows-target-1`.

---

## Documentation Phase

- Recorded my findings above.
- Documented what I found and used it to improve future hunts and defenses.
  - Saved all KQL queries, screenshots, and timelines in a dedicated “Threat Hunt” folder.
  - Summarized the exposure window, brute-force IPs, successful logons, and TTPs above.

---

## Improvement Phase

- **Lessons Learned:** Documented what worked and what didn’t.  
- **Detection Tuning:** Built/updated Sentinel analytics rules to alert on repeated failed logins to any internet-facing VM.  
- **Automation:** Scripted NSG exposure audits and lockout-policy checks using Azure Policy and PowerShell.  
- **Future Hypotheses:** Identified additional scenarios (e.g., credential stuffing, lateral movement) to expand the hunt library.
---

## Summary

In this threat hunting project, I investigated a Windows VM (windows-target-1) that was unintentionally exposed to the internet, using Microsoft Defender for Endpoint (MDE) and KQL. My hypothesis was that brute-force login attempts might have occurred, and I used KQL queries to analyze login activity. The investigation revealed multiple failed login attempts from suspicious external IP addresses but no successful unauthorized access. Based on these findings, I recommended and simulated the implementation of stronger security measures, including restricting RDP access, updating Network Security Group (NSG) rules, enabling account lockout policies, and enforcing Multi-Factor Authentication (MFA) for enhanced security.





