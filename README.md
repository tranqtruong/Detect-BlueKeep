# 🛡️ BlueKeep Exploit Detection (CVE-2019-0708)

This project demonstrates a proof-of-concept system to detect remote exploitation attempts targeting the **BlueKeep vulnerability** (CVE-2019-0708) in Microsoft's RDP service.

> 📝 Final report project for "Cybersecurity Specialization" course – PTIT University (Vietnam)

---

## 📌 Overview

**BlueKeep (CVE-2019-0708)** is a critical "Remote Code Execution" vulnerability in Microsoft Remote Desktop Services affecting older Windows systems (Windows XP to Windows 7, and Server 2003/2008). It is classified as a **wormable vulnerability**, meaning it can propagate without user interaction.

This project simulates an exploitation scenario using `Metasploit` and implements a Python-based detection mechanism using `PyShark`.

---

## 🧪 Lab Setup

| Device       | Description                                         | IP              |
|--------------|-----------------------------------------------------|-----------------|
| Attacker     | Kali Linux on VMware using Metasploit               | `192.168.20.133` |
| Victim       | Windows 7 SP1 vulnerable to BlueKeep (RDP port 3389) | `192.168.20.134` |

---

## 🚨 Exploit Behavior

- The attacker initiates RDP connection using a **custom client**.
- It requests creation of virtual channel `MS_T120`, which **already exists**.
- This triggers a **Use-After-Free** in `termdd.sys` leading to RCE.

### 🧩 Detection Signatures:

| Encryption Level | Signature                             | Detectable Info     |
|------------------|----------------------------------------|----------------------|
| Low              | `MS_T120` channel request in plaintext | via packet analysis  |
| High             | Random `cookie` + memory overflow      | via behavioral analysis |

---

## 🐍 Detection Script

A simple Python detection tool using `pyshark`:

```bash
pip install pyshark
python bluekeep_detector.py
