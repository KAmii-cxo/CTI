# 🛡️ Cyber Threat Intelligence (CTI) - Beginner to Analyst Journey

Welcome to my CTI (Cyber Threat Intelligence) practice repository!  
This repo is dedicated to hands-on labs, learning notes, IOC collections, and my journey into threat intelligence and threat hunting.

---

## 📘 What is Cyber Threat Intelligence?

**Cyber Threat Intelligence (CTI)** is evidence-based knowledge about:

- 🎯 **Threat actors**
- 🧠 **Tactics, Techniques, and Procedures (TTPs)**
- 🧩 **Indicators of Compromise (IOCs)**
- 🎯 **Attack goals and motivations**

This information helps defenders **detect, respond to, and prevent cyber threats** more effectively.

---

## 🧩 Types of CTI

| Type         | Purpose                                               | Consumers                      |
|--------------|--------------------------------------------------------|--------------------------------|
| **Strategic** | High-level context (who, why, political motives)       | Executives, CISO, policy makers |
| **Tactical**  | TTPs and behavioral patterns of attackers              | SOC analysts, Blue teams        |
| **Operational**| Details about ongoing or planned campaigns            | Incident responders             |
| **Technical** | Raw IOCs like IPs, hashes, URLs, domains               | Threat hunters, detection engineers |

---

## 🧪 Real-World Use Case Example

> 📈 **Spike in PowerShell Traffic in the Network**

### 🔍 Steps Taken with CTI:

1. Checked **threat feeds** (AlienVault OTX, AbuseIPDB)
2. Discovered **Cobalt Strike C2 IP address**
3. Mapped behavior to **MITRE ATT&CK T1059.001**
4. Cross-checked threat actor activity (**APT29** behavior)
5. Created **detection rule** (YARA / Sigma / Splunk)

✅ Turned raw data into actionable intelligence.

---

## 🛠 Tools Used

| Tool              | Purpose                            |
|-------------------|-------------------------------------|
| 🧪 **MalwareBazaar / VirusTotal** | Collect samples, gather IOCs |
| 🧠 **MITRE ATT&CK**          | Map behaviors and techniques  |
| 🧵 **MISP**                  | Threat sharing platform       |
| 🧬 **TheHive + Cortex**       | CTI + Incident Response       |
| 🌍 **Shodan / Censys**        | External recon / OSINT        |
| 🕵️‍♂️ **Maltego / SpiderFoot**  | OSINT + link analysis         |

---

## 🔧 How I Practice CTI

```bash
1. 🐾 Download malware samples from MalwareBazaar
2. 🔎 Extract IOCs using tools (e.g., PeStudio, Strings, VirusTotal)
3. 🗺️ Map IOCs and behaviors to MITRE ATT&CK TTPs
4. 📑 Create a CTI report with context (see templates below)
5. 💬 Share insights with the community (LinkedIn, blog, this repo)
