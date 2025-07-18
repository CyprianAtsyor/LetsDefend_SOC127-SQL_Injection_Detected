# LetsDefend_SOC127-SQL_Injection_Detected


# 🛡️ SOC127 - SQL Injection Detected

This project documents the detection and analysis of a simulated SQL Injection attack as part of a LetsDefend SOC investigation challenge. It showcases real-world detection, log analysis, and response steps, including raw payload inspection and interpretation.

---

## 📌 What is SQL Injection?

**SQL Injection (SQLi)** is a web application vulnerability that occurs when malicious SQL statements are injected into an entry field for execution. It allows attackers to:

* View or manipulate data they shouldn't access
* Perform administrative operations on the database
* Potentially execute system-level commands
* Bypass authentication mechanisms

---

## 🔍 How to Detect SQL Injection

**Detection techniques include:**

* **Log Analysis:** Look for suspicious strings like `' OR '1'='1`, `UNION SELECT`, or `--`.
* **Error Monitoring:** Watch for database errors returned to the user interface.
* **WAF & SIEM Alerts:** Web Application Firewalls and SIEMs flag common SQLi payloads.
* **Abnormal Query Behavior:** Check for strange or unauthorized queries in logs.

---

## 🧪 Attack Scenario Summary

* **Date:** March 7, 2024
* **Source IP:** `118.194.247.28` (Confirmed malicious via VirusTotal and AbuseIPDB)
* **Destination:** `WebServer1000 (172.16.20.12)`
* **Tool Used:** sqlmap (`sqlmap/1.7.2#stable`)
* **Action:** Allowed by the device (no blocking)

### Payload Example 1 – Union-based + XSS + Command Execution:

```http
GET /?douj=3034 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#
```

### Payload Example 2 – Boolean-based Injection:

```http
GET /index.php?id=1') AND 2574=CAST((CHR(113)||CHR(107)||CHR(107)||CHR(118)||CHR(113))||(SELECT (CASE WHEN (2574=2574) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(112)||CHR(122)||CHR(106)||CHR(113)) AS NUMERIC) AND ('FiHf'='FiHf
```

### Payload Example 3 – Time-based Injection:

```http
GET /index.php?id=1);SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(104)||CHR(97)||CHR(109)||CHR(77),5) FROM DUAL--
```

> These payloads indicate attempts to extract database information, execute system-level commands, and measure database response time — all typical of sqlmap automation.

---

## 🔎 Log Evidence

📸 *Screenshot: SIEM alert for SOC127 - SQL Injection Detected*
![SIEM Alert Screenshot](images/soc127-siem-alert.png)

📸 *Screenshot: Raw payloads found in logs*
![Raw Logs](images/soc127-raw-logs.png)

📸 *Screenshot: VirusTotal lookup for IP 118.194.247.28*
![VirusTotal Lookup](images/soc127-virustotal-ip.png)

📸 *Screenshot: AbuseIPDB reports*
![AbuseIPDB Screenshot](images/soc127-abuseipdb.png)

---

## 🧠 Final Notes (4-liner Summary)

A series of SQL injection attempts were detected from IP `118.194.247.28` targeting `WebServer1000`.
Payloads included union-based, boolean-based, and time-based injections via sqlmap.
The attacks reached the server (`200 OK`) without initial blocking, indicating exposure.
Source IP confirmed malicious — recommend updating WAF rules and hardening inputs.

---

## 🔗 Tools & Resources

* [LetsDefend](https://letsdefend.io)
* [sqlmap](https://sqlmap.org)
* [URL Decoder](https://www.urldecoder.org/)
* [VirusTotal](https://www.virustotal.com)
* [AbuseIPDB](https://www.abuseipdb.com)

---

## 🤩 Tags

`SOC` `SQL Injection` `SIEM` `Threat Hunting` `Log Analysis` `Cybersecurity` `LetsDefend`

