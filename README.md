
# AWS T-Pot Honeypot Deployment & Analysis (In Progress)

**Deployed and analyzed a T-Pot honeypot within AWS to monitor, visualize, and report cyber threats, providing actionable insights into real-time attack patterns.**

![aws-honey](https://github.com/user-attachments/assets/1d0cf542-d1da-4d87-9de5-c673e25e30d9)


## Technologies Used
- AWS
- T-Pot Honeypot
- Threat Visualization

[GitHub Repository](https://github.com/Charlemagne-ai/aws-tpot-honeypot)

## Project Overview

**Status: In Progress**

This ongoing project involves deploying and configuring the T-Pot multi-honeypot platform on AWS cloud infrastructure. T-Pot is a comprehensive honeypot solution that offers 20+ honeypot types with extensive visualization options using the Elastic Stack, animated live attack maps, and security analysis tools.

![t-pot](https://github.com/user-attachments/assets/3aca46e4-10ef-4ccc-9e43-98e8a900bbc7)


## Technical Implementation

![t-pot-architecture](https://github.com/user-attachments/assets/6567eb86-2550-48c6-a9b9-4eb1b2133be8)


*Figure 1: T-Pot Multi-Honeypot Architecture*

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

As this project progresses, I'll be adding more detailed findings and visualizations of captured attack data. The deployment is currently operational and actively collecting data, with analysis dashboards under development.
