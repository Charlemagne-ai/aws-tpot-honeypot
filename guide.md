![Screenshot 2025-03-27 at 2 21 29 AM](https://github.com/user-attachments/assets/1a3e1fb0-29fb-402a-af23-9cfeeffdd1de)


# AWS T-Pot Honeypot Guide

## Table of Contents
1. [Overview of T-Pot 24.04.1](#1-overview-of-t-pot-24041)
2. [AWS Prerequisites and Considerations](#2-aws-prerequisites-and-considerations)
3. [Launching an EC2 Instance (Ubuntu 22.04)](#3-launching-an-ec2-instance-ubuntu-2204)
4. [Preparing the System (Post-Launch Setup)](#4-preparing-the-system-post-launch-setup)
5. [Installing T-Pot 24.04.1](#5-installing-t-pot-24041)  
   5.1 [System Requirements Check](#51-system-requirements-check)  
   5.2 [One-line Installer (Recommended)](#52-one-line-installer-recommended)  
   5.3 [Reboot](#53-reboot)
6. [AWS Security Group Configuration](#6-aws-security-group-configuration)
7. [Post-Install Verification & Basic Usage](#7-post-install-verification--basic-usage)  
   7.1 [SSH on New Port](#71-ssh-on-new-port)  
   7.2 [Check T-Pot Service and Running Containers](#72-check-t-pot-service-and-running-containers)  
   7.3 [T-Pot Landing Page](#73-t-pot-landing-page)  
   7.4 [Kibana (Main Log Analysis Interface)](#74-kibana-main-log-analysis-interface)
8. [Daily Reboot & Cron Job](#8-daily-reboot--cron-job)
9. [Gathering and Managing Logs](#9-gathering-and-managing-logs)
10. [Enhancing Security](#10-enhancing-security)
11. [Disabling Community Data Submission (Optional)](#11-disabling-community-data-submission-optional)
12. [Day to Day Operation & Teardown](#12-day-to-day-operation--teardown)
13. [Quick Reference & Troubleshooting](#13-quick-reference--troubleshooting)
14. [Add Second Storage Volume (Optional)](#14-add-second-storage-volume-optional)  
   14.1 [Format Your Drive](#141-format-your-drive)  
   14.2 [Create a Mount Point and Mount It](#142-create-a-mount-point-and-mount-it)  
   14.3 [Add an Entry to /etc/fstab](#143-add-an-entry-to-etcfstab)  
   14.4 [Move T-Pot Logs to the New Drive](#144-move-t-pot-logs-to-the-new-drive)
15. [Final Thoughts & Further Enhancements](#final-thoughts--further-enhancements)

---

## 1. Overview of T-Pot 24.04.1

**T-Pot** is an all-in-one honeypot platform that bundles **20+ honeypots** (Cowrie, Dionaea, Conpot, etc.), plus multiple security and analysis tools (Elastic Stack, Suricata, CyberChef, Spiderfoot, etc.) in Docker containers.

Key highlights from T-Pot 24.04.1:

- **Multi-distribution support**: Installs on many Linux distros (Ubuntu, Debian, Fedora, Rocky, Alma, openSUSE, etc.).
- **LLM-based honeypots**: _Beelzebub_ and _Galah_ (optional, requiring GPU for Ollama or ChatGPT support).
- **Recommended system specs**:
  - **Sensor**: 8GB RAM & 128GB disk
  - **Hive** (i.e., full T-Pot on one system): 16GB RAM & 256GB disk
- **Default daily reboot** and automatic updates, with a flexible `docker-compose.yml`.
- **New default SSH port** is `64295`.
- **Blackhole Mode** to stealthily drop known mass scanners.

> **Disclaimer**: Deploy honeypots in isolated or dedicated environments. By design, honeypots attract malicious traffic.

---

## 2. AWS Prerequisites and Considerations

1. **AWS Account**: Must have permissions to launch/manage EC2, allocate Elastic IPs, manage Security Groups, etc.
2. **Instance Requirements**:
   - At minimum, an **8GB RAM** instance for a “sensor” type T-Pot.
   - If you want to enable more honeypots or the LLM-based honeypots (like Beelzebub/Galah), aim for **16GB+ RAM**.
   - **t3.large** (2 vCPU, 8GB RAM) is a _bare minimum_ for a sensor. For heavier usage, consider **t3.xlarge** (4 vCPU, 16GB).
3. **Storage**:
   - T-Pot can accumulate _large amounts_ of logs, especially if operated for several days.
   - Start with **128GB** EBS volume for a sensor, or **256GB** for a full hive if storing everything locally.
4. **VPC & Networking**:
   - Choose a **public subnet** to expose T-Pot to the internet.
   - Plan your **Security Group** inbound rules carefully (see [Section 6](#6-aws-security-group-configuration) below).
5. **Consistent Public IP**:
   - Use an **Elastic IP** to avoid changes if you stop/restart the instance.
6. **Costs**:
   - Consider compute (CPU/RAM), EBS storage, and data transfer fees.
7. **Security**:
   - Honeypots are intentionally vulnerable and _will_ be probed.
   - Do **not** store sensitive data.
   - Restrict management ports to your IP.
   - Keep the OS and T-Pot updated; plan to remove the instance after your test.

---

## 3. Launching an EC2 Instance (Ubuntu 22.04)

T-Pot supports multiple distributions, but **Ubuntu 22.04 LTS** is a straightforward choice in AWS.

1. **Choose AMI**:  
   - “Ubuntu Server 22.04 LTS (HVM), SSD Volume Type”  
   - Prefer the stable Canonical jammy image.
2. **Select Instance Type**:  
   - For a minimal sensor: `t3.large` (8GB).  
   - For a heavier deployment/hive: `t3.xlarge` (16GB) or higher.
3. **Key pair**:  
   - Select an existing or create a new key pair.  
   - Used for SSH into your EC2 instance.
4. **Configure Network**:  
   - Use a public subnet for direct internet access.  
   - If you prefer advanced setups, you can NAT/forward only certain ports; ensure T-Pot sees inbound connections.
5. **Add Storage**:
   - At least **128GB** EBS.  
   - If you plan on high-volume, go 256GB.  
   - In this example: 16GB (root volume) for OS + 256GB (EBS volume) for logs.
6. **Security Group**:
   - Inbound rule for SSH (port 22) to your IP for now.  
   - We’ll configure T-Pot’s ports (64295, 64297, etc.) in [Section 6](#6-aws-security-group-configuration).
7. **Elastic IP** (Optional):
   - Allocate & attach an Elastic IP to keep a stable IP if you stop your instance.

 ![Screenshot 2025-03-26 at 10 30 24 PM](https://github.com/user-attachments/assets/c1023e70-ee6e-4f7f-b160-d68fd6899e9c)
_Figure 1: Example EC2 setup. Region us-east-2 (Ohio)_

![Screenshot 2025-03-26 at 10 40 11 PM](https://github.com/user-attachments/assets/b166d6de-940c-4b73-b6d6-e0ff92a7bf27)
_Figure 2: Example EC2 Setup (cont.)_

---

## 4. Preparing the System (Post-Launch Setup)

1. **SSH to the Instance**:  
   Navigate to the directory with your `.pem` key.
   ```bash
   chmod 400 your-key.pem
   ssh -i /path/to/key.pem ubuntu@<Public-DNS>
   ```
   - Use port 22 initially if T-Pot isn’t installed yet. T-Pot later shifts SSH to `64295`.
   - You can find the connect command in the EC2 console → Connect → SSH client.

   ![ssh](https://github.com/user-attachments/assets/99f374c5-26b6-4e2f-b74b-b9fde570b895)


   ![Pasted image 20250325174056](https://github.com/user-attachments/assets/0a7aaac0-0704-42b0-bd80-4c1401e2f4b1)


2. **Update & Upgrade**:
   ```bash
   sudo apt-get update && sudo apt-get upgrade -y
   ```
3. **Install `curl`** (if missing):
   ```bash
   sudo apt-get install -y curl
   ```
4. **(Optional) Additional Utilities**:
   ```bash
   sudo apt-get install -y git wget net-tools
   ```

---

## 5. Installing T-Pot 24.04.1

### 5.1 System Requirements Check
- Confirm at least **8GB RAM** & **128GB** disk.
- Ensure non-filtered, outgoing internet (no proxies).
- T-Pot uses many honeypot ports—ensure your Security Group won’t block if you want real attacks.

### 5.2 One-line Installer (Recommended)
The newest T-Pot release includes a simplified installation script. Run it as a non-root user in `$HOME`:

```bash
env bash -c "$(curl -sL https://github.com/telekom-security/tpotce/raw/master/install.sh)"
```

![Pasted image 20250325175152](https://github.com/user-attachments/assets/2ab96b2c-445d-4d01-93aa-5769a5f1b4eb)


- Choose your installation type (`h` for Hive, `s` for Sensor, etc.).  
- Make sure you have the recommended requirements (Hive = 16GB+).  
- You’ll be prompted for a `<WEB_USER>` and password (BasicAuth for the T-Pot WebUI).

![Pasted image 20250325175903](https://github.com/user-attachments/assets/8d1d9def-5223-4804-8eb3-8784f953a937)


**What the installer does**:
- Changes SSH port to `64295`.
- Installs Docker + Docker Compose plugin & recommended packages.
- Disables conflicting services (DNS stub).
- Sets SELinux to monitor mode (some distros).
- Adds a `tpot` system user & a daily reboot cron.
- Configures T-Pot to run at startup, then reboots.

> **TIP**: Watch for port conflict messages if you have custom services.

### 5.3 Reboot
Once finished, reboot:

```bash
sudo reboot
```

When the instance is back, T-Pot is running. SSH now uses port **64295** by default.

---

## 6. AWS Security Group Configuration

T-Pot uses a wide range of ports. At minimum:

| **Port**       | **Purpose**                                                 |
|----------------|-------------------------------------------------------------|
| 64295 (TCP)    | **SSH** (T-Pot’s new SSH port)                              |
| 64297 (TCP)    | **NGINX Reverse Proxy** (Kibana, Attack Map, CyberChef, etc.) |
| 1–64000 (TCP/UDP) | (Optional) Full coverage. Otherwise open only needed ports. |

**Best Practice**:
- Restrict `64295` and `64297` to **your IP** only.
- If you only want specific honeypots, open those ports.  
- In the setup below, we open ports 1–64000.

![Pasted image 20250325181932](https://github.com/user-attachments/assets/eb8d1938-c48c-42d6-acbb-60118e81f1e3)


> **Note**: If you don’t have a static IP, your IP lease may change. Update the inbound rules if your IP changes to regain SSH/WebUI access.

---

## 7. Post-Install Verification & Basic Usage

### 7.1 SSH on New Port
After the T-Pot reboot, SSH on port 64295:

```bash
ssh -p 64295 -i your-key.pem ubuntu@<Public-DNS>
```
**Example**:
```bash
ssh -p 64295 -i your-key.pem ubuntu@ec2-xx-xxx-xxx-xxx.us-east-2.compute.amazonaws.com
```
- Username: `ubuntu` (or your OS user).

### 7.2 Check T-Pot Service and Running Containers
```bash
systemctl status tpot
dps
```
![Pasted image 20250325182350](https://github.com/user-attachments/assets/fb0bac76-ca1f-40d6-9021-6febb95df902)


- Should see multiple containers (Cowrie, Dionaea, Kibana, etc.).
- Status should indicate “Up.”

### 7.3 T-Pot Landing Page
Open your browser:
```
https://<AWS-Public-IPv4>:64297
```
> Obtain `AWS-Public-IPv4` from the EC2 instance page.

![Pasted image 20250325182624](https://github.com/user-attachments/assets/a19e4da3-afbe-465d-b576-17526ce36041)


#### Input the `<WEB_USER>` Credentials
![Pasted image 20250325182729](https://github.com/user-attachments/assets/4e24c4b9-5250-4ce6-94a2-e1001f501910)


- This logs you into the T-Pot WebUI.
- From here, you can access:
  - **Kibana**, **CyberChef**, **Elasticvue**, **Spiderfoot**
  - **Attack Map**

![Pasted image 20250325182938](https://github.com/user-attachments/assets/d17a7cca-a954-44a6-b3bd-1d922674d983)


### 7.4 Kibana (Main Log Analysis Interface)
- Click **Kibana** in the T-Pot Landing Page, or:
  ```
  https://<AWS-Public-IPv4>:64297/kibana
  ```
- Explore the dashboards for each honeypot.
- You’ll see hits accumulating over time.

![Pasted image 20250325183133](https://github.com/user-attachments/assets/325b8bbe-f0b4-4070-a69e-bcc1e8d4728d)


---

## 8. Daily Reboot & Cron Job
By default, T-Pot sets up a **daily reboot** around 2:42 AM:

```bash
sudo crontab -e

# T-Pot daily reboot
42 2 * * * bash -c 'systemctl stop tpot.service && docker container prune -f; docker image prune -f; docker volume prune -f; /usr/sbin/shutdown -r +1 "T-Pot Daily Reboot"'
```
If you want uninterrupted operation, remove/comment out that line.

---

## 9. Gathering and Managing Logs

1. **Kibana**:
   - Real-time visualization (top attackers, geolocation, etc.).
   - Export logs in Kibana (Stack Management → Saved Objects or Discover).
2. **Exporting Logs**:
   - T-Pot data is in **Elasticsearch** (Docker container).
   - For offline analysis, you can:
     - Export from Kibana as NDJSON/CSV.
     - Copy data from `~/tpotce/data/...`.
   - HPFeeds or third-party submission is also available.
3. **Log Retention**:
   - T-Pot sets 30-day index lifecycle policy by default. Adjust in Kibana if needed.
4. **Persistent Data**:
   - Volumes under `~/tpotce/data`. For forensics, create an EBS snapshot or tarball at test end.

---

## 10. Enhancing Security

1. **Restrict Management**:
   - Restrict Kibana (`64297`) and SSH (`64295`) to your IP.
2. **OS-Level Firewall**:
   - T-Pot modifies some firewall settings. Be sure it doesn’t block needed honeypot ports.
3. **Blackhole Mode**:
   - `TPOT_BLACKHOLE=ENABLED` in `~/tpotce/.env` blocks known mass scanners but reduces overall hits.
4. **Avoid Exposing** T-Pot’s Docker or other services beyond honeypots.

---

## 11. Disabling Community Data Submission (Optional)

T-Pot sends anonymized data to **Sicherheitstacho** by default. To opt out:

1. `sudo systemctl stop tpot`
2. Edit `~/tpotce/docker-compose.yml`
3. Remove/comment out the `ewsposter` block.
4. `sudo systemctl start tpot`

---

## 12. Day to Day Operation & Teardown

1. **Operation**:
   - Check Kibana daily.
   - Watch EC2 usage in CloudWatch.
   - T-Pot reboots daily unless disabled.
2. **Before Teardown**:
   - Export data from Kibana or copy `~/tpotce/data` for offline analysis.
   - (Optional) EBS snapshot or AMI image for full backups.
3. **Terminate the EC2**:
   - Disassociate your Elastic IP if no longer needed.
   - Terminate the instance once logs are gathered.

---

## 13. Quick Reference & Troubleshooting

1. **Check Container Health**:
   ```bash
   dpsw 2
   ```
2. **Review Logs**:
   ```bash
   docker logs -f <container_name>
   cat ~/tpotce/data/tpotinit.log
   ```
3. **Stop T-Pot**:
   ```bash
   sudo systemctl stop tpot
   ```
4. **Start T-Pot**:
   ```bash
   sudo systemctl start tpot
   ```
5. **If You Lose SSH Access**:
   - Check AWS SG rules, daily reboot, and confirm port changes.
   - Remember port `64295`.
6. **Low RAM/Disk**:
   - Elasticsearch/Logstash can crash if under-resourced.
   - Monitor with `htop` or `docker stats`.
7. **Disk Space**:
   - Keep an eye on `df -h` to avoid filling up the partition.

---

## 14. Add Second Storage Volume (Optional)

If you run out of space for logs, you can attach a second EBS volume. Many prefer having a separate volume from the OS to keep logs and utilize gp3 for cost savings. Create the volume in AWS, attach it, then follow these steps.

### 14.1 Format Your Drive

1. **Create a Partition** (optional, but recommended)
   ```bash
   sudo parted /dev/nvme1n1 -- mklabel gpt
   sudo parted /dev/nvme1n1 -- mkpart primary ext4 0% 100%
   ```
   Afterward, you may have `/dev/nvme1n1p1`.

2. **Format** (ext4):
   ```bash
   sudo mkfs.ext4 /dev/nvme1n1p1
   ```
   (Adjust if parted labeled it differently.)

---

### 14.2 Create a Mount Point and Mount It
```bash
sudo mkdir /data
sudo mount /dev/nvme1n1p1 /data
df -h
```
You should see `/data` with the new capacity (e.g., 256GB).

---

### 14.3 Add an Entry to `/etc/fstab`
So it auto-mounts on reboot:
```bash
echo "/dev/nvme1n1p1 /data ext4 defaults 0 0" | sudo tee -a /etc/fstab
```

---

### 14.4 Move T-Pot Logs to the New Drive
T-Pot stores data in `~/tpotce/data`. Let’s relocate:

1. **Stop T-Pot**:
   ```bash
   sudo systemctl stop tpot
   ```
2. **Move the Data Folder**:
   ```bash
   mv ~/tpotce/data /data/tpot-data
   ```
3. **Symlink** it back:
   ```bash
   ln -s /data/tpot-data ~/tpotce/data
   ```
4. **Start T-Pot**:
   ```bash
   sudo systemctl start tpot
   ```

5. **Confirm with**:
   ```bash
   df -h
   ```
   Now T-Pot writes data to `/data/tpot-data`.

---

## Final Thoughts & Further Enhancements

With T-Pot 24.04.1 on AWS:

1. **You have a single EC2 instance** running a robust multi-honeypot environment (Hive or Sensor style).  
2. **Data ingestion** happens in real-time, visible via Kibana, Attack Map, and more.  
3. **Fine-tune your honeypot** by restricting or opening specific ports and adjusting T-Pot’s settings so it behaves more like a genuine production system. Attackers are adept at identifying honeypot signatures, so a realistic environment can attract deeper or more sophisticated attacks.  
4. **Avoid storing sensitive data**; remember that honeypots are by design open to malicious traffic.  
5. **Plan your post-run analysis** by exporting or snapshotting your logs, then safely terminate the EC2 to avoid further charges.

I hope this guide helps you successfully deploy and manage T-Pot on AWS. Feel free to experiment with new honeypot configurations, visualization dashboards, or additional cloud monitoring tools. If you have questions or want to share findings, reach out on my socials. 

**Happy Hacking!**

*Charlemagne (0xCD)*
