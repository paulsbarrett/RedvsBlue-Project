

## Capstone Engagement

## Assessment, Analysis,

## and Hardening of a Vulnerable System

# Report Prepared by Paul Barrett





## Table of Contents

# 01 **Network Topology**

# 02 **Red Team**: Security Assessment

# 03 **Blue Team**: Log Analysis and Attack Characterization

# 04 **Hardening**: Proposed Alarms and Mitigation Strategies

# 05 **Assessment Summary**

# 06 **Appendix**



## Preface

This report has been prepared for the purpose of identifying critical vulnerbilities on my client’s network. The targeted approach undertaken was to first use the Red Team to identify risks and penetrate in similar ways that a hacker might. This is a highly recommended approach to testing how your existing cybersecurity defenses stack up.

Once sufficient vulnerabilities have been identified, the blue team then approaches the critical vulnerbilities and makes sure the recommended security measures will be effective after implementation.

Based on the above red team blue team assessment, mitigation strategies are then recommended.

Please refer to the Appendix at the end of this report for additional references and screenshots. These references can be identified as [APDX000]

**Paul Barrett**
**SOC Analyst**
**27th November 2020**





## Network Topology



Network Topology

Network Address Range: 192.168.1.0/24
Netmask: 255.255.255.0
Gateway: 10.0.0.76
Machines IPv4: 19.168.1.1
OS: Windows 10

Hostname: Azure Hyper-V ML-RefVm-684427
IPv4:192.168.1.90
OS: Linux 2.6.32
Hostname: Kali
IPv4: 192.168.1.100
OS: Linux

Hostname: ELK-Stack
IPv4: 192.168.1.105
OS: Linux
Hostname: Capstone
Capstone Analysis




### **Red Team**

Security Assessment


# Recon: Describing the Target

Nmap identified the following hosts on the network:

**Hostname**

**IP Address**

**Role on Network**

Hyper-V Azure machine

ML-RefVm-684427

192.168.1.1

Host Machine

Cloud based

Kali

192.168.1.90

192.168.1.100

192.168.1.105

Attacking Machine

ELK stack

Capstone

Network Monitoring Machine running

Kibana

Target Machine

Replicating a vulnerable server





Vulnerability Assessment

The assessment uncovered the following critical vulnerabilities in the target:

**Vulnerability**

**Description**

**Impact**

Port 80 open with public access

Open and unsecured access to anyone attempting entry using Port 80.

Files and Folders are readily accessible.

Sensitive (and secret) files and folders can be found.

Root accessibility

Authorization to execute and command, and access any resource on the vulnerable device.

Vulnerabilities can be leveraged. Extensive potential Impact to any connected network.

# Simplistic Usernames

First name, short names, or similar information can be easily socially engineered

‘Hannah’, ‘Ryan’ and ‘ashton’ are all predictable names that can be discovered by social engineering. In conjunction with a simple/ weak password, file/folder access can be attained.

# Weak Passwords

Commonly used passwords such as simple words, and the lack of password complexity, such as the inclusion of symbols, numbers and capitals.

System access could be discovered by social engineering.

[https://thycotic.com/resources/password-strength](https://thycotic.com/resources/password-strength-checker/)

[-checker/](https://thycotic.com/resources/password-strength-checker/)[ ](https://thycotic.com/resources/password-strength-checker/)suggests that ‘Leopoldo’ could be cracked in 21 seconds by a computer.





## Vulnerability Assessment

**Vulnerability**

**Description**

**Impact**

# Ability to discover password by Brute force.

When an attacker uses numerous username and password combinations to access a device and/or system.

Easy system access by use of brute force with common password lists such as rockyou.txt by programs such as ‘John the ripper’, Hydra, Medusa, Ophcrack, Brutus and ‘Cain and Able’.

# Hashed Passwords

If a password is not salted it can be cracked via online tools such as [www.crackstation.ne](http://www.crackstation.net/)[t](http://www.crackstation.net/)[ ](http://www.crackstation.net/) or programs such as hashcat.

Once the password is cracked, and if a user name is already known, a hacker can access system files.

# Directory Indexing vulnerability CWE-548

Attacker can view and download content of a directory located on a vulnerable device.

The attacker can gain access to source code, or devise other exploits. The directory listing can compromise private or confidential data.

# LFI Vulnerability

LFI allows access into confidential files on a vulnerable machine.

An LFI vulnerability allows attackers to gain access to sensitive credentials. The attacker can read (and sometimes execute) files on the vulnerable machine.





## Vulnerability Assessment

**Vulnerability**

**Description**

**Impact**

# WebDAV Vulnerability

Exploit WebDAV on a server and Shell access is possible.

If WebDAV is not configured properly, it can allow hackers to remotely modify website content.





# Exploitation: **Brute Force Password**

01

**Tools & Processes**

03

I used Hydra which is already preinstalled on Kali Linux. I also required a password list – in this case I used rockyou.txt

**Command**: $ hydra -l ashton -P /root/Downloads/rockyou.txt -s 80 -f 192.168.1.105 http-get /company_folders/secret_folder

02

**Achievements**

The exploit provided me with confirmation of the login name ‘**ashton**’ as well as the password ‘**leopoldo**’.
User access achieved.





# Exploitation: **Port 80 Open to Public Access**

03

01

**Tools & Processes**

I used nmap to scan for open ports on the target machine.

02

**Achievements**

Nmap scanned 256 IP addresses: I found 4 hosts up:
Port 22 and 80 was of interest to me.





# Exploitation: **Hashed Passwords**

01

02

**Tools & Processes**

**Achievements**

I used the website crackstation.net to crack the hashed password.
The password ‘**linux4u**’ was used in conjunction with username **Ryan** to access the **/webdav** folder.




Exploitation: **LFI vulnerability**

01

02

**Tools & Processes**

**Achievements**

I used msfvenom and meterpreter to deliver a payload onto the vulnerable machine (the capstone server)
Using the **multi/handler** exploit I could get access to the machine’s shell.




### **Blue Team**

## Log Analysis and Attack Characterization


# Analysis: Identifying the Port Scan

● The port scan started on November 17, 2020 at approximately 0900hrs

● 125,219 connections occurred at the peak, the source IP was 192.168.1.90

● The sudden peaks in network traffic indicate that this was a port scan.





Analysis: Finding the Request for a Hidden Directory

● The request started at 0700hrs on 17th November 2020

● 109,843 requests were made to access the **/secret_folder**

● The **/secret_folder** contained a hash that I could use to access the system using another employee’s credentials (Ryan)

● The **/secret_folder** also allowed me to upload a payload, thus exploiting other vulnerabilities.





Analysis: Uncovering a Brute Force Attack

● 109,843 requests were made in the attack to access the **/secret_folder**.

● 30 attacks were successful. 100% of these attacks returned a 301 HTTP status code “Moved Permanently”.





Analysis: Finding the WebDAV Connection

● 96 requests were made to access the **/webdav** directory.

● The primary requests were for the **passwd.dav** and **shell.php** files.





### **Blue Team**

## Proposed Alarms and Mitigation Strategies






## Mitigation: Blocking the Port Scan

Alarm

System Hardening

I recommend an alert be sent once 1000 connections occur in an hour.

● Regularly run a system port scan to proactively detect and audit any open ports.

● Set server iptables to drop packet traffic when thresholds are exceeded

● Ensure the firewall is regularly patched to minimise new zero-day attacks.

● Ensure the firewall detects and cuts off the scan attempt in real time.





## Mitigation: Finding the Request for the Hidden Directory

Alarm

System Hardening

To detect unauthorized accessrequests for hidden folders and files, I would set an alert when these requests occur.

● Highly confidential folders should not be shared for public access

● Rename folders containing sensitive/private/company critical data

● Encrypt data contained within confidential folders

● Review IP addresses that cause an alert to be sent: either whitelist or block the IP addresses.

I would recommend a threshold of maximum 5 attempts per hour that would trigger an alert to be sent.





## Mitigation: Preventing Brute Force Attacks

Alarm

System Hardening

A HTTP 401 Unauthorized client error indicates that the request has ot been applied because it lacks valid authentication credentials for the target resource.

● I would create a policy that locks out accounts for 30 minutes after 5 unsuccessful attempts.

● I would create a password policy that requires password complexity. I would compare the passwords to common password lists, and prevent users from reusing historical passwords.

I would detect future brute force attacks by setting an alarm that alerts if a 401 error is returned.

The threshold I would set to activate this alarm would be when 10 errors are returned.

● I would create a list of blocked IP addresses based on IP addresses that have 30 unsuccessful attempts in 6 months. If the IP address happens to be a staff member, re-education may be required.




## Mitigation: Detecting the WebDAV Connection

Alarm

System Hardening

First, I would create a Whitelist of trusted IP Addresses. Review this list every 6 months: ‘do they really need access?’

● Creating a whitelist of trusted IP addresses and ensure my firewall security policy prevents all other access.

[APDX001] [APDX002]

On **HTTP GET** request, I would set an alarm that activates on any IP address trying to access the webDAV directory outside of those trusted IP addresses.

Assuming my IP address is 192.168.1.1, within Ubuntu I would run the following command:
$ iptables -I INPUT -s **192.168.1.1** -p tcp -m multiport --dports 80,443 -j ACCEPT

● In conjunction with other mitigation strategies, I would ensure that any access to the WebDAV folder is only permitted by users with complex username and passwords.

The threshold I would set to activate this alarm would be when any **HTTP PUT** request is made.





## Mitigation: Identifying Reverse Shell Uploads

Alarm

# System Hardening

I recommend that an alert be set for any traffic attempting to access port 4444. The threshold for the alert to be sent is when one or more attempt is made.

● Block all IP addresses other than whitelisted IP addresses (because reverse shells can be created over DNS, this action will only limit the risk of reverse shell connections, not eliminate the risk)

● Set access to the /webDAV folder to read only to prevent payloads from being uploaded

I recommend setting an alert for any files being uploaded into the /webDAV folder.

The threshold for the alert to be sent is when one or more attempt is made.

● Ensure only necessary ports are open

[APDX003]





### Assessment Summary

# The Red Team uncovered the following vulnerabilities:

● Accessed the system via HTTP Port 80

● Found Root accessibility

# The Blue Team also:

● Confirmed that a port scan occurred

● Found requests for a hidden directory

● Found evidence of a brute force attack

● Found requests to access critical system folders and files

● Found the occurrence of simplistic usernames and weak passwords

● Brute forced passwords to gain system access

● Cracked a hashed password to gain system access and use a shell script

● Identified a WebDAV vulnerability

● Identified a LFI vulnerability

● Identified Directory Indexing vulnerability CWE-548

It is important to note that the above report is not an exhaustive review of the client’s I.T. systems or security policies. I have identified 9 vulnerabilities and provided mitigation strategies for several of them. What I have made clear however is that vulnerabilities can and will always be found. If you are a company executive, you should be constantly asking yourself: How prepared is my company for dealing with a cybersecurity breach?

**Keep this fact in mind: It is not if you will get hacked, it is WHEN you will get hacked.**

**I encourage you to take steps to minimising the impacts of when this occurs.**





### Appendix

The following pages are a list of references and relevant screenshots.

● APDX001

● APDX002

[https://support.stackpath.com/hc/en-](https://support.stackpath.com/hc/en-us/articles/360001074623-How-To-Whitelist-StackPath-IP-Blocks-in-IPTables)

[us/articles/360001074623-How-To-Whitelist](https://support.stackpath.com/hc/en-us/articles/360001074623-How-To-Whitelist-StackPath-IP-Blocks-in-IPTables)[-](https://support.stackpath.com/hc/en-us/articles/360001074623-How-To-Whitelist-StackPath-IP-Blocks-in-IPTables)

[StackPath-IP-Blocks-in-IPTable](https://support.stackpath.com/hc/en-us/articles/360001074623-How-To-Whitelist-StackPath-IP-Blocks-in-IPTables)[s](https://support.stackpath.com/hc/en-us/articles/360001074623-How-To-Whitelist-StackPath-IP-Blocks-in-IPTables)

● APDX003

[http://help.sonicwall.com/help/sw/eng/9530/26/2/3/c](http://help.sonicwall.com/help/sw/eng/9530/26/2/3/content/Application_Control.065.23.htm)

[ontent/Application_Control.065.23.htm](http://help.sonicwall.com/help/sw/eng/9530/26/2/3/content/Application_Control.065.23.htm)


