# Splunk Incident Handling Investigation

## Scenario Overview

In this exercise, we will investigate a cyber attack in which an attacker successfully defaced an organization's website.

The organization, **Wayne Enterprises**, uses **Splunk** as its Security Information and Event Management (**SIEM**) solution. Our role as a **Security Analyst** is to investigate the attack, identify the attacker's activities, determine the root cause, and map the observed activity to all seven phases of the **Cyber Kill Chain**.

It is important to note that the investigation does not need to follow the Cyber Kill Chain phases in chronological order. Evidence discovered during one phase may lead to findings associated with another phase.

---

## Cyber Kill Chain

During this investigation, we will map the attacker's activity to the seven phases of the Cyber Kill Chain:

1. **Reconnaissance**
2. **Weaponization**
3. **Delivery**
4. **Exploitation**
5. **Installation**
6. **Command & Control**
7. **Actions on Objectives**

Where required, we may also use **Open Source Intelligence (OSINT)** and other supporting evidence to fill gaps in the attack chain.

---

## Incident Scenario

A large corporate organization, **Wayne Enterprises**, recently suffered a cyber attack.

The attackers successfully gained access to the organization's network, reached the web server, and defaced the company website:

`http://www.imreallynotbatman.com`

The compromised website displayed the attacker's message:

> **YOUR SITE HAS BEEN DEFACED**

Wayne Enterprises has requested assistance from the Security Operations team to investigate the incident and determine:

- How the attacker gained access to the network
- Which systems and services were targeted
- What actions the attacker performed
- How the attacker moved through the environment
- The root cause of the compromise
- How the observed activity maps to the Cyber Kill Chain

This investigation falls under the **Detection and Analysis** phase of incident response.

---

## Splunk

For this investigation, **Splunk** will be used as the SIEM platform.

Wayne Enterprises has multiple security and system log sources being ingested into Splunk, including:

- Web server logs
- Firewall logs
- Suricata IDS/IPS logs
- Sysmon logs
- Other network and host-based telemetry

These data sources provide visibility into both **network-centric** and **host-centric** activity.

To understand which hosts and log sources are being monitored in the Wayne Enterprises environment, use the **Data Summary** section in Splunk and review the available tabs.

The collected logs will be used throughout the investigation to reconstruct the attacker's activity and map the evidence to the relevant Cyber Kill Chain phases.
