# Microsoft Sentinel Detection Lab

A hands-on SOC lab built in Microsoft Azure: a Windows Server VM sends its security logs to Microsoft Sentinel, I simulate attacks against it, and I write my own KQL detection rules for what shows up.

The goal is to practise detection engineering on a real Sentinel workspace, beyond the SC-200 theory. It runs on the Azure free account ($200 credit, 30 days) and the 31-day Sentinel free trial.

## Series

| Part | Topic | Status | Article |
| --- | --- | --- | --- |
| 1 | Build the lab and verify that logs arrive | Done | [Read on Medium](https://medium.com/@ed.cavaillez/microsoft-sentinel-detection-lab-part-e6213cac3e75?sharedUserId=ed.cavaillez) |
| 2 | First detection: RDP brute-force rule | Planned | Coming Soon |
| 3 | Simulating attacks with Atomic Red Team and mapping to MITRE ATT&CK | Planned | |
| 4 | Investigating an incident, costs and clean-up | Planned | |

## Architecture

Windows Server VM > Azure Monitor Agent > Log Analytics workspace > Microsoft Sentinel

| Component | Name |
| --- | --- |
| Resource group | rg-sentinel-lab |
| Log Analytics workspace | law-sentinel-lab |
| Windows Server VM | vm-win-lab |
| Sentinel content | Windows Security Events solution (AMA connector) |

## Stack

Microsoft Azure, Microsoft Sentinel, Microsoft Defender portal, KQL, Atomic Red Team (planned).

