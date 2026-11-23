# Windows Endpoint Security Audit Tool

A read-only PowerShell tool that runs 65 security checks across 12 areas on a
Windows PC and generates a professional PDF/HTML report (Critical/High/Medium/Low
findings, each with proof).

> The script only reads information. It changes no Windows setting.

## What it checks
Local admin accounts, password policy, BitLocker, firewall, Defender status,
UAC, stored credentials, persistence mechanisms (IFEO, AppInit, Winlogon),
USB storage policy, remote access tools, shares, event log health, and more.

## Usage
1. Download and extract the files (don't run from inside the ZIP).
2. Double-click `Run_EndpointCheck.bat`, approve the Administrator (UAC) prompt.
3. Wait 5-10 minutes. A PDF + HTML report is saved in the same folder.

## Customize
Edit the settings block at the top of `EndpointCheck.ps1`:
`PreparedBy`, `ClientName`, `ApprovedAdmins`, `RequireUsbBlocked`, etc.

## Sample report
See [sample-report/Sample_Report_Redacted.pdf](sample-report/Sample_Report_Redacted.pdf)
for a redacted example (25 findings across BitLocker, firewall, remote access
tools, outdated software, and more).

Author: Harshad M | Junior Cyber Security Analyst
