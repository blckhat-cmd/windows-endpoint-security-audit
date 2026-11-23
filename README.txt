HOW TO RUN
1. Extract this ZIP first (right-click > Extract All). Do not run from inside the ZIP.
2. Double-click Run_EndpointCheck.bat
3. Click Yes on the Administrator (UAC) box.
4. Wait 5 to 10 minutes. Do not close the window.
5. The PDF report is saved in the same folder.

IF THE BAT DOES NOT WORK:
Open Windows PowerShell as Administrator and type:
  cd "folder where you extracted the files"
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\EndpointCheck.ps1

OPTIONAL SETTINGS (top of EndpointCheck.ps1, open in Notepad):
  ApprovedAdmins, ApprovedSoftware, ApprovedShares, ApprovedRemoteTools = names the client approved (they will not be marked BAD)
  RequireUsbBlocked = $false if the client allows USB storage
  ProxyAllowed = $true if the client uses a proxy server
  CheckOnline = $false to skip the 2 checks that need internet
  ClientName = optional. Empty = the report cover shows only the PC's IP address as Client
  PreparedBy = company/your name shown on the cover, page header and footer (default: 'Your Company Name')
  ShowLogo = $true to show the company logo on the cover (default off, like the model report)
  DevicePrefix = issue ID prefix (example MRT gives MRT-01). Empty = made from the computer name

This script checks the inside of the PC only (65 checks).
Network scans (Nmap, OpenVAS, ZAP) are done separately.
The company logo is inside the script. To use another logo, put a file named logo.png next to the script.
The report lists every issue as Critical, High, Medium or Low, each with its proof (PoC). GOOD checks are not shown.
Checks the script cannot prove are listed as NOT CHECKED, not as issues.
The script only reads information. It changes no Windows setting.
