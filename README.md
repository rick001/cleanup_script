# CloudPanel System Cleanup Script

This script is designed to help clean systems using CloudPanel as the hosting control panel, which may have been compromised due to a zero-day vulnerability in CloudPanel versions below 2.3.1. The script includes several functions to detect and remove suspicious files, terminate malicious processes, and perform system-wide scans for malware using the ClamAV antivirus.

## Prerequisites

- This script is intended for use on systems running Ubuntu or Debian-based distributions.
- Ensure that you have administrative privileges to execute the necessary commands using `sudo`.
- The system should have ClamAV installed for malware scanning. If not present, the script will attempt to install it.

## Usage

1. Clone this repository and navigate to the script directory:
   ```
   git clone https://github.com/rick001/cleanup_script.git
   cd cleanup_script
   ```

2. Make the script executable (if needed):
   ```
   chmod +x cleanup_script.sh
   ```

3. Execute the script as follows:
   ```
   ./cleanup_script.sh
   ```

## Script Overview

The script performs the following actions:

1. **clp-update**: It runs `clp-update` to update the CloudPanel control panel.

2. **Delete User**: The script lists all system users and their home directories. It provides an option to delete selected users, with highlighting for users having their home directory in `/tmp`, which might be suspicious.

3. **Remove Attacker's SSH Public Key**: The script checks for and removes the attacker's SSH public key from the `authorized_keys` file of the root user and other users' `authorized_keys` files.

4. **Webshell Detection**: The script clones the [Webshell-Detect](https://github.com/rick001/Webshell-Detect) repository, checks if Python 3 is installed, runs a comprehensive system scan for web shells, and prompts the user to delete detected files and terminate associated processes.

5. **Remove Bad Files**: It terminates processes associated with suspicious filenames like `isbdd`, `ispdd`, and `dotnet.x86` and removes these files from `/tmp` if found. Additionally, it checks for suspicious ELF binaries in `/tmp` and `/home/clp/htdocs/` and provides the option to delete them.

6. **Install Freshclam and Run Scan**: The script installs `freshclam` (if not already installed) and performs a system-wide scan using `clamscan` if the user chooses to do so.

7. **Delete Infected Files**: If infected files are detected during the scan, the script provides an option to delete them.

8. **Remove Cron Jobs**: The script removes cron jobs containing "/tmp" for the user "clp".

## Important Notes

- The script is provided as-is and should be used with caution. Understand the actions performed by the script before execution.
- Please take a backup of critical data before running the cleanup script.
- While the script attempts to remove suspicious files and terminate malicious processes, it may not cover all possible attack vectors.
- It's recommended to update to the latest version of CloudPanel (v2.3.1 or above) to mitigate known vulnerabilities.

## Disclaimer

The authors of this script are not liable for any damages caused by the use of this script. Use it at your own risk and responsibility. Always verify the actions performed by the script before execution. If you are unsure about any step, seek advice from a qualified system administrator or security professional.

**Please note:** This script might not cover all scenarios or protect against all types of attacks. It's essential to keep your system and software up-to-date and follow security best practices to ensure a secure hosting environment.
