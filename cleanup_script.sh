#!/bin/bash

# Function to check if freshclam is installed and install it if not
install_freshclam() {
  if ! command -v freshclam &>/dev/null; then
    sudo apt update
    sudo apt install clamav
  fi
}

# Function to run freshclam and scan all files
run_scan() {
  echo "Do you want to run a system-wide scan?"
  echo "Enter 'Y' to run a system-wide scan or 'N' to skip the scan:"
  read -r run_scan_option

  if [ "$run_scan_option" = "Y" ] || [ "$run_scan_option" = "y" ]; then
    echo "Scanning the system for malware. Please wait..."
    # Run a scan on all files and store the result in a variable
    scan_result=$(sudo clamscan -r /)
  else
    echo "Skipping the scan."
  fi
}

# Function to delete infected files if user confirms
delete_infected_files() {
  # Check if there are any infected files
  if echo "$scan_result" | grep -q "Infected files: "; then
    # Extract the list of infected files using grep and awk
    infected_files=$(echo "$scan_result" | grep "Infected files: " | awk '{print $3}')
    # Print the list of infected files for user confirmation
    echo "Infected files found:"
    echo "$infected_files"
    echo
    # Ask for user confirmation to delete the infected files
    read -p "Do you want to delete the infected files? (y/n): " confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
      # Loop through the infected files and delete them
      for file in $infected_files; do
        sudo rm -f "$file"
        echo "Deleted: $file"
      done
    else
      echo "No files deleted."
    fi
  else
    echo "No infected files found."
  fi
}

# Function to check for suspicious ELF binaries in /tmp and /home/
check_suspicious_elf_files() {
  # Find all ELF binaries in /tmp and /home/
  suspicious_files=$(find /tmp /home -type f -exec file {} + | grep 'ELF' | cut -d: -f1)

  # Check if any suspicious files were found
  if [ -n "$suspicious_files" ]; then
    # Print the list of suspicious files for user confirmation
    echo "Suspicious ELF binaries found in /tmp and /home/:"
    echo "$suspicious_files"
    echo
    # Ask for user confirmation to delete the suspicious files
    read -p "Do you want to delete the suspicious files? (y/n): " confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
      # Loop through the suspicious files, terminate related processes, and delete them
      for file in $suspicious_files; do
        # Terminate processes associated with the suspicious file
        sudo pkill -f "$file"
        # Delete the suspicious file
        sudo rm -f "$file"
        echo "Deleted: $file"
      done
    else
      echo "No files deleted."
    fi
  else
    echo "No suspicious ELF binaries found in /tmp and /home/."
  fi
}

# Function to delete user with highlighting for users having home directory in /tmp
delete_user() {
  # List all system users and their home directories
  local suspicious_users=$(awk -F':' '$3 >= 1000 && $6 ~ /^\/tmp\// && $1 != "clp" {print $1}' /etc/passwd)
  
  if [ -z "$suspicious_users" ]; then
    echo "Listing all system users..."
    echo "-----------------------------------------"
    awk -F':' '{if ($3 >= 1000 && $1 != "clp") {printf "\033[1m%-20s\033[0m:%s\n", $1, $6} else if ($1 != "clp") {printf "%-20s:%s\n", $1, $6}}' /etc/passwd
    echo "-----------------------------------------"
    echo "No suspicious users found with their home directory in /tmp."
  else
    echo "Listing all system users..."
    echo "-----------------------------------------"
    awk -F':' -v sus_users="$suspicious_users" 'BEGIN {split(sus_users, users, " ")} {if ($3 >= 1000 && $1 != "clp") {if ($1 in users) printf "\033[1m%-20s\033[0m:%s\n", $1, $6; else printf "%-20s:%s\n", $1, $6}}' /etc/passwd
    echo "-----------------------------------------"
  fi
  
  local usernames=()
  while true; do
    read -p "Enter a username to delete or press ENTER to continue: " input_username
    if [ -z "$input_username" ]; then
      break
    fi
    usernames+=("$input_username")
  done

  # Process each entered username
  for username in "${usernames[@]}"; do
    # Check if the user exists and if the home directory is in /tmp
    if [ -n "$username" ]; then
      if id "$username" &>/dev/null; then
        user_home=$(awk -F':' -v user="$username" '$1 == user {print $6}' /etc/passwd)
        if [ "$user_home" = "/tmp" ]; then
          echo -e "\033[1mUser '$username' is a suspicious user with their home directory in /tmp.\033[0m"
        fi
        # Prompt for user confirmation before deleting
        read -p "Do you want to delete the user '$username'? (y/n): " confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
          sudo userdel "$username"
          echo "User '$username' has been deleted."
        else
          echo "User deletion canceled."
        fi
      else
        echo "User '$username' not found."
      fi
    else
      echo "User deletion skipped."
    fi
  done
}

# Function to remove bad files and suspicious web shell files from /tmp/ and /home/clp/htdocs/app/files/public/ directories
remove_bad_files() {
  echo "Checking for and terminating processes using 'isbdd', 'ispdd', and 'dotnet.x86'..."
  # Terminating processes associated with filenames (even if files are not present)
  sudo pkill -f '/tmp/isbdd'
  sudo pkill -f '/tmp/ispdd'
  sudo pkill -f '/tmp/dotnet.x86'

  # Remove the files if they exist
  if [ -e "/tmp/isbdd" ]; then
    sudo rm -f "/tmp/isbdd"
    echo "Removed: /tmp/isbdd"
  fi
  if [ -e "/tmp/ispdd" ]; then
    sudo rm -f "/tmp/ispdd"
    echo "Removed: /tmp/ispdd"
  fi
  if [ -e "/tmp/dotnet.x86" ]; then
    sudo rm -f "/tmp/dotnet.x86"
    echo "Removed: /tmp/dotnet.x86"
  fi

  echo "Files 'isbdd', 'ispdd', and 'dotnet.x86' have been removed from /tmp (if found)."
  
  echo "Checking for suspicious ELF binaries in /tmp and /home/clp/htdocs/ please be patient."
  # Check for suspicious ELF binaries in /tmp and /home/clp/htdocs/ and ask for user confirmation to delete
  check_suspicious_elf_files

  # Detect and remove suspicious web shell files
  echo "Checking for and removing suspicious web shell files in /home/clp/htdocs/app/files/public/..."
  if sudo find /home/clp/htdocs/app/files/public/ -type f \( -name 'shell.php' -o -name 'mget.php' -o -name 'test.php' \) -print -exec rm -f {} \; ; then
    echo "Suspicious web shell files (shell.php, mget.php, test.php, etc.) have been removed (if found)."
  else
    echo "No suspicious web shell files found in /home/clp/htdocs/app/files/public/."
  fi

  # Terminating processes associated with suspicious web shell filenames (even if files are not present)
  sudo pkill -f 'shell.php'
  sudo pkill -f 'mget.php'
  sudo pkill -f 'test.php'
  # Add more filenames as needed
  echo "Processes associated with suspicious web shell filenames have been terminated (if found)."
}

# Function to remove the attacker's SSH public key from authorized_keys
remove_attacker_public_key() {
  # Check if the attacker's public key exists in the root user's authorized_keys file
  echo "Checking for the attacker's SSH public key in the root user's authorized_keys file..."
  if [ -f "/root/.ssh/authorized_keys" ]; then
    if grep -q "admin@test.com" "/root/.ssh/authorized_keys"; then
      echo "Attacker's SSH public key found in the authorized_keys file of the root user."
      # Remove the line containing the attacker's public key from the root user's authorized_keys file
      sudo sed -i '/admin@test\.com/d' "/root/.ssh/authorized_keys"
      echo "Attacker's SSH public key has been removed from the authorized_keys file of the root user."
    fi
  fi

  # Check if the attacker's public key exists in any other user's authorized_keys file
  echo "Checking for the attacker's SSH public key in other users' authorized_keys files..."
  while read -r username; do
    if [ "$username" != "root" ] && [ -f "/home/$username/.ssh/authorized_keys" ]; then
      if grep -q "admin@test.com" "/home/$username/.ssh/authorized_keys"; then
        echo "Attacker's SSH public key found in the authorized_keys file of user '$username'."
        # Remove the line containing the attacker's public key from other users' authorized_keys files
        sudo sed -i '/admin@test\.com/d' "/home/$username/.ssh/authorized_keys"
        echo "Attacker's SSH public key has been removed from the authorized_keys file of user '$username'."
      fi
    fi
  done < <(cut -d: -f1 /etc/passwd | grep -v '^#' | grep -v '^$')
}

# Function to run clp-update
run_clp_update() {
  echo "Running clp-update..."
  sudo clp-update
  echo "clp-update has been executed."
}

# Function to remove cron jobs containing "/tmp" for user "clp"
remove_cron_jobs() {
  if crontab -u clp -l | grep -q "/tmp[[:space:]]\+\S\+"; then
    echo "Removing cron jobs containing '/tmp' for user 'clp'..."
    (crontab -u clp -l | grep -v "/tmp[[:space:]]\+\S\+") | crontab -u clp -
    echo "Cron jobs containing '/tmp' for user 'clp' have been removed."
  else
    echo "No cron jobs containing '/tmp' found for user 'clp'."
  fi
}

webshell_detection() {
  # Step 1: Clone the repository
git clone https://github.com/rick001/Webshell-Detect.git
cd Webshell-Detect

# Step 2: Check if python3 is installed
if ! command -v python3 &> /dev/null; then
    # Step 3: Install python3 if it's not installed
    sudo apt update
    sudo apt install -y python3
fi

# Step 4: Run the python script
echo "Initiating a comprehensive system scan. This process may take some time, so we kindly request your patience and understanding."
python3 webshell_detect.py

# Step 5: Read the generated csv file and print the detected files
csv_file="webshell_detection_results.csv"
if [ -f "$csv_file" ]; then
    echo "Detected Webshells:"

    # Read the CSV file line by line and prompt the user for each file
    tail -n +2 "$csv_file" | cut -d',' -f1 | while IFS= read -r file; do
        if [[ -z "${file// }" ]]; then
            continue
        fi

        echo "Found file: $file"
        echo "Do you want to delete and kill processes for this file? (y/n)"
        read -r response < /dev/tty
        if [[ $response =~ ^[Yy]$ ]]; then
            if [ -f "$file" ]; then
                # Delete the file if it exists
                rm "$file"
                echo "Deleted: $file"
            fi

            # Check if a process with the same name is running and terminate it
            process_name=$(basename "$file")
            pids=$(pgrep -f "$process_name")
            if [ -n "$pids" ]; then
                echo "Processes running for $file:"
                ps -p $pids
                echo "Do you want to terminate these processes? (y/n)"
                read -r kill_response < /dev/tty
                if [[ $kill_response =~ ^[Yy]$ ]]; then
                    kill $pids
                    echo "Terminated processes for $file"
                fi
            else
                echo "No running processes found for $file"
            fi
        fi
    done
else
    echo "No Webshell detected."
fi
}

# Main script execution starts here

# Run clp-update
run_clp_update

# Delete users including 'dotsh' based on user input
delete_user

# Remove the attacker's SSH public key from authorized_keys
remove_attacker_public_key

#Detect and remove WebShells
webshell_detection

# Navigate to /tmp/ directory and remove bad files 'isbdd', 'ispdd', and 'dotnet.x86' if found
remove_bad_files

# Install freshclam if not already installed
install_freshclam

# Run freshclam to update virus definitions and perform the scan
run_scan

# Delete infected files if found
delete_infected_files

# Remove cron jobs containing "/tmp" for user "clp"
remove_cron_jobs

echo "Cleanup script execution complete."
