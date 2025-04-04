## Kayumi

![](/Attachments/kayumi.png)

__Kayumi__ is a customized and optimized Windows agent, it's also intended to be used as a loader/wrapper for any compatible Windows payload.

## Use Case

Kayumi is designed to enhance stealth, persistence, and evasion capabilities while efficiently delivering the C2 payload. It follows these design principles:

- Use multiple techniques update
- Bypass Windows AV/EDR as much as possible
- Keep the binary size acceptable 
- Work with many versions of Windows without any framework requirements

It combines multiple anti-detection techniques to bypass security solutions and ensure stable execution in compromised environments.

Kayumi is suitable as an agent for Stage 1 in Red Team Operation. (For education only).

## Installation

### Manual:

- First, you need to place your payload in `src/Scripts` then run the remove-entropy script (example: payload-raw.bin) using python:
   ```
   python remove-entropy.py payload-raw.bin payload.bin
   ```
  The payload with removed entropy is written to `payload.bin`
- Next, compile the agent using Visual Studio (`loader` project) as a release binary.
- Finally, Run the string obfuscator on the release binary:
  ```
  StringObfuscator.exe loader.exe
  ```

The final binary can now be used.

### Testing result

Kayumi has been tested with Havoc Agent, which reduced the detection rate:

The results (tested on 11/01/2025) on VirusTotal are shown below:

![](/Attachments/virustotal_result.png)

We've also tested with some AVs on the newest version of Windows 11 (24H2), with default settings and Firewall on. We fully received connections from the agent:

- Trend Micro (Bypassed, Undetected)
- Symantec (Bypassed, Undetected)
- McAfee (Bypassed, Undetected)

### Automation
- (Update later)

## Implemented techniques  

- **String Obfuscation**: Obfuscates function names (`.fname`) to prevent API-based detection.  
- **Anti-VirtualVM Detection**: Currently disabled for testing but can be re-enabled to detect sandboxed environments.  
- **Anti-Debugging**: Implements multiple anti-debugging techniques to detect and prevent analysis through debuggers.
- **Indirect & Direct Syscalls (Hell’s Gate / Halo’s Gate)**: Evades user-mode hooks by dynamically resolving and executing syscalls directly in kernel mode.  
- **IAT Reduction**: Strips unnecessary imports and removes suspicious API calls (`VirtualAllocEx`, `WriteProcessMemory`, etc.) to minimize detection.
- **Nirvana Debugging**: Creates a hook on callback function that will execute our payload when the callback is called.
- **Entropy Reduction**: Lowers entropy in the `.data` section to avoid heuristic-based detections.

## Execution Flow

**Automated Privilege Escalation**: Initially prompts for administrative privileges but automates privilege escalation (`SeDebugPrivilege`) in subsequent executions.  

**Trapdoor Function Enhancements**:  
  - Creates a dedicated execution thread to handle the payload.  
  - Implements a **sleep-based handler** to delay execution and evade sandbox analysis.  
  - Fixes trapdoor behavior to ensure controlled single execution before payload injection.  

For more information, check the execution flow shown below:

![](/Attachments/loader_flow.png)


## Planned Features

- **Persistence Mechanisms**: Ensures long-term access by surviving reboots.  
- **Defender Evasion via Window Cloaking**: Uses an exclusive loader window (e.g., Notepad.exe) to evade Windows Defender detection.  
- **Packer Integration**: Additional obfuscation and compression for improved stealth.  

## Requirements  
**Administrator Privileges Required** for privilege escalation and advanced process injection techniques.