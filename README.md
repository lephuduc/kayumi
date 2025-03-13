### Kayuumi

#### Overview  
This loader is designed to enhance stealth, persistence, and evasion capabilities while efficiently delivering the C2 payload. It incorporates multiple anti-detection techniques to bypass security solutions and ensure stable execution in compromised environments.  

#### Evasion & Anti-Detection Techniques  
- **String Obfuscation**:  
  - Obfuscates function names (`.fname`) to prevent API-based detection.  
- **Anti-Virtual Machine (VM) Detection**:  
  - Currently disabled for testing but can be re-enabled to detect sandboxed environments.  
- **Anti-Debugging**:  
  - Implements multiple anti-debugging techniques to detect and prevent analysis through debuggers (e.g., x64dbg, OllyDbg, WinDbg).  
- **Indirect & Direct Syscalls (Hell’s Gate / Halo’s Gate)**:  
  - Evades user-mode hooks by dynamically resolving and executing syscalls directly in kernel mode.  
- **Import Address Table (IAT) Reduction**:  
  - Strips unnecessary imports and removes suspicious API calls (`VirtualAllocEx`, `WriteProcessMemory`, etc.) to minimize detection.  
- **Nirvana Debugging**:  
  - Prevents debuggers and security tools from attaching to the process in real time.  
- **Entropy Reduction**:  
  - Lowers entropy in the `.data` section to avoid heuristic-based detections.  

#### Execution Flow & Process Injection  
- **Automated Privilege Escalation**:  
  - Initially prompts for administrative privileges but automates privilege escalation (`SeDebugPrivilege`) in subsequent executions.  
- **Trapdoor Function Enhancements**:  
  - Creates a dedicated execution thread to handle the payload.  
  - Implements a **sleep-based handler** to delay execution and evade sandbox analysis.  
  - Fixes trapdoor behavior to ensure controlled single execution before payload injection.  

#### Planned Features (To Be Implemented)  
- **Persistence Mechanisms**:  
  - Ensures long-term access by surviving reboots.  
- **Defender Evasion via Window Cloaking**:  
  - Uses an exclusive loader window (e.g., Notepad.exe) to evade Windows Defender detection.  
- **Packer Integration**:  
  - Additional obfuscation and compression for improved stealth.  

#### Requirements  
- **Administrator Privileges Required** for privilege escalation and advanced process injection techniques.  

This loader is optimized for **Havoc C2**, providing a stealthy, resilient, and efficient delivery mechanism for payload execution. 🚀  
