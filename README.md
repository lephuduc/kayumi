### Loader
-   Target:
    -   [ ] Persistence
    -   [x] String obfuscation (in .fname, to prevent API detection)
    -   [x] Anti VM (can be add later, current remove for testing on VM)
    -   [x] Anti debugging
    -   [x] Reduce entropy in data section.
    -   [ ] Add exclusive (loader, notepad) window defender.
    -   [ ] Add packer
    -   [x] Maybe automate process of gain admin priv/ SE_DEBUG (the first time, it will ask for priv, but in the - later, those are automate when execute)
    -   [x] Indirect syscall / direct syscall without depend on context (hellsgate, halosgate)
    -   [x] IAT remove (not completely, but remove some sussy API such as VirtualAllocEx, WriteProcessMemory, ...)
    -   [x] Nirvana debugging
    -   [x] Entropy reduce
    -   [x] Improve trapdoor function:
        -   [x] Create new thread (this thread will handle the payload)
        -   [x] Sleep handler thread
        -   [x] Fix trapdoor (allow jump once)

-   Some requirement:
    -   require admin