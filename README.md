### Loader
Target:
-   Persistence
-   Improve trapdoor function:
    -   Create new thread (this thread will handle the payload)
    -   Sleep handler thread
    -   Fix trapdoor (allow jump once)
-   String obfuscation (in rdata, to prevent API detection)
-   Anti VM
-   Fix trapdoor ( anti virus submitted old code, so this one is forced)
-   Reduce entropy in data section.
-   NTDLL unhooking (dont know, could implement if have more time)

-   Add exclusive (loader, notepad) window defender.
-   Add packer
-   Maybe automate process of gain admin priv/ SE_DEBUG (the first time, it will ask for priv, but in the later, those are automate when execute)
-   Indirect syscall / direct syscall without depend on context (hellsgate, halosgate)

Achieved:
-   IAT remove
-   Nirvana debugging
-   Entropy reduce
-   

Some requirement:
-   require admin
-   Have to interact with notepad properly