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


Achieved:
-   IAT remove
-   Nirvana debugging
-   Entropy reduce
-   

Some requirement:
-   require admin
-   Have to interact with notepad properly