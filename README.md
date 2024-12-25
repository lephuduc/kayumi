### Loader
Target:
[ ] Persistence

[ ] String obfuscation (in rdata, to prevent API detection)
[ ] Anti VM
[ ] Reduce entropy in data section.
[ ] Add exclusive (loader, notepad) window defender.
[ ] Add packer
[ ] Maybe automate process of gain admin priv/ SE_DEBUG (the first time, it will ask for priv, but in the later, those are automate when execute)
[x] Indirect syscall / direct syscall without depend on context (hellsgate, halosgate)
[ ] IAT remove
[x] Nirvana debugging
[ ] Entropy reduce
[x] Improve trapdoor function:
    [x] Create new thread (this thread will handle the payload)
    [x] Sleep handler thread
    [x] Fix trapdoor (allow jump once)

Achieved:

Some requirement:
-   require admin