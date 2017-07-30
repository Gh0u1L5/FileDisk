# FileDisk
FileDisk is a virtual disk utility on Windows x86 platform with on-the-fly encryption. This project includes two components: a CLI control program and a filter driver.

I wrote the project in a rush, so the cryptography algorithm is just XOR, but you can easily replace it with your own algorithm.

## Installation
1. Import the driver configuration file “filedisk.reg” into the registry.
2. Copy “Filedisk.sys” to %windir%\system32\drivers\
3. Reboot and enjoy!

__NOTE__: Currently the filter driver doesn't have digital signature, so it cannot work without disabling driver signature enforcement.

## Credits
Thanks to Bo Brantén for the drivers on https://www.acc.umu.se/~bosse/.
