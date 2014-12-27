# FileDisk

## What Did I Make?

I wrote a disk encryption utility on Windows x86 platform with on-the-fly encryption, based on the open source project “File Disk”.

The utility can create and mount image files as virtual encrypted drives, which includes two components: a CLI control program and a file system filter driver. The control program basically takes responsibility to initialize the environment and communicate with the filter driver. Then the driver will create the virtual drives, redirect the I/O stream and encrypt or decrypt the bytes automatically.

I made it in a hurry, so the control program could not process nonstandard inputs and the strength of encryption algorithm was as low as a XOR algorithm. However, in my codes, I provided a good framework, so the algorithm can be upgraded after altering a few lines.

Installation of the utility includes three steps: 
```
  1. Import the driver configuration file “Filedisk.reg” into the registry.
  2. Copy “Filedisk.sys” to %windir%\system32\drivers\.
  3. Reboot.
```

Currently the filter driver does not have digital signature, so it cannot work without disabling driver signature enforcement. The stability and compatibility of the utility are uncertain. Thus, it is recommended to be tested in virtual machines.

## How Did I Make?

First of all,the utility was compiled and debugged with Windows 7+Visual Studio 2012.

I started from reading the codes of the original control program,because its functions were familiar to me.Then I got stuck in reading the driver's codes.I had not learned it before,and those blogs and posts about File Disk were either useless fragments,or sophisticate essays requiring lots of background knowledge.The deadline was January 1st,2015.I only had about ten days so that I did not have enough time to study the whole knowledge system about how to develop kernel drivers.

Finally I just read some concepts from books,and then tried to read the codes.After I got a rough blueprint of it in my mind,I realized that sending passwords should be in the same way as sending image file paths.

I made a control program adding a '\0' at the end of the path,and then using pointer to write password after the '\0'.All the original codes processed the path well,and the driver got the password by pointer as well.

The next key point was encryption.The driver processed data in uncertain length,so I wrote an algorithm that could encrypt data byte by byte and I did some unit tests.After this, the utility was able to work with a few bugs.The references about the bugs and solutions are written below.

```
Unable to format the drive.(http://bbs.csdn.net/topics/360037128)
Error 6: The handle is invalid.(http://stackoverflow.com/questions/20304026/error-starting-windows-driver-the-handle-is-invalid)
```

## Why Did I Make?

The thought to write a disk encryption utility first came to my mind while I finished writing my first encryption algorithm which emulated the rotation of Rubik’s cube. I was seeking for more potential methods to utilize my algorithm, and considered not only disk encryption utility, but also online chat tool, text editor, etc.
However, with limited time and ability, at the end I only made an editor.

Few years later, while I knew that I could submit some projects for my application, I recalled this thought and decided to finish it. Dramatically, the “Rubik’s algorithm” can only encrypt data group by group, because it needs to fulfill a cube with certain edge length. Therefore my original dream had somehow failed as I mentioned in the previous section. Then I wrote a new algorithm for disk encryption.

All the reasons written above are the direct ones for doing this project, but, I think that the thought basically came from the fear of privacy leak. Currently, not criminals, but governments and international companies are exploiting the value of users’ data. It is hard to diagnose the backdoor or vulnerabilities in those close source encryption software, but I have ability to develop an open source one for every one on this Internet. So I took my step, and it made me feel pretty good. In the future I will keep upgrading it and ask my friends on GitHub for support.
