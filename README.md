#  CVE-2018-??? - CA Dollar Universe 5.3.3 'uxdqmsrv' - Privilege escalation via a vulnerable setuid binary 

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/ca-dollaru-uxdqmsrv-privesc.gif">
</p>

## Executive summary
A vulnerability was discovered in the _uxdqmsrv_ binary. It consists in an arbitrary file write as root that can be leveraged by any local user to gain full root privileges on the host (UNIX/Linux only).

Indeed, the program tries to write to a log file that can be specified using the _U_LOG_FILE_ environment variable. When _uxdqmsrv_ is owned by root and the _setuid_ bit is set (default setup), this file will be created with root privileges if it doesn't exist. Using a UNIX/Linux feature called _umask_, a local user can also control the permissions of the created file and make it world-writable, thus controlling the content of the file.

## Vulnerability analysis
On a default UNIX/Linux setup, the binary "uxdqmsrv" is owned by root and is configured with the _setuid_ bit. In other words, when executed by a user other than root, the system will set the EUID to zero so that it can execute code as root.

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/01_file-permissions.png">
</p>

When the program is executed without any arguments, two error messages are displayed. Apparently, it tries to open two files, which cannot be found if the appropriate options are not set.

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/02_error-missing-file.png">
</p>

The _file_ and _ldd_ commands will give some basic information about the file. Here, we notice two things:
- Although the host is running on a 64-bit OS, the file is a 32-bit executable.
- The file is not _stripped_, i.e. it was compiled with debugging information. This may ease the reverse engineering process.

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/03_file-info.png">
</p>

Using IDA, we will try to identify the code responsible for the two error messages.
First, we list all the strings that are present in the binary and search for _U_LOG_FILE_. This string is located in the _.rodata_ section at the address 0x0806A8FF. Then, we can list all the references to this address (using _Xrefs to_). In the present case, there is only one reference, so we jump directly to this one.

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/04_ida-string-ref.png">
</p>

The string _U_LOG_FILE_ is indeed used in the instruction at the address 0x08061BCC (_.text_ section).

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/05_ida-getenv-call.png">
</p>

A pointer to this string is loaded into EAX. Then the content of the register is pushed onto the stack and finally 'getenv()' is called. This is equivalent to the following C code:

```c
getenv("U_LOG_FILE");
```

This means that the second error message is somehow related to a missing environment variable. So, without further investigation, we can try to set this environment variable and observe the behavior of the program.

As it seems a file is expected, we can try to set the value of the _U_LOG_FILE_ variable to a dummy file path. After executing the program, we notice that the second error message has now disappeared.

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/06_env-var-and-run.png">
</p>

Using _ls_, we can see that the file _foo123.log_ was created and is owned by root, which means that the program created it without dropping the privileges. However, it can only be modified by root, so we get a _Permission denied_ error message if we try to write to it.

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/07_permission-denied.png">
</p>

To work around this issue, we can take advantage of a UNIX/Linux feature, which is called _umask_. _umask_ is used to set the default permissions of newly created files. On the screenshot below, we can see that the current _umask_ is set to _022_, i.e. new files are created with _rw-r--r--_ permissions (and new folders are created with _rwxr-xr-x_ permissions).

Therefore, if we set the current _umask_ to _0111_ (or _0000_, which yields the same result for files), we could theoretically control the permissions of the new file by setting them to _rw-rw-rw-_, unless the program sets its own _umask_.

To do so, we use the command _umask 111_ (or _umask 000_) and then repeat the previous steps.

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/08_using-umask.png">
</p>

This time, the file is still owned by root but the permissions are set to “rw-rw-rw-“, which means that we can now modify it.
This arbitrary file creation as root can be used as a primitive to gain full root privileges on the host. This will be explained in the next section.

## Exploit development

When an arbitrary file creation vulnerability is found in a _setuid_ binary, a common trick to gain full root privileges is to take advantage of another UNIX/Linux feature: shared object preloading.

Shared object preloading can be used to specify libraries that will be loaded by a program before any other library. This can be achieved in two ways: either by setting the _LD_PRELOAD_ environment variable or by using the _/etc/ld.so.preload_ file, which requires root privileges.

According to the manual, _/etc/ld.so.preload_ is a file containing a whitespace-separated list of ELF shared objects to be loaded before the program. Unlike _LD_PRELOAD_, shared objects listed in _/etc/ld.so.preload_ are loaded even if the program has the _setuid_ bit.

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/09_man-ld-so-preload.png">
</p>

The exploit will consist in using the vulnerable binary to create the _/etc/ld.so.preload_ file and using _umask_ to make it writable by everyone. This way, we will be able to reference a custom library that will be loaded by any program. Especially, we will use an arbitrary built-in _setuid_ binary to trigger the execution of some malicious code as root.

As a summary, the following steps will be implemented in the final exploit:

### 1) Create a _root shell_ binary
- It must invoke setuid(0) and setgid(0) to be able to impersonate root.
- It will then call system('/bin/sh') to get a shell as root.

### 2) Create a custom shared object
- We will overwrite the function geteuid() (for example).
- The malicious code will set the owner of the _root shell_ binary to root, set the _setuid_ bit and finally return the result of the legitimate geteuid() function.
- The execution of the code will be triggered by a call to _/usr/bin/sudo_ (which is also a _setuid_ binary owned by root).

### 3) Trigger the vulnerability
- Set the UMASK to 111 to make new files writable by everyone in the current context.
- Set the environment variable _U_LOG_FILE_ to _/etc/ld.so.preload_.
- Execute the vulnerable binary. This way, _/etc/ld.so.preload_ will be created and will be writable by the current user.
- Clear the file's content and reference our custom shared object.
- Finally call _/usr/bin/sudo_ to force the execution of the malicious code.

### 4) Run the _root shell_
- At this stage, the _root shell_ binary should be owned by root and should have the _setuid_ and _setgid_ bits enabled.
- Running the file should pop a shell as root.

Running the exploit script...

<p align="center">
  <img src="https://github.com/itm4n/ca-dollaru-uxdqmsrv-privesc/raw/master/screenshots/10_exploit.png">
</p>

## Side note 
The machine on which the vulnerability was initially discovered was properly hardened. The _/tmp/_ folder was mounted in a separate partition with the option _nosuid_. It means that although the exploit was successful and the _root shell_ was created, it didn't grant root privileges. Therefore, some additional code was added to search for a world-writable directory in _/opt/_. The global variable _USE_TMP_ is used in the script to specify whether the exploit should use _/tmp/_ as a working directory or recursively search for a suitable one in _/opt/_.

## Remediation  
At the time of writing, Dollar Universe 5.3.3 is reaching its end of life. Therefore, no patch has been developped on this version.

However, a workaround exists:
- Remove the setuid uid bit. 
- Create a new entry in _/etc/sudoers_ to enable a specific user to run it as root. 

Alternatively, upgrade to Dollar Universe 6. 

## Credits 
The shared object was taken from the following exploit: https://www.exploit-db.com/exploits/40768/

## Disclosure timeline 
2018-06-06 - Vulnerability discovery  
2018-06-07 - Being redirected to the Product Manager  
2018-06-26 - Report (+demonstration video) sent to vendor  
2018-07-11 - Reminder sent to vendor  
2018-07-12 - Vendor acknowledges vulnerability  
2018-07-12 - Suggested a workaround  
2018-08-02 - Reminder sent to vendor  
2018-08-03 - Workaround accepted by vendor  
2018-08-31 - Vulnerability disclosed  
