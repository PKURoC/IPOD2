# IPOD2

This repository contains the Proof-of-concept implementation for the paper  
* "IPOD2: An Irrecoverable and Verifiable Deletion Scheme for Outsourced Data".
  
IPOD2 is an irrecoverable and verifiable deletion scheme for outsourced data. It utilizes the overwriting-based deletion method to implement outsourced data deletion and extends the Integrity Measurement Architecture (IMA) to measure the operations in the deletion process. The measurement results are protected by the Trusted Platform Module (TPM) and verifiable for users. 

# Tested Setup
============

There are several guides for kernel developers and users. These guides can be rendered in a number of formats, like HTML and PDF. Please read Documentation/admin-guide/README.rst first.

In order to build the documentation, use ``make htmldocs`` or ``make pdfdocs``.  The formatted documentation can also be read online at:

    https://www.kernel.org/doc/html/latest/

There are various text files in the Documentation/ subdirectory, several of them using the Restructured Text markup notation.

Please read the Documentation/process/changes.rst file, as it contains the requirements for building and running the kernel, and information about the problems which may result by upgrading your kernel.


Modified Part
============

initramfs
------------
Use busybox to create a simple file system for debugging. The file system is located in the initramfs directory.

ima policy
------------
Custom ima policy is located in /etc/ima_policy(the path in the qemu), and it is loaded by /init script. IMA policy related documentation can be read online at:

    https://www.kernel.org/doc/Documentation/ABI/testing/ima_policy

fpcr module
------------
Custom the File-based Platform Configuration Register module


## Contact

If there are questions regarding the PoC implementation, please send an email to `chenzhaoyu@stu.pku.edu.cn`.
