# soscl
SiFive Open Source Cryptographic Library
The SOSCL is an open source software cryptographic library that proposes the most demanded and useful cryptographic algorithms. It includes symmetric block ciphers, hash functions and public-key cryptography algorithms.
It aims to comply with all the cryptographic standards, first of all being the NIST standards.
32-bit and 64-bit architectures will be supported, by setting the defines SOSCL_WORD32 or SOSCL_WORD64.
Today, only the 32-bit architecture has been tested.
Makefiles are provided as examples for x86-linux and RISC-V 32-bit FE310.
It has been tested on x86-linux and SiFive FE310.

Features
--------
 * written in C
 * compact code
 * uses a dedicated memory buffer for temp data management
 * contains NIST test vectors in test/data directory
 * makefiles for ubuntu and RISC-V
 * simple API
 * MIT license

Usage Notes
-----------
 * for Ubuntu
  * make -f makefile_ubuntu : it generates an executable program
  * cd test/data
  * ../../soscl_library.exe

 * for RISC-V
  * SiFive Freedom Studio shall be installed
  * the makefile shall be updated, if needed, with correct RISC-V gcc path
  * make -f makefile_riscv32 all : it generates a RISC-V library
  * the library has to be linked to an example code
  
[release 1.0.0](releases_notes.md)

   