# BP-MAC implementation and benchmarking

This repository provides a prototype implementation of BP-MAC and the benchmarking against UMAC and hardware-accelerated HMAC-SHA256 in Contiki-NG[1]. BP-MAC is a novel MAC algorithm for fast MAC computations on contrained devices that is proposed in the paper "BP-MAC: Fast Authentication for Short Messages", accepted for publication at ACM WiSec'22.

### Getting started

To run our BP-MAC implementation, you first need to setup the Contiki-NG [build environment](https://github.com/contiki-ng/contiki-ng/wiki). To recreate the results from the paper, you additionally need special hardware, namely the Zolertia Z1 and Zolertia Re-Mote boards. However, you can also run the applcation natively in Linux or within the Cooja simulatation environment.

After you setup the environment, you can copy the bpmac folder into the top-level Contiki-NG directory.

As a final preparation step, you might want to move to the tinydtls directory (<contiki-ng>/os/net/security/tinydtls) and apply the provided patch to enable support for hardware-accelerated HMAC-SHA256 on the Zolertia Re-Mote board:
```
git apply ../../../../bpmac/tinydtls.patch

```
#### Known Error Messages

* On macOS, we ran into the problem that `git submodule update --init --recursive` did nothing after cloning the contiki-ng repository. Using `git clone --recursive https://github.com/contiki-ng/contiki-ng.git` when cloning makes that step unnecessary and did work for us in that case.

* If you run contiki-ng via docker, as described in the Contiki-NG documentation, you might see the warning `WARNING: The requested image's platform (linux/386) does not match the detected host platform (linux/amd64) and no specific platform was requested`. This is apparently a bug in docker and the warning can be ignored.

### Evaluation Flags

Now you are almost ready to run the code. The final adjustment needs to happen in the Makefile, to adopt it to you specific hardware setup and evaluation goal. The relevant flags that have to be used are the following four:

 - *DWITH_DTLS*: has to be set to 1
 - *DMAC_LEN*: lets you choose the length of the evaluated MAC tag. The supported sizes are 4,8,12, and 16
 - *DIS_ZOUL* is used to know the processor architecture (in particular the size of a int variable). For the Zolertia Z1, this has to be set to 0. For most other hardware, this should be set to 1 to assume the 4-byte long int.
 - *DUSE_HW_ACCEL* can be set to 1 if the programmed hardware supports hardware acceleration of SHA256, e.g. the Zolertia Remote, and the relevant patch has been applied. Otherwise remove this option.

### Run the code

Depending on the hardware, you need slightly different commands to see the output of the application in your terminal. These commands were test with gcc version 9.4.0 on Ubuntu 20.04. Newer versions versions of gcc (at least version 11.1.0 and 11.2.0) cause some issues, not necessarily cause by the BP-MAC code itself.


**Native execution on Linux**
```
make TARGET=native client
./client.native
```
*Note: As most Linux computers are way more powerful than the targeted hardware, you can expect that all measured timing are 0*

**Zolertia ReMote**
```
make TARGET=zoul BOARD=remote-revb savetarget
make client.upload && make login
```

**Zolertia Z1**
```
make TARGET=z1 savetarget
make client
make client.upload
make z1-reset && make login
```


[1] https://github.com/contiki-ng/contiki-ng
