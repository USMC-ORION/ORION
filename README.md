# ORION Registration Application (ORA)
![Screenshot](Images/orion.JPG)
![Screenshot](Images/expedited_structure.JPG)
Includes both server and client side applications of the ORA needed to successfuly register and credential a device.

## Getting Started
The following system specifications were used to develop the app: <br />
<br />
System Operating System: Windows 10 Pro <br />
Manufacturer/Model: Acer Aspire E5-576G <br />
Processor: Intel Core i5-8250U @ 1.6 GHz <br />
Graphics Coprocessor: NVIDIA GeForce MX150 with 2.00 GB Dedicated GDDR5 VRAM <br />
Installed Memory (RAM): 8.00 GB Dual Channel Memory DDR4 <br />
Hard Drive: 256 GB SSD <br />
System Type: 64-bit <br />
Operating System, x64-based processor <br />
Hypervisor: Oracle VM VirtualBox 6.0.4r128413 (Qt5.6.2) <br />
Virtual Machine Operating System: Ubuntu 19.10S <br />
DN Operating System: Open Network Operating System (ONOS) 2.4.0 <br />
Network Emulator: Mininet 2.2.2 <br />
Packet Analyzer: Wireshark 3.0.5 <br />
Programming Languages: Python 2.7.17 & Java 1.8.0 <br />

![Screenshot](Images/ora_experiment.JPG)

### Prerequisites
The project was built in a Linux virtual environment: <br />

1) Install Mininet Network Emulator <br />
2) Install Open Network Operating System <br />
3) Utilize onos-create-app tool to build a new ONOS application, replace the template .java file with AppComponent.java <br />
4) Install OpenSSL <br />
5) Install any code-dependent libraries, as required, needed to execute the code (as noted in source code) <br />

![Screenshot](Images/ora_mainmenu.JPG)

### Installing and Running Tests
Download all source files to working directory.
1) Run ONOS <br />
2) Run Mininet and deploy toplogy, ensure OpenFlow and Reactive Forwarding is enabled. <br />
3) Compile and deploy AppComponent.java in ONOS CLI to start up the server-side application. <br />
4) Execute client_registration.py to start the client-side application. <br />

## Authors

**Jack Chang** - *Initial work* - https://github.com/usmc-orion/orion

## Acknowledgments

* Dr. Geoffrey Xie
* Dr. Gurminder Singh
* Naval Postgraduate School, Monterey, CA, USA
