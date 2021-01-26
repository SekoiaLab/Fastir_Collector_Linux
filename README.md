# FastIR Collector Linux

**We changed our approach to live forensics acquisition, which means FastIR Collector is no longer maintained. We recommend using our new [FastIR Artifacts collector](https://github.com/SekoiaLab/fastir_artifacts) instead**

## Concepts
This tool collects different artefacts on live Linux and records the results in csv files.
With the analysis of these artefacts, an early compromission can be detected.
All code must be in a python 2 file and support starts at 2.4. This program should be run as root.

## Artefacts

* System Informations   
  * Kernel version
  * Kernel modules
  * Network interfaces
  * Hostname
  * Distribution versions

* Last Logins

* Connexions

* Handles

* User's data
  * Hidden files in Users profiles
  * SSH know_host files

* /tmp content

* Autoruns
  * /etc/\*.d
  * /etc/crontab
  * /etc/cron.\*/

* Disks Informations  
  * List of partitions
  * MBR

* Files System Informations
  
