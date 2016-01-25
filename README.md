#FastIR Collector Linux
##Concepts
This tool collects different artefacts on live Linux and records the results in csv files. With the analysis of these artefacts, an early compromission can be detected. All code must be in a python file and support 2.4 to 3.5 python versions.

##Artefacts

* System Informations   
  * Kernel version
  * Network interfaces
  * Hostname
  * Distribution versions


* Last Logins

* Connexions

* Handles


* User's datas
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

  
