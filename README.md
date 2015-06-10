Claimsman
===========

Introduction
------------

Claimsman logs all file handle creations on Windows systems, and logs them to both a local file and centralized log management system. The goal is to collect information that helps in answering the following two questions:

* What files has user X accessed within defined time frame?
* Who has accessed file X within defined time frame?

The application consists of a kernel driver, and an application (windows service) that forwards the data to Graylog installation. The outcome will look something like:

![Screenshot from Graylog](https://raw.githubusercontent.com/mikkolehtisalo/claimsman/master/doc/claimsman.png "Screenshot from Graylog")

Features
--------

* Local file, containing JSON, saved
* Log forwarding done with GELF (HTTP)
* Can recover from temporary server availability issues
* Ability to ignore users (for instance service accounts) by SID  (see the claimsman.inf for details)
* Ability to select what files get logged by extension (see the claimsman.inf for details)
* Automatically monitors also shares, and removable devices
* Extendable (log a copy of the accessed files, etc)

Currently the following information is logged:

| Field			| Description           | Example  |
| ------------- |-------------|-----|
|  | right-aligned |  |
|     | centered      |    |
|  | are neat      |     |

Requirements
------------

* Visual Studio 2010+
* zlib
* Casablanca (C++ REST SDK)
* Certificates for [KMCS](http://www.microsoft.com/whdc/winlogo/drvsign/kmcs_walkthrough.mspx)
* Log management system (for example [Graylog](https://www.graylog.org/) or [ELK](https://www.elastic.co/))
* Packaging toolchain (for example [InstallShield](http://www.installshield.com/))

Configuration options
---------------------

The following registry keys are used to configure claimsman:

| Field			| Description           | Example  |
| ------------- |-------------|-----|
| HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\claimsman\DebugFlags  | Debugging option for the driver | 0x1  |
| HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\claimsman\Extensions   | File extensions included in monitoring | "docx","doc","xls","xlsx","ppt","pptx","txt","rtf"   |
| HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\claimsman\Extensions | Users (SIDs) to be ignored    |  "S-1-5-18"   |
| HKEY_LOCAL_MACHINE\SOFTWARE\Claimsman\LogFile | Location of the log file    |  c:\logs\activity.log   |
| HKEY_LOCAL_MACHINE\SOFTWARE\Claimsman\LogServer | Target server (Graylog/HTTP)  |  http://192.168.1.200:12201   |

Packaging
---------

1. Install your certificates for signing the driver
1. Package the driver - the provided INF should be informative enough, set the SIDs and file extensions
1. Package the service - set the registry keys for logging locations
```
HKLM -> Software -> Claimsman -> LogFile
// Example c:\activity.log
HKLM -> Software -> Claimsman -> LogServer
// Example http://myserver.mydomain:1201
```
1. Distribute

