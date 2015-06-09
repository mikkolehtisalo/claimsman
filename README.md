Claimsman
===========

Introduction
------------

Claimsman logs all file handle creations on Windows systems, and logs them to both a local file and centralized log management system.

The application consists of a kernel driver, and an application (windows service) that forwards the data to Graylog installation. The outcome will look something like:

![Screenshot from Graylog](https://raw.githubusercontent.com/mikkolehtisalo/claimsman/master/doc/claimsman.png "Screenshot from Graylog")

Features
--------

* Local file, containing JSON, saved
* Log forwarding done with GELF (HTTP)
* Can recover from temporary server availability issues
* Ability to ignore users (for instance service accounts) by SID  (see the claimsman.inf for details)
* Ability to select what files get logged by extension (see the claimsman.inf for details)

Requirements
------------

* Visual Studio 2010+
* zlib
* Casablanca (C++ REST SDK)
* Certificates for KMCS (See http://www.microsoft.com/whdc/winlogo/drvsign/kmcs_walkthrough.mspx)

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

