# Getting started guide

1. Overview
2. Prerequisites
3. Running the script

## Overview
Acquia has a goal of enabling FIPS 140-2 validated cryptographic modules on servers that deal with federal data. The source of these modules are from Canonical’s Ubuntu Advantage program, which has a private repository where we retrieve these packages and apply them to our Ubuntu 16.04 systems.

Acquia uses Tenable’s SecurityCenter (Nessus) to do monthly and release vulnerability scans and it has become apparent that these packages are not being identified properly. This script is a tool to identify those packages on hosts where Nessus fails to properly do so.


## Prerequisites
Nessus Results
This workflow is dependent on a result-set from Nessus that requires further confirmation that the packages are in fact present on given systems or not.  These results are published in the FedRAMP Deviation Request Form

FedRAMP Deviation Request Form
FIPS 140-2 DR-FP Form, tab DR Sheet is used to record the Nessus findings.  Column 'D' of this form (Assets Impacted) serves as basis of the host list the script will execute against.  Column 'E' (Vulnerability Name) provides the package name which needs to be verified. 

### ssh_subprocess.py 
This python script needs to be present in the same directory.  This module is imported and handles the execution of the ssh command used to gaterh package details from the remote hosts.

### package-list
This is the list of FIPS 140-2 packages from Ubuntu's private repo.  package-list has been parsed to contain simply the package name and the package version as in the following example:
```
Package: libssl-dev Version: 1.0.2g-1ubuntu4.fips.4.6.3
```
### host-list
This is the list of hosts derived from column D on FIPS 140-2 DR-FP Form.  The format of the file is comma delimmited with no spaces:
```
svn-2,bal-3,bal-4,web-5,web-6,fsdb-7,fsdb-8,backup-9 
```
Create the host-list file comprising of the hosts that need to be inspected for the FIPS packages.  Populate the host-list from column D on FIPS 140-2 DR-FP Form. The data in the FIPS 140-2 DR-FP Form would have been populated already by a seperate process as the results of the Nessus scan were reviewed and tracked.  The hostnames must be common seperated with no spaces.

## Running the Script
Make sure to add your SSH key to your ssh agent
```bash
ssh-add
```
The script is written to be compatible with the Acquia SCNG-Nessus repo which uses Python 2.7.5.  Execute the script with the host-list as the argument:
```bash
python test-main2.py host-list
```
The script will poll each server in the host-list for the installed packages.  The manifest of packages will be stored on the filesystem for each host in the format of $(host)-manifest.txt.  The script will then compare the entries in the FIPS package list against the packages from the package manifest to report what is installed, and what is missing.

Be sure to clean up the filesystem of left-over manifest files once the script has run.


