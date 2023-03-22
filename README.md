# Introduction 
Boman CLI is a Orchestration script written in python to run security scans on the customer's local or CI/CD environment and upload the results to Boman.ai SaaS server.


# Installation

` pip install boman-cli`

# Getting Started

###  For help

` boman-cli -h` 

### To test the boman cli server

` boman-cli -a test-saas`


### To test the boman configuration written in boman.yaml file

` boman-cli -a test-yaml`

### To run the scan 

` boman-cli -a run`

### To run the scan on specific Boman SaaS URL (On prem)

` boman-cli -a run -u {URL}`


### releases:

#### v1.02 with following changes:

Version with synk integration, codeql csharp build, exit code sorted
added option to fail/pass build, dast error sorted
Snyk feature added and upload logs to saas function added


### v1.3:


SCA scan bug fixed
