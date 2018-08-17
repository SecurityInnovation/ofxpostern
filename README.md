# ofxpostern
Vulnerability scanner for OFX servers.

**ofxpostern** is a CLI tool which fingerprints an OFX service, describes its capabilities, and assesses its security.

## Installation

**ofxpostern** is written in Python 3 with few external dependencies.

## Usage

`./ofxpostern.py [-f FID] [-o ORG] url`

Example:

`./ofxpostern.py -o Cavion -f 11135 https://ofx.lanxtra.com/ofx/servlet/Teller`

The Financial Identifer (FID) and Oranganization (ORG) are sometimes optional, sometimes required depending on the Financial Institution.

A current list of public OFX servers is available at https://ofxhome.com/.

## Tests

Only a small number of security tests are currently implemented. All are done with anonymous credentials.

* Check for MFA support within the protocol.
* Check password policy
