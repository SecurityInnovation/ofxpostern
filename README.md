# ofxpostern
Vulnerability scanner for OFX servers.

**ofxpostern** is a CLI tool which fingerprints an OFX service, describes its capabilities, and assesses its security.

## Installation

**ofxpostern** is written in Python 3 with few external dependencies. It has only been tested on Linux.

1. `git clone git@github.com:sdann/ofxpostern.git`
2. `cd ofxpostern`
3. `pip install -r requirements.txt`

## Usage

`./ofxpostern.py [-f FID] [-o ORG] url`

Example:

`./ofxpostern.py -o Cavion -f 11135 https://ofx.lanxtra.com/ofx/servlet/Teller`

The Financial Identifer (FID) and Organization (ORG) are sometimes optional, sometimes required depending on the Financial Institution.

A current list of public OFX servers is available at https://ofxhome.com/.

## Security Scan

A small number of security tests are implemented. All are done with anonymous credentials.

* Check that TLS is required
* Check for correct application/x-ofx content-type
* Check for web server / framework version disclosure
* Check for MFA support within the protocol
* Check password policy
* Check for username disclosure
* Check for NULL return values
* Check for Internal Server Error 500
* Check for internal IP address disclosure

## Advanced

Within the *ofxpostern.py* script the *cache* global variable can be enabled to store text copies of all OFX protocol responses to `$HOME/.ofxpostern/`.

## Docker
```bash
# Get this project
git clone git@github.com:sdann/ofxpostern.git
cd ofxpostern
# run with docker
docker build -tag ofxpostern 
docker run ofxpostern  -o Cavion -f 11135 https://ofx.lanxtra.com/ofx/servlet/Teller
```
