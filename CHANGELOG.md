# CHANGELOG

## 0.1.0 - 2018-08-16

All features (capabilities, fingerprinting, security scan) work in a limited capacity. The tool has been tested against multiple live OFX servers.

### Features

* Parse OFX 1.0.x
* Enumerate FI contact information
* Fingerprint server stack based off HTTP headers
* Fingerprint OFX software based off URL paths
* Enumerate Banking capabilities
* Run recon security tests with anonymous credentials

### Tests

* Check for MFA support within the protocol
* Check password policy
