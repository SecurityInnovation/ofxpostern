# CHANGELOG

## 0.2.0 - 2018-10-30

Added many new tests and capability parsing.

### Features

* Parse OFX 2.0.x
* Enumerate capabilities:
  - Investments
  - Bill Pay
  - Credit Card
  - 401(k)
  - Tax
  - Messaging
  - Authentication
* Fingerprint some Service Providers

### Tests

* Check that TLS is required
* Check for correct application/x-ofx content-type
* Check for web server / framework version disclosure
* Check for username disclosure
* Check for NULL return values
* Check for Internal Server Error 500
* Check for internal IP address disclosure

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
