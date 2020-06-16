Implements a certificate store and SSL contexts for use with `mTCPIPConnections`
to allow secure connections. Offers the ability to generate certificates for
any dmain from a root certificate. This completely breaks security to allow
intercepting secure communications.

*You will need to download OpenSSL for windows and store `openssl.exe` in a
seprate `OpenSSL` folder in the main folder of this module.*
`
`cCertificateStore`
-------------------
Implements a certificate store that stores SSL contexts per hostname/domain.

`cSSLContext`
-------------
Implements a single SSL context tied to a hostname for use with securing a
TCP/IP connection to a server with that hostname.

`oCertificateAuthority`
-----------------------
Implements a Certificate Authority for generating certificates for any
hostname/domain for use in SSL contexts.