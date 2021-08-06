mSSL
====
mSSL is a Python module that implements SSL context for use in securing socket.
It implements a certificate store that can be used to store and retreive client
and server certificates. It allows you to get client SSL contexts for checking
server certificates using the locally installed Root Certificate Authorities.
It also allows you to create your own Certificate Authority and that it to
create self-signed certificates.

It can be use in conjunction with the `mTCPIPConnections` module to create
secure connections across the network.

The self-signed certificates created using the Certificate Authority can be
used to Man-in-the-Middle secure connections.

cSSLContext
-----------
Implements a single SSL context tied to a hostname for use with securing a
TCP/IP connection to a server with that hostname.

Example usage:
```
import mSSL;
from mNotProvided import *;

def foSecureSocket(
  oPythonSocket,
  sbHostname,
  n0zTimeoutInSeconds = zNotProvided,
):
  # Every time this function is called a `cSSLContext` instance is created:
  oSSLContext = mSSL.cSSLContext.foForClientWithHostname(
    sbHostname,
    bCheckHostname = True,
  );
  return oSSLContext.foWrapSocket(
    oPythonSocket,
    n0zTimeoutInSeconds
  );

# Now you can connect to a secure server and secure the connection by calling
# `foSecureSocket` and providing the expected hostname of the server in the
# arguments.
```

cCertificateStore
-----------------
Implements a certificate store that stores client and/or server SSL contexts
per hostname/domain. This requires less CPU and memory than creating a new
instance every time you need one.

Example usage:
```
import mSSL;
from mNotProvided import *;

oCertificateStore = mSSL.cCertificateStore();

def foSecureSocket(
  oPythonSocket,
  sbHostname,
  n0zTimeoutInSeconds = zNotProvided,
):
  # The first time this function is called for each hostname, a
  # `cSSLContext` instance is created, cached, and returned. Every
  # subsequent time this function is called for the same hostname,
  # the cached `cSSLContext` instance is returned:
  oSSLContext = oCertificateStore.foGetClientsideSSLContextForHostname(
    sbHostname,
    bCheckHostname = True,
  );
  return oSSLContext.foWrapSocket(
    oPythonSocket,
    n0zTimeoutInSeconds,
  );

# Now you can connect to a secure server and secure the connection by calling
# `foSecureSocket` and providing the expected hostname of the server in the
# arguments.
# Note that a certificate store can be used to store both client- and 
# server-side contexts.
```

oCertificateAuthority
---------------------
Implements a Certificate Authority for generating certificates for any
hostname/domain for use in SSL contexts.

Example usage:
```
import mSSL;
from mNotProvided import *;

sbTestHostname = b"localhost";

# The cCertificateAuthority uses OpenSSL to create
# private keys and certificates. OpenSSL needs to store
# files somewhere to do this:
sCAFolderPath = os.path.join(os.path.dirname(__file__), "temp");
# You can provide your own name for the CA:
sCAName = "Self signed";

# Create a certificate authority:
oCA = mSSL.cCertificateAuthority(
  sCAFolderPath,
  sCAName
);

# Create an SSL Context with a self-signed certificate:
oSSLContext = oCA.foGenerateServersideSSLContextForHostname(
  sbTestHostname
);

def foSecureSocket(
  oPythonSocket,
  n0zTimeoutInSeconds = zNotProvided,
):
  # Perform SSL handshake with the client using the server SSL context and
  # secure the connection:
  return oSSLContext.foWrapSocket(
    oPythonSocket,
    n0zTimeoutInSeconds,
  );

# Now you can create a web server on "localhost" and after accepting a
# connection from a client, call `foSecureSocket` to secure the connection.
```