class cSSLException(Exception):
  def __init__(oSelf, sMessage, *, dxDetails = None):
    assert isinstance(dxDetails, dict), \
        "dxDetails must be a dict, not %s" % repr(dxDetails);
    oSelf.sMessage = sMessage;
    oSelf.dxDetails = dxDetails;
    Exception.__init__(oSelf, sMessage, dxDetails);
  
  def fasDetails(oSelf):
    return ["%s: %s" % (str(sName), repr(xValue)) for (sName, xValue) in oSelf.dxDetails.items()];
  def __str__(oSelf):
    return "%s (%s)" % (oSelf.sMessage, ", ".join(oSelf.fasDetails()));
  def __repr__(oSelf):
    return "<%s.%s %s>" % (oSelf.__class__.__module__, oSelf.__class__.__name__, oSelf);

class cSSLSecureTimeoutException(cSSLException):
  pass; # Cannot secure the connection within the maximum acceptable time.

class cSSLWrapSocketException(cSSLException):
  pass; # Cannot wrap the socket in SSL.

class cSSLUnknownCertificateAuthorityException(cSSLException):
  pass; # Cannot complete a secure handshake successfully because the signing Certificate Authority is not known.

class cSSLIncompleteCertificateChainException(cSSLException):
  pass; # The provided certificate chain is incomplete.

class cSSLInvalidCertificateException(cSSLException):
  pass; # The provided certificate is invalid (no further details about the reason for this unfortunately)

class cSSLInvalidCertificateChainException(cSSLInvalidCertificateException):
  pass; # The provided certificate is invalid because it does not have a complete trust-chain.
class cSSLInvalidCertificateExpiredException(cSSLInvalidCertificateException):
  pass; # The provided certificate is invalid because it has expired.
class cSSLInvalidCertificateRevocationListException(cSSLInvalidCertificateException):
  pass; # The provided certificate is invalid because it has an invalid certificate revocation list.
class cSSLInvalidCertificateRevocationListNotAvailableException(cSSLInvalidCertificateRevocationListException):
  pass; # The provided certificate is invalid because it's certificate revocation list is not available.
class cSSLInvalidHostForCertificateException(cSSLInvalidCertificateException):
  pass; # The provided certificate is invalid because it does not apply to the remote Host used in the connection
class cSSLInvalidSelfSignedCertificateException(cSSLInvalidCertificateException):
  pass; # The provided certificate is invalid because it is self-signed.
class cSSLInvalidSelfSignedCertificateInChainException(cSSLInvalidSelfSignedCertificateException):
  pass; # The provided certificate is invalid because it has a self-signed certificate in its trust-chain.

class cSSLSecureHandshakeException(cSSLException):
  pass; # Cannot complete a secure handshake successfully

class cSSLCannotGetRemoteCertificateException(cSSLException):
  pass; # Cannot get the remote certificate

acExceptions = [
  cSSLException,
  cSSLSecureTimeoutException,
  cSSLWrapSocketException,
  cSSLUnknownCertificateAuthorityException,
  cSSLIncompleteCertificateChainException,
  cSSLInvalidCertificateException,
  cSSLInvalidCertificateChainException,
  cSSLInvalidCertificateExpiredException,
  cSSLInvalidCertificateRevocationListException,
  cSSLInvalidCertificateRevocationListNotAvailableException,
  cSSLInvalidHostForCertificateException,
  cSSLInvalidSelfSignedCertificateException,
  cSSLInvalidSelfSignedCertificateInChainException,
  cSSLSecureHandshakeException,
  cSSLCannotGetRemoteCertificateException,
];