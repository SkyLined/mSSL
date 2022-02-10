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

class cSSLSecureHandshakeException(cSSLException):
  pass; # Cannot complete a secure handshake successfully

class cSSLCannotGetRemoteCertificateException(cSSLException):
  pass; # Cannot get the remote certificate

class cSSLIncorrectHostnameException(cSSLException):
  pass; # The remote certificate is for an incorrect hostname.

acExceptions = [
  cSSLException,
  cSSLSecureTimeoutException,
  cSSLWrapSocketException,
  cSSLUnknownCertificateAuthorityException,
  cSSLSecureHandshakeException,
  cSSLCannotGetRemoteCertificateException,
  cSSLIncorrectHostnameException,
];