class cSSLException(Exception):
  def __init__(oSelf, sMessage, dxDetails):
    oSelf.sMessage = sMessage;
    oSelf.dxDetails = dxDetails;
    Exception.__init__(oSelf, sMessage, dxDetails);
  
  def __repr__(oSelf):
    return "<%s %s>" % (oSelf.__class__.__name__, oSelf);
  def __str__(oSelf):
    sDetails = ", ".join("%s: %s" % (str(sName), repr(xValue)) for (sName, xValue) in oSelf.dxDetails.items());
    return "%s (%s)" % (oSelf.sMessage, sDetails);

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