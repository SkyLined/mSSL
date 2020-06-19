class cSSLException(Exception):
  def __init__(oSelf, sMessage, xDetails):
    oSelf.sMessage = sMessage;
    oSelf.xDetails = xDetails;
    Exception.__init__(oSelf, (sMessage, xDetails));
  
  def __repr__(oSelf):
    return "<%s %s>" % (oSelf.__class__.__name__, oSelf);
  def __str__(oSelf):
    sDetails = str(oSelf.xDetails) if not hasattr(oSelf.xDetails, "fsToString") else oSelf.xDetails.fsToString();
    return "%s (%s)" % (oSelf.sMessage, sDetails);

class cSSLSecureTimeoutException(cSSLException):
  pass; # Cannot secure the connection within the maximum acceptable time.

class cSSLWrapSocketException(cSSLException):
  pass; # Cannot wrap the socket in SSL.

class cSSLSecureHandshakeException(cSSLException):
  pass; # Cannot complete a secure handshake successfully

class cSSLCannotGetRemoteCertificateException(cSSLException):
  pass; # Cannot get the remote certificate

class cSSLIncorrectHostnameException(cSSLException):
  pass; # The remote certificate is for an incorrect hostname.
