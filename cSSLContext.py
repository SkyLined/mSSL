import ssl, time;

from mDebugOutput import ShowDebugOutput, fShowDebugOutput;

class cSSLContext(object):
  class cSSLException(Exception):
    def __init__(oSelf, sMessage, sDetails):
      oSelf.sMessage = sMessage;
      oSelf.sDetails = sDetails;
      Exception.__init__(oSelf, sMessage, sDetails);
  class cSSLHostnameException(cSSLException):
    pass;
  
  @classmethod
  def foForServerWithHostnameAndCertificateFilePath(cClass, sHostname, sCertificateFilePath):
    # Server side with everything in one file
    oPythonSSLContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH);
    oPythonSSLContext.load_cert_chain(certfile = sCertificateFilePath);
    return cClass(sHostname, oPythonSSLContext, bServerSide = True);
  
  @classmethod
  def foForServerWithHostnameAndKeyAndCertificateFilePath(cClass, sHostname, sKeyFilePath, sCertificateFilePath):
    # Server side with certificate and private key in separate files
    oPythonSSLContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH);
    try:
      oPythonSSLContext.load_cert_chain(keyfile = sKeyFilePath, certfile = sCertificateFilePath);
    except ssl.SSLError as oException:
      fShowDebugOutput("Cannot load certificate chain (keyfile = %s, certfile = %s): %s" % \
          (sKeyFilePath, sCertificateFilePath, oException.message));
      oException.message = "Cannot load certificate chain (keyfile = %s, certfile = %s): %s" % \
          (sKeyFilePath, sCertificateFilePath, oException.message);
      raise;
    return cClass(sHostname, oPythonSSLContext, bServerSide = True);
  
  @classmethod
  def foForClientWithHostnameAndCertificateFilePath(cClass, sHostname, sCertificateFilePath):
    # Client side with key pinning
    oPythonSSLContext = ssl.create_default_context(cafile = sCertificateFilePath);
    oPythonSSLContext.verify_mode = ssl.CERT_REQUIRED;
    oPythonSSLContext.check_hostname = False;
    return cClass(sHostname, oPythonSSLContext, bServerSide = False);
  
  @classmethod
  def foForClientWithHostname(cClass, sHostname):
    # Client side
    oPythonSSLContext = ssl.create_default_context();
    oPythonSSLContext.load_default_certs();
    oPythonSSLContext.verify_mode = ssl.CERT_REQUIRED;
    oPythonSSLContext.check_hostname = False;
    return cClass(sHostname, oPythonSSLContext, bServerSide = False);

  @ShowDebugOutput
  def __init__(oSelf, szHostname, oPythonSSLContext, bServerSide):
    oSelf.__szHostname = szHostname;
    oSelf.__oPythonSSLContext = oPythonSSLContext;
    oSelf.__bServerSide = bServerSide;
  
  @property
  def fbServerSide(oSelf):
    return oSelf.__bServerSide;
  
  @property
  def fbClientSide(oSelf):
    return not oSelf.__bServerSide;
  
  @property
  def szHostname(oSelf):
    return oSelf.__szHostname;
  
  def fAddCertificateAuthority(oSelf, oCertificateAuthority):
    oCertificateAuthority.fVerifyPythonSSLContext(oSelf.__oPythonSSLContext);
  
  @ShowDebugOutput
  def foWrapSocket(oSelf, oPythonSocket, nzTimeoutInSeconds = None, bCheckHostname = None):
    if bCheckHostname is None:
      bCheckHostname = not oSelf.__bServerSide;
    if nzTimeoutInSeconds is not None and nzTimeoutInSeconds <= 0:
      raise oSelf.cSSLException(
        "Timeout before socket could be secured.",
        {"nzTimeoutInSeconds" : nzTimeoutInSeconds},
      );
    nzEndTime = time.time() + nzTimeoutInSeconds if nzTimeoutInSeconds else None;
    fShowDebugOutput("Wrapping socket%s..." % (" (timeout = %ss)" % nzTimeoutInSeconds if nzTimeoutInSeconds is not None else ""));
    try:
      oPythonSocket.settimeout(nzTimeoutInSeconds);
      oPythonSSLSocket = oSelf.__oPythonSSLContext.wrap_socket(
        sock = oPythonSocket,
        server_side = oSelf.__bServerSide,
        server_hostname = None if oSelf.__bServerSide else oSelf.__szHostname,
        do_handshake_on_connect = False,
      );
      oPythonSSLSocket.do_handshake();
    except ssl.SSLError as oException:
      # The SSL negotiation failed, which leaves the socket in an unknown state so we will close it.
      oPythonSocket.close(); 
      raise oSelf.cSSLException("Could not create secure socket.", repr(oException));
      fShowDebugOutput("Exception while wrapping socket in SSL: %s" % repr(oException));
      raise;
    if bCheckHostname:
      assert oSelf.__szHostname, \
          "No hostname to check";
      nzCurrentTimeoutInSeconds = nzEndTime - time.time() if nzEndTime is not None else None;
      oSelf.fCheckHostname(oPythonSSLSocket, nzCurrentTimeoutInSeconds);
    fShowDebugOutput("Connection secured");
    return oPythonSSLSocket;
  
  @ShowDebugOutput
  def fCheckHostname(oSelf, oPythonSSLSocket, nzTimeoutInSeconds = None):
    assert oSelf.__szHostname, \
        "No hostname to check";
    fShowDebugOutput("Checking hostname%s..." % (" (timeout = %ss)" % nzTimeoutInSeconds if nzTimeoutInSeconds is not None else ""));
    try:
      oPythonSSLSocket.settimeout(nzTimeoutInSeconds);
      oRemoteCertificate = oPythonSSLSocket.getpeercert();
      assert oRemoteCertificate, \
          "No certificate!?";
      ssl.match_hostname(oRemoteCertificate, oSelf.__szHostname);
    except ssl.CertificateError as oException:
      oPythonSSLSocket.shutdown(socket.SHUT_RDWR);
      oPythonSSLSocket.close();
      raise oSelf.cSSLHostnameException("The server reported an incorrect hostname for the secure connection", repr(oException));
    except ssl.SSLError as oException:
      # The SSL negotiation failed, which leaves the socket in an unknown state so we will close it.
      oPythonSocket.close(); 
      raise oSelf.cSSLException("Could not check the hostname against the certificate.", repr(oException));

  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    return [s for s in [
      ("hostname=%s" % oSelf.__szHostname) if oSelf.__szHostname else "no hostname",
      "%s side" % ("server" if oSelf.__bServerSide else "client"),
    ] if s];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));
