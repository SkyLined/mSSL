import ssl, time;

try: # mDebugOutput use is Optional
  from mDebugOutput import *;
except: # Do nothing if not available.
  ShowDebugOutput = lambda fxFunction: fxFunction;
  fShowDebugOutput = lambda sMessage: None;
  fEnableDebugOutputForModule = lambda mModule: None;
  fEnableDebugOutputForClass = lambda cClass: None;
  fEnableAllDebugOutput = lambda: None;
  cCallStack = fTerminateWithException = fTerminateWithConsoleOutput = None;

from .mExceptions import *;

class cSSLContext(object):
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
  def foForClientWithHostnameAndCertificateFilePath(cClass, sHostname, sCertificateFilePath, bCheckHostname = True):
    # Client side with key pinning
    oPythonSSLContext = ssl.create_default_context(cafile = sCertificateFilePath);
    oPythonSSLContext.verify_mode = ssl.CERT_REQUIRED;
    oPythonSSLContext.check_hostname = bCheckHostname;
    return cClass(sHostname, oPythonSSLContext, bServerSide = False);
  
  @classmethod
  def foForClientWithHostname(cClass, sHostname, bCheckHostname = True):
    # Client side
    oPythonSSLContext = ssl.create_default_context();
    oPythonSSLContext.load_default_certs();
    oPythonSSLContext.verify_mode = ssl.CERT_REQUIRED;
    oPythonSSLContext.check_hostname = bCheckHostname;
    return cClass(sHostname, oPythonSSLContext, bServerSide = False);

  @classmethod
  def foForClientWithoutVerification(cClass):
    # Client side
    oPythonSSLContext = ssl._create_unverified_context();
    return cClass(None, oPythonSSLContext, bServerSide = False, bUnverified = True);

  @ShowDebugOutput
  def __init__(oSelf, szHostname, oPythonSSLContext, bServerSide, bUnverified = False):
    oSelf.__szHostname = szHostname;
    oSelf.__oPythonSSLContext = oPythonSSLContext;
    oSelf.__bServerSide = bServerSide;
    oSelf.__bUnverified = bUnverified;
  
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
  def foWrapSocket(oSelf,
    oPythonSocket,
    nzTimeoutInSeconds = None,
  ):
    if nzTimeoutInSeconds is not None and nzTimeoutInSeconds <= 0:
      raise cSSLSecureTimeoutException(
        "Timeout before socket could be secured.",
        {"nzTimeoutInSeconds" : nzTimeoutInSeconds},
      );
    nzEndTime = time.clock() + nzTimeoutInSeconds if nzTimeoutInSeconds else None;
    fShowDebugOutput("Wrapping socket%s..." % (" (timeout = %ss)" % nzTimeoutInSeconds if nzTimeoutInSeconds is not None else ""));
    try:
      oPythonSocket.settimeout(nzTimeoutInSeconds);
      oPythonSSLSocket = oSelf.__oPythonSSLContext.wrap_socket(
        sock = oPythonSocket,
        server_side = oSelf.__bServerSide,
        server_hostname = None if oSelf.__bServerSide else oSelf.__szHostname,
        do_handshake_on_connect = False,
      );
    except ssl.SSLError as oException:
      fShowDebugOutput("Exception while wrapping socket in SSL: %s" % repr(oException));
      raise cSSLWrapSocketException(
        "Could not create secure socket.",
        {"oSSLContext": oSelf, "oException": oException},
      );
    if nzEndTime is not None and time.clock() > nzEndTime:
      raise cSSLSecureTimeoutException(
        "Timeout before socket could be secured.",
        {"nzTimeoutInSeconds" : nzTimeoutInSeconds},
      );
    fShowDebugOutput("Performing handshake...");
    try:
      oPythonSSLSocket.do_handshake();
    except ssl.SSLError as oException:
      fShowDebugOutput("Exception while performing SSL handshake: %s" % repr(oException));
      raise cSSLSecureHandshakeException(
        "Could not perform SSL handshake.",
        {"oSSLContext": oSelf, "oException": oException},
      );
    if oSelf.__oPythonSSLContext.check_hostname:
      if nzEndTime is not None and time.clock() > nzEndTime:
        raise cSSLSecureTimeoutException(
          "Timeout before socket could be secured.",
          {"nzTimeoutInSeconds" : nzTimeoutInSeconds},
        );
      fShowDebugOutput("Checking hostname...");
      try:
        oRemoteCertificate = oPythonSSLSocket.getpeercert();
      except ssl.SSLError as oException:
        fShowDebugOutput("Exception while getting remote certificate: %s" % repr(oException));
        raise cSSLCannotGetRemoteCertificateException(
          "Could not get remote certificate.",
          {"oSSLContext": oSelf, "oException": oException},
        );
      assert oRemoteCertificate, \
          "No certificate!?";
      if nzEndTime is not None and time.clock() > nzEndTime:
        raise cSSLSecureTimeoutException(
          "Timeout before socket could be secured.",
          {"nzTimeoutInSeconds" : nzTimeoutInSeconds},
        );
      try:
        ssl.match_hostname(oRemoteCertificate, oSelf.__szHostname);
      except ssl.CertificateError as oException:
        fShowDebugOutput("Exception while matching hostname: %s" % repr(oException));
        raise cSSLIncorrectHostnameException(
          "The server reported an incorrect hostname for the secure connection",
          {"oSSLContext": oSelf, "oException": oException},
        );
    fShowDebugOutput("Connection secured.");
    return oPythonSSLSocket;

  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    return [s for s in [
      ("hostname=%s" % oSelf.__szHostname) if oSelf.__szHostname else "NO HOSTNAME",
      "%s side" % ("server" if oSelf.__bServerSide else "client"),
      "checks hostname" if oSelf.__oPythonSSLContext.check_hostname else "DOES NOT CHECK HOSTNAME",
      "UNVERIFIED" if oSelf.__bUnverified else None,
    ] if s];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));
