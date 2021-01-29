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

from mNotProvided import *;

from .mExceptions import *;

class cSSLContext(object):
  n0DefaultSecureTimeoutInSeconds = 5;
  
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
  def __init__(oSelf, s0Hostname, oPythonSSLContext, bServerSide, bUnverified = False):
    oSelf.__s0Hostname = s0Hostname;
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
  def s0Hostname(oSelf):
    return oSelf.__s0Hostname;
  
  def fAddCertificateAuthority(oSelf, oCertificateAuthority):
    oCertificateAuthority.fVerifyPythonSSLContext(oSelf.__oPythonSSLContext);
  
  @ShowDebugOutput
  def foWrapSocket(oSelf,
    oPythonSocket,
    n0zTimeoutInSeconds = zNotProvided,
  ):
    n0TimeoutInSeconds = fxGetFirstProvidedValue(n0zTimeoutInSeconds, oSelf.n0DefaultSecureTimeoutInSeconds);
    if n0TimeoutInSeconds is not None and n0TimeoutInSeconds <= 0:
      raise cSSLSecureTimeoutException(
        "Timeout before socket could be secured.",
        {"n0TimeoutInSeconds" : n0TimeoutInSeconds, "sRemoteAddress": "%s:%d" % oPythonSocket.getpeername()},
      );
    n0EndTime = time.clock() + n0TimeoutInSeconds if n0TimeoutInSeconds else None;
    fShowDebugOutput("Wrapping socket%s..." % (" (timeout = %ss)" % n0TimeoutInSeconds if n0TimeoutInSeconds is not None else ""));
    try:
      oPythonSocket.settimeout(n0TimeoutInSeconds);
      oPythonSSLSocket = oSelf.__oPythonSSLContext.wrap_socket(
        sock = oPythonSocket,
        server_side = oSelf.__bServerSide,
        server_hostname = None if oSelf.__bServerSide else oSelf.__s0Hostname,
        do_handshake_on_connect = False,
      );
    except ssl.SSLError as oException:
      fShowDebugOutput("Exception while wrapping socket in SSL: %s" % repr(oException));
      raise cSSLWrapSocketException(
        "Could not create secure socket.",
        {"oSSLContext": oSelf, "oException": oException},
      );
    if n0EndTime is not None and time.clock() > n0EndTime:
      raise cSSLSecureTimeoutException(
        "Timeout before socket could be secured.",
        {"n0TimeoutInSeconds" : n0TimeoutInSeconds, "sRemoteAddress": "%s:%d" % oPythonSocket.getpeername()},
      );
    fShowDebugOutput("Performing handshake...");
    try:
      oPythonSSLSocket.do_handshake();
    except ssl.SSLError as oException:
      fShowDebugOutput("Exception while performing SSL handshake: %s" % repr(oException));
      raise cSSLSecureHandshakeException(
        "Could not perform SSL handshake.",
        {"oSSLContext": oSelf, "oException": oException, "sRemoteAddress": "%s:%d" % oPythonSocket.getpeername()},
      );
    if oSelf.__oPythonSSLContext.check_hostname:
      if n0EndTime is not None and time.clock() > n0EndTime:
        raise cSSLSecureTimeoutException(
          "Timeout before socket could be secured.",
          {"n0TimeoutInSeconds" : n0TimeoutInSeconds, "sRemoteAddress": "%s:%d" % oPythonSocket.getpeername()},
        );
      fShowDebugOutput("Checking hostname...");
      try:
        oRemoteCertificate = oPythonSSLSocket.getpeercert();
      except ssl.SSLError as oException:
        fShowDebugOutput("Exception while getting remote certificate: %s" % repr(oException));
        raise cSSLCannotGetRemoteCertificateException(
          "Could not get remote certificate.",
          {"oSSLContext": oSelf, "oException": oException, "sRemoteAddress": "%s:%d" % oPythonSocket.getpeername()},
        );
      assert oRemoteCertificate, \
          "No certificate!?";
      if n0EndTime is not None and time.clock() > n0EndTime:
        raise cSSLSecureTimeoutException(
          "Timeout before socket could be secured.",
          {"n0TimeoutInSeconds" : n0TimeoutInSeconds},
        );
      try:
        ssl.match_hostname(oRemoteCertificate, oSelf.__s0Hostname);
      except ssl.CertificateError as oException:
        fShowDebugOutput("Exception while matching hostname: %s" % repr(oException));
        raise cSSLIncorrectHostnameException(
          "The server reported an incorrect hostname for the secure connection",
          {"oSSLContext": oSelf, "oException": oException, "sRemoteAddress": "%s:%d" % oPythonSocket.getpeername()},
        );
    fShowDebugOutput("Connection secured.");
    return oPythonSSLSocket;
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    if oSelf.__bServerSide:
      asCertificates = [];
      s0HostName = None;
      for dxPythonCertificateInformation in oSelf.__oPythonSSLContext.get_ca_certs():
        s0OrganizationName = None;
        s0CommonName = None;
        ttsSubjectData = dxPythonCertificateInformation["subject"];
        for ttsData in ttsSubjectData:
          assert len(ttsData) == 1, \
              "Expected a tuple with a single value, got %s" % repr(ttsData);
          (sName, sValue) = ttsData[0];
          if sName == "organizationName":
            s0OrganizationName = sValue;
          elif sName == "commonName":
            s0CommonName = sValue;
            if s0HostName is None:
              s0HostName = s0CommonName;
            else:
              s0CommonName += "(repeat!)" if s0HostName == sValue else "(different!?)"; # Mark additional commonName values
        # Must be in the first certificate!
        assert s0HostName, \
            "First certificate in chain does not contain 'commonName' value! %s" % repr(ttsSubjectData);
        assert s0CommonName or s0OrganizationName, \
            "Python certificate information does not contain 'organizationName' value! %s" % repr(ttsSubjectData);
        sSerialNumber = dxPythonCertificateInformation["serialNumber"];
        asCertificates.append("%s#%s" % (
          ("%s@%s" % (s0CommonName, s0OrganizationName)) if s0CommonName and s0OrganizationName else
              s0CommonName if s0CommonName else
              s0OrganizationName if s0OrganizationName else
              "",
          sSerialNumber
        ));
      if asCertificates:
        sNotes = "certificate chain=%s" % " => ".join(asCertificates);
      else:
        sNotes = "no certificate chain";
    else:
      sNotes = "%d certificate authorities" % len(oSelf.__oPythonSSLContext.get_ca_certs());
    return [s for s in [
      ("hostname=%s" % oSelf.__s0Hostname) if oSelf.__s0Hostname else "NO HOSTNAME",
      "%s side" % ("server" if oSelf.__bServerSide else "client"),
      "checks hostname" if oSelf.__oPythonSSLContext.check_hostname else "DOES NOT CHECK HOSTNAME",
      "UNVERIFIED" if oSelf.__bUnverified else None,
      sNotes,
    ] if s];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));
