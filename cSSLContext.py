import socket, ssl, time;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = lambda fx: fx; # NOP
  fShowDebugOutput = lambda x, s0 = None: x; # NOP

from mNotProvided import \
    fAssertTypes, \
    fxGetFirstProvidedValue, \
    zNotProvided;
from .mExceptions import \
    cSSLCannotGetRemoteCertificateException, \
    cSSLIncorrectHostnameException, \
    cSSLInvaliCertificateChainException, \
    cSSLInvalidCertificateException, \
    cSSLInvalidCertificateExpiredException, \
    cSSLInvalidCertificateRevocationListNotAvailableException, \
    cSSLInvalidHostnameForCertificateException, \
    cSSLInvalidSelfSignedCertificateException, \
    cSSLInvalidSelfSignedCertificateInChainException, \
    cSSLSecureHandshakeException, \
    cSSLSecureTimeoutException, \
    cSSLUnknownCertificateAuthorityException, \
    cSSLWrapSocketException;

gbDebugOutput = True;

class cSSLContext(object):
  n0DefaultSecureTimeoutInSeconds = 5;
  
  @classmethod
  def foForServerWithHostnameAndCertificateFilePath(cClass,
    sbHostname,
    sCertificateFilePath,
  ):
    fAssertTypes({
      "sbHostname": (sbHostname, bytes),
      "sCertificateFilePath": (sCertificateFilePath, str),
    });
    # Server side with everything in one file
    oPythonSSLContextWithoutCheckHostname = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH);
    try:
      oPythonSSLContextWithoutCheckHostname.load_cert_chain(certfile = sCertificateFilePath);
    except FileNotFoundError as oException:
      raise FileNotFoundError(oException.args[0], "Certificate file %s not found!" % (repr(sCertificateFilePath),), *oException.args[2:]);
    return cClass(
      sb0Hostname = sbHostname,
      o0PythonSSLContextWithCheckHostname = None,
      oPythonSSLContextWithoutCheckHostname = oPythonSSLContextWithoutCheckHostname,
      bServerSide = True,
    );
  
  @classmethod
  def foForServerWithHostnameAndKeyAndCertificateFilePath(cClass,
    sbHostname,
    sKeyFilePath,
    sCertificateFilePath,
  ):
    fAssertTypes({
      "sbHostname": (sbHostname, bytes),
      "sKeyFilePath": (sKeyFilePath, str),
      "sCertificateFilePath": (sCertificateFilePath, str),
    });
    # Server side with certificate and private key in separate files
    oPythonSSLContextWithoutCheckHostname = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH);
    try:
      oPythonSSLContextWithoutCheckHostname.load_cert_chain(keyfile = sKeyFilePath, certfile = sCertificateFilePath);
    except FileNotFoundError as oException:
      raise FileNotFoundError(
        oException.args[0],
        "Certificate file %s or key file %s not found!" % (
          repr(sCertificateFilePath),
          repr(sKeyFilePath),
        ),
        *oException.args[2:],
      );
    except ssl.SSLError as oException:
      fShowDebugOutput("Cannot load certificate chain (keyfile = %s, certfile = %s): %s" % \
          (sKeyFilePath, sCertificateFilePath, oException.message));
      oException.message = "Cannot load certificate chain (keyfile = %s, certfile = %s): %s" % \
          (sKeyFilePath, sCertificateFilePath, oException.message);
      raise;
    return cClass(
      sb0Hostname = sbHostname,
      o0PythonSSLContextWithCheckHostname = None,
      oPythonSSLContextWithoutCheckHostname = oPythonSSLContextWithoutCheckHostname,
      bServerSide = True,
    );
  
  @classmethod
  def foForClientWithHostnameAndCertificateFilePath(cClass,
    sbHostname,
    sCertificateFilePath,
  ):
    fAssertTypes({
      "sbHostname": (sbHostname, bytes),
      "sCertificateFilePath": (sCertificateFilePath, str),
    });
    # Client side with key pinning
    try:
      oPythonSSLContextWithCheckHostname = ssl.create_default_context(cafile = sCertificateFilePath);
      oPythonSSLContextWithoutCheckHostname = ssl.create_default_context(cafile = sCertificateFilePath);
    except FileNotFoundError as oException:
      raise FileNotFoundError(oException.args[0], "Certificate file %s not found!" % (repr(sCertificateFilePath),), *oException.args[2:]);
    return cClass(
      sb0Hostname = sbHostname,
      o0PythonSSLContextWithCheckHostname = oPythonSSLContextWithCheckHostname,
      oPythonSSLContextWithoutCheckHostname = oPythonSSLContextWithoutCheckHostname,
      bServerSide = False,
    );
  
  @classmethod
  def foForClientWithHostname(cClass,
    sbHostname,
  ):
    fAssertTypes({
      "sbHostname": (sbHostname, bytes),
    });
    # Client side
    oPythonSSLContextWithCheckHostname = ssl.create_default_context();
    oPythonSSLContextWithoutCheckHostname = ssl.create_default_context();
    oPythonSSLContextWithCheckHostname.check_hostname = True;
    oPythonSSLContextWithoutCheckHostname.check_hostname = False;
    for oPythonSSLContext in (oPythonSSLContextWithCheckHostname, oPythonSSLContextWithoutCheckHostname):
      oPythonSSLContext.load_default_certs();
    return cClass(
      sb0Hostname = sbHostname,
      o0PythonSSLContextWithCheckHostname = oPythonSSLContextWithCheckHostname,
      oPythonSSLContextWithoutCheckHostname = oPythonSSLContextWithoutCheckHostname,
      bServerSide = False,
    );
  
  @classmethod
  def foForClientWithoutVerification(cClass):
    # Client side
    oPythonSSLContextWithoutCheckHostname = ssl._create_unverified_context();
    oPythonSSLContextWithoutCheckHostname.check_hostname = False;
    return cClass(
      sb0Hostname = None,
      o0PythonSSLContextWithCheckHostname = None,
      oPythonSSLContextWithoutCheckHostname = oPythonSSLContextWithoutCheckHostname,
      bServerSide = False,
      bUnverified = True,
    );
  
  @ShowDebugOutput
  def __init__(oSelf,
    *,
    sb0Hostname,
    o0PythonSSLContextWithCheckHostname,
    oPythonSSLContextWithoutCheckHostname,
    bServerSide = False,
    bUnverified = False,
  ):
    fAssertTypes({
      "sb0Hostname": (sb0Hostname, bytes, None),
      "bServerSide": (bServerSide, bool),
      "bUnverified": (bServerSide, bool),
    });
    oSelf.__sb0Hostname = sb0Hostname;
    oSelf.__o0PythonSSLContextWithCheckHostname = o0PythonSSLContextWithCheckHostname;
    oSelf.__oPythonSSLContextWithoutCheckHostname = oPythonSSLContextWithoutCheckHostname;
    oSelf.__s0RootCertificateFilePath = None;
    oSelf.__bServerSide = bServerSide;
    oSelf.__bUnverified = bUnverified;
  
  @property
  def bServerSide(oSelf):
    return oSelf.__bServerSide;
  
  @property
  def bClientSide(oSelf):
    return not oSelf.__bServerSide;
  
  @property
  def sb0Hostname(oSelf):
    return oSelf.__sb0Hostname;
  
  def fAddCertificateAuthority(oSelf,
    oCertificateAuthority,
  ):
    # late import to prevent import loops.
    from .cCertificateAuthority import cCertificateAuthority;
    fAssertTypes({
      "oCertificateAuthority": (oCertificateAuthority, cCertificateAuthority),
    });
    oSelf.__s0RootCertificateFilePath = oCertificateAuthority.fsGetRootCertificateFilePath();
    if oSelf.__o0PythonSSLContextWithCheckHostname:
      oSelf.__o0PythonSSLContextWithCheckHostname.load_verify_locations(oSelf.__s0RootCertificateFilePath);
    oSelf.__oPythonSSLContextWithoutCheckHostname.load_verify_locations(oSelf.__s0RootCertificateFilePath);
  
  @ShowDebugOutput
  def foWrapSocket(oSelf,
    oPythonSocket,
    *,
    n0zTimeoutInSeconds = zNotProvided,
    bzCheckHostname = zNotProvided,
  ):
    fAssertTypes({
      "oPythonSocket": (oPythonSocket, socket.socket),
      "n0zTimeoutInSeconds": (n0zTimeoutInSeconds, int, float, None, zNotProvided),
      "bzCheckHostname": (bzCheckHostname, bool, zNotProvided),
    });
    n0TimeoutInSeconds = fxGetFirstProvidedValue(n0zTimeoutInSeconds, oSelf.n0DefaultSecureTimeoutInSeconds);
    txRemoteAddress = oPythonSocket.getpeername();
    dxDetails = {
      "oSSLContext": oSelf,
      "n0TimeoutInSeconds" : n0TimeoutInSeconds,
      "sRemoteAddress": "%s:%d" % (txRemoteAddress[0], txRemoteAddress[1]),
    };
    if n0TimeoutInSeconds is not None and n0TimeoutInSeconds <= 0:
      raise cSSLSecureTimeoutException(
        "Timeout before socket could be secured.",
        dxDetails = dxDetails,
      );
    n0EndTime = time.time() + n0TimeoutInSeconds if n0TimeoutInSeconds else None;
    bCheckHostname = fxGetFirstProvidedValue(bzCheckHostname, not oSelf.bServerSide);
    if bCheckHostname:
      assert oSelf.__o0PythonSSLContextWithCheckHostname, \
          "Cannot check hostname when using %s" % oSelf;
      oPythonSSLContext = oSelf.__o0PythonSSLContextWithCheckHostname;
    else:
      oPythonSSLContext = oSelf.__oPythonSSLContextWithoutCheckHostname;
    fShowDebugOutput("Wrapping socket%s..." % (" (timeout = %ss)" % n0TimeoutInSeconds if n0TimeoutInSeconds is not None else ""));
    oPythonSocket.settimeout(n0TimeoutInSeconds);
    try:
      oPythonSSLSocket = oPythonSSLContext.wrap_socket(
        sock = oPythonSocket,
        server_side = oSelf.bServerSide,
        server_hostname = None if oSelf.bServerSide else oSelf.sb0Hostname,
        do_handshake_on_connect = False,
      );
    except ssl.SSLError as oException:
      fShowDebugOutput("Exception while wrapping socket in SSL: %s" % repr(oException));
      dxDetails["oException"] = oException;
      raise cSSLWrapSocketException(
        "Could not create secure socket.",
        dxDetails = dxDetails,
      );
    if n0EndTime is not None and time.time() > n0EndTime:
      raise cSSLSecureTimeoutException(
        "Timeout before socket could be secured.",
        dxDetails = dxDetails,
      );
    fShowDebugOutput("Performing handshake...");
    try:
      oPythonSSLSocket.do_handshake();
    except (socket.timeout, TimeoutError):
      raise cSSLSecureTimeoutException(
        "Timeout before socket could be secured.",
        dxDetails = dxDetails,
      );
    except ssl.SSLError as oException:
      fShowDebugOutput("Exception while performing SSL handshake: %s" % repr(oException));
      if gbDebugOutput:
        print("==== EXCEPTION ====");
        for sName in dir(oException):
          if sName.startswith("__"): continue;
          try:
            xValue = getattr(oException, sName);
          except:
            continue;
          print("%s: %s" % (sName, repr(xValue)));
      try:
        dxPeerCertificate = oPythonSSLSocket.getpeercert();
      except ValueError:
        pass;
      else:
        dxDetails["dxPeerCertificate"] = dxPeerCertificate;
        if gbDebugOutput:
          print("==== CERTIFICATE ====");
          for sName in dir(dxPeerCertificate):
            print("%s: %s" % (sName, repr(dxPeerCertificate[sName])));
      if gbDebugOutput:
        print("========");
      if oException.args[1].find("ALERT_UNKNOWN_CA") != -1 or oException.args[1].find("invalid CA certificate") != -1:
        raise cSSLUnknownCertificateAuthorityException(
          "The remote host is using a certificate signed by an unknown Certificate Authority%s" % (
            " for %s" % repr(oSelf.sb0Hostname)[1:] if oSelf.sb0Hostname else "",
          ),
          dxDetails = dxDetails,
        );
      elif oException.reason == "CERTIFICATE_VERIFY_FAILED":
        if oException.verify_code == 3:
          raise cSSLInvalidCertificateRevocationListNotAvailableException(
            "The remote host provided a certificate with a revocation list that is not available%s" % (
              " for %s" % repr(oSelf.sb0Hostname)[1:] if oSelf.sb0Hostname else "",
            ),
            dxDetails = dxDetails,
          );
        if oException.verify_code == 10:
          raise cSSLInvalidCertificateExpiredException(
            "The remote host provided a certificate that is expired%s" % (
              " for %s" % repr(oSelf.sb0Hostname)[1:] if oSelf.sb0Hostname else "",
            ),
            dxDetails = dxDetails,
          );
        if oException.verify_code == 18:
          raise cSSLInvalidSelfSignedCertificateException(
            "The remote host provided a self-signed certificate%s" % (
              " for %s" % repr(oSelf.sb0Hostname)[1:] if oSelf.sb0Hostname else "",
            ),
            dxDetails = dxDetails,
          );
        if oException.verify_code == 19:
          raise cSSLInvalidSelfSignedCertificateInChainException(
            "The remote host provided a self-signed certificate in the certificate chain%s" % (
              " for %s" % repr(oSelf.sb0Hostname)[1:] if oSelf.sb0Hostname else "",
            ),
            dxDetails = dxDetails,
          );
        if oException.verify_code == 20:
          raise cSSLInvaliCertificateChainException(
            "The remote host provided a certificate with an invalid certificate chain%s" % (
              " for %s" % repr(oSelf.sb0Hostname)[1:] if oSelf.sb0Hostname else "",
            ),
            dxDetails = dxDetails,
          );
        if oException.verify_code == 62:
          raise cSSLInvalidHostnameForCertificateException(
            "The remote host provided a certificate that is not valid%s" % (
              " for %s" % repr(oSelf.sb0Hostname)[1:] if oSelf.sb0Hostname else "",
            ),
            dxDetails = dxDetails,
          );
        raise cSSLInvalidCertificateException(
          "The remote host provided an invalid certificate",
          dxDetails = dxDetails,
        );
      dxDetails["oException"] = oException;
      raise cSSLSecureHandshakeException(
        "Could not perform SSL handshake.",
        dxDetails = dxDetails,
      );
    if bCheckHostname:
      fShowDebugOutput("Checking domain name...");
      try:
        oRemoteCertificate = oPythonSSLSocket.getpeercert();
      except ssl.SSLError as oException:
        fShowDebugOutput("Exception while getting remote certificate: %s" % repr(oException));
        dxDetails["oException"] = oException;
        raise cSSLCannotGetRemoteCertificateException(
          "Could not get remote certificate.",
          dxDetails = dxDetails,
        );
      assert oRemoteCertificate, \
          "No certificate!?";
      if n0EndTime is not None and time.time() > n0EndTime:
        raise cSSLSecureTimeoutException(
          "Timeout before socket could be secured.",
          dxDetails = dxDetails,
        );
      try:
        ssl.match_hostname(oRemoteCertificate, str(oSelf.sb0Hostname, "ascii", "strict"));
      except ssl.CertificateError as oException:
        fShowDebugOutput("Exception while matching hostname: %s" % repr(oException));
        dxDetails["oException"] = oException;
        raise cSSLIncorrectHostnameException(
          "The server reported an incorrect domain name for the secure connection",
          dxDetails = dxDetails,
        );
    fShowDebugOutput("Connection secured.");
    return oPythonSSLSocket;
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    adxPythonCertificateInformation  = oSelf.__oPythonSSLContextWithoutCheckHostname.get_ca_certs();
    if oSelf.__bServerSide:
      asCertificates = [];
      s0Hostname = None;
      for dxPythonCertificateInformation in adxPythonCertificateInformation:
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
            if s0Hostname is None:
              s0Hostname = s0CommonName;
            else:
              s0CommonName += "(repeat!)" if s0Hostname == sValue else "(different!?)"; # Mark additional commonName values
        # Must be in the first certificate!
        assert s0Hostname, \
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
      sNotes = "%d certificate authorities" % len(adxPythonCertificateInformation);
    return [s for s in [
      ("hostname=%s" % str(oSelf.__sb0Hostname, "utf-8", "strict")) if oSelf.__sb0Hostname else "NO HOSTNAME",
      "%s side" % ("server" if oSelf.__bServerSide else "client"),
      "UNVERIFIED" if oSelf.__bUnverified else None,
      "root certificate file=%s" % oSelf.__s0RootCertificateFilePath if oSelf.__s0RootCertificateFilePath is not None else None,
      sNotes,
    ] if s];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));

from .mExceptions import acExceptions;
for cException in acExceptions:
  setattr(cSSLContext, cException.__name__, cException);
