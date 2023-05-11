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

@ShowDebugOutput
def cSSLContext_foWrapSocket(oSelf,
  oPythonSocket,
  *,
  n0zTimeoutInSeconds = zNotProvided,
):
  fAssertTypes({
    "oPythonSocket": (oPythonSocket, socket.socket),
    "n0zTimeoutInSeconds": (n0zTimeoutInSeconds, int, float, None),
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
  fShowDebugOutput("Wrapping socket%s..." % (" (timeout = %ss)" % n0TimeoutInSeconds if n0TimeoutInSeconds is not None else ""));
  try:
    oPythonSocket.settimeout(n0TimeoutInSeconds);
    oPythonSSLSocket = oSelf.oPythonSSLContext.wrap_socket(
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
    if oException.args[1].find("ALERT_UNKNOWN_CA") != -1:
      raise cSSLUnknownCertificateAuthorityException(
        "The remote host is using a certificate signed by an unknown Certificate Authority",
        dxDetails = dxDetails,
      );
    elif oException.args[1].find("invalid CA certificate") != -1:
      raise cSSLUnknownCertificateAuthorityException(
        "The remote host is using a certificate signed by an unknown Certificate Authority",
        dxDetails = dxDetails,
      );
    elif oException.reason == "CERTIFICATE_VERIFY_FAILED":
      if oException.verify_code == 3:
        raise cSSLInvalidCertificateRevocationListNotAvailableException(
          "The remote host provided a certificate with a revocation list that is not available for %s" % repr(oSelf.sb0Hostname)[1:],
          dxDetails = dxDetails,
        );
      if oException.verify_code == 10:
        raise cSSLInvalidCertificateExpiredException(
          "The remote host provided a certificate that is expired for %s" % repr(oSelf.sb0Hostname)[1:],
          dxDetails = dxDetails,
        );
      if oException.verify_code == 18:
        raise cSSLInvalidSelfSignedCertificateException(
          "The remote host provided a self-signed certificate for %s" % repr(oSelf.sb0Hostname)[1:],
          dxDetails = dxDetails,
        );
      if oException.verify_code == 19:
        raise cSSLInvalidSelfSignedCertificateInChainException(
          "The remote host provided a self-signed certificate in the certificate chain for %s" % repr(oSelf.sb0Hostname)[1:],
          dxDetails = dxDetails,
        );
      if oException.verify_code == 20:
        raise cSSLInvaliCertificateChainException(
          "The remote host provided an certificate with an invalid certificate chain for %s" % repr(oSelf.sb0Hostname)[1:],
          dxDetails = dxDetails,
        );
      if oException.verify_code == 62:
        raise cSSLInvalidHostnameForCertificateException(
          "The remote host provided a certificate that is not valid for %s" % repr(oSelf.sb0Hostname)[1:],
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
  if oSelf.oPythonSSLContext.check_hostname:
    if n0EndTime is not None and time.time() > n0EndTime:
      raise cSSLSecureTimeoutException(
        "Timeout before socket could be secured.",
        dxDetails = dxDetails,
      );
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
