import ssl;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = lambda fx: fx; # NOP
  fShowDebugOutput = lambda x, s0 = None: x; # NOP

from mNotProvided import \
  fAssertTypes;

class cSSLContext(object):
  n0DefaultSecureTimeoutInSeconds = 5;
  
  @classmethod
  def foForServerWithHostnameAndCertificateFilePath(cClass,
    sbHostname,
    sCertificateFilePath,
  ):
    fAssertTypes({
      "sbHostname": s(bHostname, bytes),
      "sCertificateFilePath": (sCertificateFilePath, str),
    });
    # Server side with everything in one file
    oPythonSSLContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH);
    try:
      oPythonSSLContext.load_cert_chain(certfile = sCertificateFilePath);
    except FileNotFoundError as oException:
      raise FileNotFoundError(oException.args[0], "Certificate file %s not found!" % (repr(sCertificateFilePath),), *oException.args[2:]);
    return cClass(sbHostname, oPythonSSLContext, bServerSide = True);
  
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
    oPythonSSLContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH);
    try:
      oPythonSSLContext.load_cert_chain(keyfile = sKeyFilePath, certfile = sCertificateFilePath);
    except FileNotFoundError as oException:
      raise FileNotFoundError(oException.args[0], "Certificate file %s or key file %s not found!" % (repr(sCertificateFilePath), repr(sKeyFilePath)), *oException.args[2:]);
    except ssl.SSLError as oException:
      fShowDebugOutput("Cannot load certificate chain (keyfile = %s, certfile = %s): %s" % \
          (sKeyFilePath, sCertificateFilePath, oException.message));
      oException.message = "Cannot load certificate chain (keyfile = %s, certfile = %s): %s" % \
          (sKeyFilePath, sCertificateFilePath, oException.message);
      raise;
    return cClass(sbHostname, oPythonSSLContext, bServerSide = True);
  
  @classmethod
  def foForClientWithHostnameAndCertificateFilePath(cClass,
    sbHostname,
    sCertificateFilePath,
    *,
    bCheckHostname = True,
  ):
    fAssertTypes({
      "sbHostname": (sbHostname, bytes),
      "sCertificateFilePath": (sCertificateFilePath, str),
      "bCheckHostname": (bCheckHostname, bool),
    });
    # Client side with key pinning
    try:
      oPythonSSLContext = ssl.create_default_context(cafile = sCertificateFilePath);
    except FileNotFoundError as oException:
      raise FileNotFoundError(oException.args[0], "Certificate file %s not found!" % (repr(sCertificateFilePath),), *oException.args[2:]);
    oPythonSSLContext.verify_mode = ssl.CERT_REQUIRED;
    oPythonSSLContext.check_hostname = bCheckHostname;
    return cClass(sbHostname, oPythonSSLContext, bServerSide = False);
  
  @classmethod
  def foForClientWithHostname(cClass,
    sbHostname,
    *,
    bCheckHostname = True,
  ):
    fAssertTypes({
      "sbHostname": (sbHostname, bytes),
      "bCheckHostname": (bCheckHostname, bool),
    });
    # Client side
    oPythonSSLContext = ssl.create_default_context();
    oPythonSSLContext.load_default_certs();
    oPythonSSLContext.verify_mode = ssl.CERT_REQUIRED;
    oPythonSSLContext.check_hostname = bCheckHostname;
    return cClass(sbHostname, oPythonSSLContext, bServerSide = False);
  
  @classmethod
  def foForClientWithoutVerification(cClass):
    # Client side
    oPythonSSLContext = ssl._create_unverified_context();
    return cClass(
      sb0Hostname = None,
      oPythonSSLContext = oPythonSSLContext,
      bServerSide = False,
      bUnverified = True,
    );
  
  @ShowDebugOutput
  def __init__(oSelf,
    sb0Hostname,
    oPythonSSLContext,
    *,
    bServerSide = False,
    bUnverified = False,
  ):
    fAssertTypes({
      "sb0Hostname": (sb0Hostname, bytes, None),
      "bServerSide": (bServerSide, bool),
      "bUnverified": (bServerSide, bool),
    });
    oSelf.__sb0Hostname = sb0Hostname;
    oSelf.__oPythonSSLContext = oPythonSSLContext;
    oSelf.__s0RootCertificateFilePath = None;
    oSelf.__bServerSide = bServerSide;
    oSelf.__bUnverified = bUnverified;
  
  @property
  def oPythonSSLContext(oSelf):
    # For use with "regular" Python code that doesn't accept cSSLContext instances.
    # Please try to avoid using this, as it defeats the purpose of having this class.
    return oSelf.__oPythonSSLContext;
  
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
    oSelf.__oPythonSSLContext.load_verify_locations(oSelf.__s0RootCertificateFilePath);
  
  from .cSSLContext_foWrapSocket import cSSLContext_foWrapSocket as foWrapSocket;
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    if oSelf.__bServerSide:
      asCertificates = [];
      s0Hostname = None;
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
      sNotes = "%d certificate authorities" % len(oSelf.__oPythonSSLContext.get_ca_certs());
    return [s for s in [
      ("hostname=%s" % str(oSelf.__sb0Hostname, "utf-8", "strict")) if oSelf.__sb0Hostname else "NO HOSTNAME",
      "%s side" % ("server" if oSelf.__bServerSide else "client"),
      "checks domain name" if oSelf.__oPythonSSLContext.check_hostname else "DOES NOT CHECK DOMAIN NAME",
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
