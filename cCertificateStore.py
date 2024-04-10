from mNotProvided import fAssertType;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = lambda fx: fx; # NOP
  fShowDebugOutput = lambda x, s0 = None: x; # NOP

from .cSSLContext import cSSLContext;

class cCertificateStore(object):
  __o0SSLContextForClientWithoutVerification = None; # will be initialized later when  needed
    
  @ShowDebugOutput
  def __init__(oSelf):
    oSelf.__aoCertificateAuthorities = [];
    oSelf.__dsCertificateFilePath_by_sbHost = {};
    oSelf.__dsPrivateKeyFilePath_by_sbHost = {};
    oSelf.__doSSLContextForClient_by_sbHost = {};
    oSelf.__doSSLContextForServer_by_sbHost = {};
  
  @ShowDebugOutput
  def fAddCertificateAuthority(oSelf, oCertificateAuthority):
    assert (
      not oSelf.__doSSLContextForClient_by_sbHost
      and not oSelf.__doSSLContextForServer_by_sbHost
    ), \
        "Cannot add CAs after creating SSLContexts";
    oSelf.__aoCertificateAuthorities.append(oCertificateAuthority);
  
  @ShowDebugOutput
  def fAddCertificateFilePathForHost(oSelf, sbHost, sCertificateFilePath):
    fAssertType("sbHost", sbHost, bytes);
    fAssertType("sCertificateFilePath", sCertificateFilePath, str);
    oSelf.__dsCertificateFilePath_by_sbHost[sbHost] = sCertificateFilePath;
  
  @ShowDebugOutput
  def fAddCertificateAndKeyFilePathsForHost(oSelf, sbHost, sCertificateFilePath, sKeyFilePath):
    fAssertType("sbHost", sbHost, bytes);
    fAssertType("sCertificateFilePath", sCertificateFilePath, str);
    fAssertType("sKeyFilePath", sKeyFilePath, str);
    oSelf.__dsCertificateFilePath_by_sbHost[sbHost] = sCertificateFilePath;
    oSelf.__dsPrivateKeyFilePath_by_sbHost[sbHost] = sKeyFilePath;
  
  @ShowDebugOutput
  def foAddSSLContextForServerWithHost(oSelf, oSSLContext, sbHost):
    fAssertType("sbHost", sbHost, bytes);
    assert sbHost not in oSelf.__doSSLContextForServer_by_sbHost, \
        "Cannot add two SSL contexts for the same host (%s)" % sbHost;
    oSelf.__doSSLContextForServer_by_sbHost[sbHost] = oSSLContext;
  
  @ShowDebugOutput
  def foGetServersideSSLContextForHost(oSelf, sbHost):
    fAssertType("sbHost", sbHost, bytes);
    o0SSLContext = oSelf.__doSSLContextForServer_by_sbHost.get(sbHost);
    if o0SSLContext is not None:
      oSSLContext = o0SSLContext;
    else:
      sCertificateFilePath = oSelf.__dsCertificateFilePath_by_sbHost.get(sbHost);
      if sCertificateFilePath:
        sKeyFilePath = oSelf.__dsPrivateKeyFilePath_by_sbHost.get(sbHost);
        if sKeyFilePath:
          oSSLContext = cSSLContext.foForServerWithHostAndKeyAndCertificateFilePath(sbHost, sKeyFilePath, sCertificateFilePath);
        else:
          oSSLContext = cSSLContext.foForServerWithHostAndCertificateFilePath(sbHost, sCertificateFilePath);
      else:
        for oCertificateAuthority in oSelf.__aoCertificateAuthorities:
          o0SSLContext = oCertificateAuthority.fo0GetServersideSSLContextForHost(sbHost);
          if o0SSLContext is not None:
            oSSLContext = o0SSLContext;
            break;
        else:
          raise AssertionError("No certificate exists for host %s; please create one using a cCertificateAuthority instance." % sbHost);
      oSelf.__doSSLContextForServer_by_sbHost[sbHost] = oSSLContext;
      for oCertificateAuthority in oSelf.__aoCertificateAuthorities:
        oSSLContext.fAddCertificateAuthority(oCertificateAuthority);
    return oSSLContext;
  
  @ShowDebugOutput
  def foGetClientsideSSLContextWithoutVerification(oSelf):
    if oSelf.__o0SSLContextForClientWithoutVerification is None:
      oSelf.__o0SSLContextForClientWithoutVerification = cSSLContext.foForClientWithoutVerification();
    return oSelf.__o0SSLContextForClientWithoutVerification;
    
  @ShowDebugOutput
  def foGetClientsideSSLContextForHost(oSelf,
    sbHost,
  ):
    fAssertType("sbHost", sbHost, bytes);
    oSSLContext = oSelf.__doSSLContextForClient_by_sbHost.get(sbHost);
    if not oSSLContext:
      sCertificateFilePath = oSelf.__dsCertificateFilePath_by_sbHost.get(sbHost);
      if sCertificateFilePath:
        oSSLContext = cSSLContext.foForClientWithHostAndCertificateFilePath(
          sbHost,
          sCertificateFilePath,
        );
      else:
        oSSLContext = cSSLContext.foForClientWithHost(
          sbHost,
        );
      oSelf.__doSSLContextForClient_by_sbHost[sbHost] = oSSLContext;
      for oCertificateAuthority in oSelf.__aoCertificateAuthorities:
        oSSLContext.fAddCertificateAuthority(oCertificateAuthority);
    return oSSLContext;
  
  def fasGetDetails(oSelf):
    return [
      "%d CAs" % len(oSelf.__aoCertificateAuthorities),
      "%d certs" % len(oSelf.__dsCertificateFilePath_by_sbHost),
      "%d keys" % len(oSelf.__dsPrivateKeyFilePath_by_sbHost),
      "%d client contexts" % len(oSelf.__doSSLContextForClient_by_sbHost),
      "%d server contexts" % len(oSelf.__doSSLContextForServer_by_sbHost),
    ];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));
