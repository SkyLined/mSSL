from mNotProvided import *;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = fShowDebugOutput = lambda x: x; # NOP

from .cSSLContext import cSSLContext;

class cCertificateStore(object):
  __oSSLContextForClientWithoutVerification = cSSLContext.foForClientWithoutVerification();
  
  @ShowDebugOutput
  def __init__(oSelf):
    oSelf.__aoCertificateAuthorities = [];
    oSelf.__dsCertificateFilePath_by_sbHostname = {};
    oSelf.__dsPrivateKeyFilePath_by_sbHostname = {};
    oSelf.__doSSLContextWithCheckHostnameForClient_by_sbHostname = {};
    oSelf.__doSSLContextWithoutCheckHostnameForClient_by_sbHostname = {};
    oSelf.__doSSLContextForServer_by_sbHostname = {};
  
  @ShowDebugOutput
  def fAddCertificateAuthority(oSelf, oCertificateAuthority):
    assert (
      not oSelf.__doSSLContextWithCheckHostnameForClient_by_sbHostname
      and not oSelf.__doSSLContextWithoutCheckHostnameForClient_by_sbHostname
      and not oSelf.__doSSLContextForServer_by_sbHostname
    ), \
        "Cannot add CAs after creating SSLContexts";
    oSelf.__aoCertificateAuthorities.append(oCertificateAuthority);
  
  @ShowDebugOutput
  def fAddCertificateFilePathForHostname(sbHostname, sCertificateFilePath):
    fAssertType("sbHostname", sbHostname, bytes);
    fAssertType("sCertificateFilePath", sCertificateFilePath, str);
    oSelf.__dsCertificateFilePath_by_sbHostname[sbHostname] = sCertificateFilePath;
  
  @ShowDebugOutput
  def fAddCertificateAndKeyFilePathsForHostname(sbHostname, sCertificateFilePath, sKeyFilePath):
    fAssertType("sbHostname", sbHostname, bytes);
    fAssertType("sCertificateFilePath", sCertificateFilePath, str);
    fAssertType("sKeyFilePath", sKeyFilePath, str);
    oSelf.__dsCertificateFilePath_by_sbHostname[sbHostname] = sCertificateFilePath;
    oSelf.__dsPrivateKeyFilePath_by_sbHostname[sbHostname] = sKeyFilePath;
  
  @ShowDebugOutput
  def foAddSSLContextForServerWithHostname(oSelf, oSSLContext, sbHostname):
    fAssertType("sbHostname", sbHostname, bytes);
    assert sbHostname not in oSelf.__doSSLContextForServer_by_sbHostname, \
        "Cannot add two SSL contexts for the same domain name (%s)" % sbHostname;
    oSelf.__doSSLContextForServer_by_sbHostname[sbHostname] = oSSLContext;
  
  @ShowDebugOutput
  def foGetServersideSSLContextForHostname(oSelf, sbHostname):
    fAssertType("sbHostname", sbHostname, bytes);
    o0SSLContext = oSelf.__doSSLContextForServer_by_sbHostname.get(sbHostname);
    if o0SSLContext is not None:
      oSSLContext = o0SSLContext;
    else:
      sCertificateFilePath = oSelf.__dsCertificateFilePath_by_sbHostname.get(sbHostname);
      if sCertificateFilePath:
        sKeyFilePath = oSelf.__dsPrivateKeyFilePath_by_sbHostname.get(sbHostname);
        if sKeyFilePath:
          oSSLContext = cSSLContext.foForServerWithHostnameAndKeyAndCertificateFilePath(sbHostname, sKeyFilePath, sCertificateFilePath);
        else:
          oSSLContext = cSSLContext.foForServerWithHostnameAndCertificateFilePath(sbHostname, sCertificateFilePath);
      else:
        for oCertificateAuthority in oSelf.__aoCertificateAuthorities:
          o0SSLContext = oCertificateAuthority.fo0GetServersideSSLContextForHostname(sbHostname);
          if o0SSLContext is not None:
            oSSLContext = o0SSLContext;
            break;
        else:
          raise AssertionError("No certificate exists for domain %s; please create one using a cCertificateAuthority instance." % sbHostname);
      oSelf.__doSSLContextForServer_by_sbHostname[sbHostname] = oSSLContext;
      for oCertificateAuthority in oSelf.__aoCertificateAuthorities:
        oSSLContext.fAddCertificateAuthority(oCertificateAuthority);
    return oSSLContext;
  
  @ShowDebugOutput
  def foGetClientsideSSLContextWithoutVerification(oSelf):
    return oSelf.__oSSLContextForClientWithoutVerification;
    
  @ShowDebugOutput
  def foGetClientsideSSLContextForHostname(oSelf, sbHostname, bCheckHostname = True):
    fAssertType("sbHostname", sbHostname, bytes);
    doSSLContextForClient_by_sbHostname = (
      oSelf.__doSSLContextWithCheckHostnameForClient_by_sbHostname
      if bCheckHostname else
      oSelf.__doSSLContextWithoutCheckHostnameForClient_by_sbHostname
    );
    
    oSSLContext = doSSLContextForClient_by_sbHostname.get(sbHostname);
    if not oSSLContext:
      sCertificateFilePath = oSelf.__dsCertificateFilePath_by_sbHostname.get(sbHostname);
      if sCertificateFilePath:
        oSSLContext = cSSLContext.foForClientWithHostnameAndCertificateFilePath(sbHostname, sCertificateFilePath);
      else:
        oSSLContext = cSSLContext.foForClientWithHostname(sbHostname);
      doSSLContextForClient_by_sbHostname[sbHostname] = oSSLContext;
      for oCertificateAuthority in oSelf.__aoCertificateAuthorities:
        oSSLContext.fAddCertificateAuthority(oCertificateAuthority);
    return oSSLContext;
  
  def fasGetDetails(oSelf):
    return [
      "%d CAs" % len(oSelf.__aoCertificateAuthorities),
      "%d certs" % len(oSelf.__dsCertificateFilePath_by_sbHostname),
      "%d keys" % len(oSelf.__dsPrivateKeyFilePath_by_sbHostname),
      "%d client contexts (%d unchecked)" % (
        len(oSelf.__doSSLContextWithCheckHostnameForClient_by_sbHostname) + len(oSelf.__doSSLContextWithoutCheckHostnameForClient_by_sbHostname),
        len(oSelf.__doSSLContextWithoutCheckHostnameForClient_by_sbHostname),
      ),
      "%d server contexts" % len(oSelf.__doSSLContextForServer_by_sbHostname),
    ];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));
