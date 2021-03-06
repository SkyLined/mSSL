from .cSSLContext import cSSLContext;

try: # mDebugOutput use is Optional
  from mDebugOutput import *;
except: # Do nothing if not available.
  ShowDebugOutput = lambda fxFunction: fxFunction;
  fShowDebugOutput = lambda sMessage: None;
  fEnableDebugOutputForModule = lambda mModule: None;
  fEnableDebugOutputForClass = lambda cClass: None;
  fEnableAllDebugOutput = lambda: None;
  cCallStack = fTerminateWithException = fTerminateWithConsoleOutput = None;

class cCertificateStore(object):
  __oSSLContextForClientWithoutVerification = cSSLContext.foForClientWithoutVerification();
  
  @ShowDebugOutput
  def __init__(oSelf):
    oSelf.__aoCertificateAuthorities = [];
    oSelf.__dsCertificateFilePath_by_sHostname = {};
    oSelf.__dsKeyFilePath_by_sHostname = {};
    oSelf.__doSSLContextWithCheckHostnameForClient_by_sHostname = {};
    oSelf.__doSSLContextWithoutCheckHostnameForClient_by_sHostname = {};
    oSelf.__doSSLContextForServer_by_sHostname = {};
  
  @ShowDebugOutput
  def fAddCertificateAuthority(oSelf, oCertificateAuthority):
    assert (
      not oSelf.__doSSLContextWithCheckHostnameForClient_by_sHostname
      and not oSelf.__doSSLContextWithoutCheckHostnameForClient_by_sHostname
      and not oSelf.__doSSLContextForServer_by_sHostname
    ), \
        "Cannot add CAs after creating SSLContexts";
    oSelf.__aoCertificateAuthorities.append(oCertificateAuthority);
  
  @ShowDebugOutput
  def fAddCertificateFilePathForHostname(sHostname, sCertificateFilePath):
    oSelf.__dsCertificateFilePath_by_sHostname[sHostname] = sCertificateFilePath;
  
  @ShowDebugOutput
  def fAddCertificateAndKeyFilePathsForHostname(sHostname, sCertificateFilePath, sKeyFilePath):
    oSelf.__dsCertificateFilePath_by_sHostname[sHostname] = sCertificateFilePath;
    oSelf.__dsKeyFilePath_by_sHostname[sHostname] = sKeyFilePath;

  @ShowDebugOutput
  def foAddSSLContextForServerWithHostname(oSelf, oSSLContext, sHostname):
    assert sHostname not in oSelf.__doSSLContextForServer_by_sHostname, \
        "Cannot add two SSL contexts for the same server (%s)" % sHostname;
    oSelf.__doSSLContextForServer_by_sHostname[sHostname] = oSSLContext;
  
  @ShowDebugOutput
  def foGetServersideSSLContextForHostname(oSelf, sHostname):
    oSSLContext = oSelf.__doSSLContextForServer_by_sHostname.get(sHostname);
    if not oSSLContext:
      sCertificateFilePath = oSelf.__dsCertificateFilePath_by_sHostname.get(sHostname);
      if sCertificateFilePath:
        sKeyFilePath = oSelf.__dsKeyFilePath_by_sHostname.get(sHostname);
        if sKeyFilePath:
          oSSLContext = cSSLContext.foForServerWithHostnameAndKeyAndCertificateFilePath(sHostname, sKeyFilePath, sCertificateFilePath);
        else:
          oSSLContext = cSSLContext.foForServerWithHostnameAndCertificateFilePath(sHostname, sCertificateFilePath);
      else:
        for oCertificateAuthority in oSelf.__aoCertificateAuthorities:
          oSSLContext = oCertificateAuthority.foGetServersideSSLContextForHostname(sHostname);
          if oSSLContext:
            break;
        else:
          raise AssertionError("No certificate file exists for %s and no Certificate Authority can create one." % sHostname);
      oSelf.__doSSLContextForServer_by_sHostname[sHostname] = oSSLContext;
      for oCertificateAuthority in oSelf.__aoCertificateAuthorities:
        oSSLContext.fAddCertificateAuthority(oCertificateAuthority);
    return oSSLContext;
  
  @ShowDebugOutput
  def foGetClientsideSSLContextWithoutVerification(oSelf):
    return oSelf.__oSSLContextForClientWithoutVerification;
    
  @ShowDebugOutput
  def foGetClientsideSSLContextForHostname(oSelf, sHostname, bCheckHostname):
    doSSLContextForClient_by_sHostname = (
      oSelf.__doSSLContextWithCheckHostnameForClient_by_sHostname
      if bCheckHostname else
      oSelf.__doSSLContextWithoutCheckHostnameForClient_by_sHostname
    );
    
    oSSLContext = doSSLContextForClient_by_sHostname.get(sHostname);
    if not oSSLContext:
      sCertificateFilePath = oSelf.__dsCertificateFilePath_by_sHostname.get(sHostname);
      if sCertificateFilePath:
        oSSLContext = cSSLContext.foForClientWithHostnameAndCertificateFilePath(sHostname, sCertificateFilePath);
      else:
        oSSLContext = cSSLContext.foForClientWithHostname(sHostname);
      doSSLContextForClient_by_sHostname[sHostname] = oSSLContext;
      for oCertificateAuthority in oSelf.__aoCertificateAuthorities:
        oSSLContext.fAddCertificateAuthority(oCertificateAuthority);
    return oSSLContext;
