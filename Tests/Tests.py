from fTestDependencies import fTestDependencies;
fTestDependencies();

from mDebugOutput import fEnableDebugOutputForClass, fEnableDebugOutputForModule, fTerminateWithException;
try:
  import json, os, sys;
  
  from oConsole import oConsole;
  import mSSL;
  
  for sArgument in sys.argv[1:]:
    if sArgument == "--quick": 
      pass; # Always quick :)
    elif sArgument == "--debug": 
      fEnableDebugOutputForModule(mSSL);
    else:
      raise AssertionError("Unknown argument %s" % sArgument);
  
  oConsole.fOutput("\xFE\xFE\xFE\xFE Resetting oCertificateAuthority... ", sPadding = "\xFE");
  oConsole.fOutput("  oCertificateAuthority = ", str(mSSL.oCertificateAuthority));
  mSSL.oCertificateAuthority.fReset();

  oConsole.fOutput("\xFE\xFE\xFE\xFE Ask oCertificateAuthority to generate cSSLContext for hostname 'test-hostname'...", sPadding = "\xFE");
  oSSLContext = mSSL.oCertificateAuthority.foGenerateSSLContextForServerWithHostname("test-hostname");
  oConsole.fOutput("  oSSLContext = ", str(oSSLContext));

  oConsole.fOutput("\xFE\xFE\xFE\xFE Generate cCertificateStore instance...", sPadding = "\xFE");
  oCertificateStore = mSSL.cCertificateStore();

  oConsole.fOutput("\xFE\xFE\xFE\xFE Add oCertificateAuthority to oCertificateStore...", sPadding = "\xFE");
  oCertificateStore.fAddCertificateAuthority(mSSL.oCertificateAuthority);

  oConsole.fOutput("\xFE\xFE\xFE\xFE Ask oCertificateStore for cSSLContext for hostname 'test-hostname'...", sPadding = "\xFE");
  oSSLContext = oCertificateStore.foGetSSLContextForServerWithHostname("test-hostname");
  oConsole.fPrint("+ Done.");
except Exception as oException:
  fTerminateWithException(oException, bShowStacksForAllThread = True);
