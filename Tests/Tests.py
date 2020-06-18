from fTestDependencies import fTestDependencies;
fTestDependencies();

try:
  import mDebugOutput;
except:
  mDebugOutput = None;
try:
  try:
    from oConsole import oConsole;
  except:
    import sys, threading;
    oConsoleLock = threading.Lock();
    class oConsole(object):
      @staticmethod
      def fOutput(*txArguments, **dxArguments):
        sOutput = "";
        for x in txArguments:
          if isinstance(x, (str, unicode)):
            sOutput += x;
        sPadding = dxArguments.get("sPadding");
        if sPadding:
          sOutput.ljust(120, sPadding);
        oConsoleLock.acquire();
        print sOutput;
        sys.stdout.flush();
        oConsoleLock.release();
      fPrint = fOutput;
      @staticmethod
      def fStatus(*txArguments, **dxArguments):
        pass;
  
  import json, os, sys;
  
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
  
  oConsole.fOutput("\xFE\xFE\xFE\xFE Cleaning Certificate Authority folder... ", sPadding = "\xFE");
  mSSL.oCertificateAuthority.fClean();
  
  oConsole.fPrint("+ Done.");
  
except Exception as oException:
  if mDebugOutput:
    mDebugOutput.fTerminateWithException(oException, bShowStacksForAllThread = True);
  raise;
