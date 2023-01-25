import os, sys;
sModulePath = os.path.dirname(__file__);
sys.path = [sModulePath] + [sPath for sPath in sys.path if sPath.lower() != sModulePath.lower()];

from fTestDependencies import fTestDependencies;
fTestDependencies("--automatically-fix-dependencies" in sys.argv);
sys.argv = [s for s in sys.argv if s != "--automatically-fix-dependencies"];

try: # mDebugOutput use is Optional
  import mDebugOutput as m0DebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  m0DebugOutput = None;

guExitCodeInternalError = 1; # Use standard value;
try:
  try:
    from mConsole import oConsole;
  except:
    import sys, threading;
    oConsoleLock = threading.Lock();
    class oConsole(object):
      @staticmethod
      def fOutput(*txArguments, **dxArguments):
        sOutput = "";
        for x in txArguments:
          if isinstance(x, str):
            sOutput += x;
        sPadding = dxArguments.get("sPadding");
        if sPadding:
          sOutput.ljust(120, sPadding);
        oConsoleLock.acquire();
        print(sOutput);
        sys.stdout.flush();
        oConsoleLock.release();
      @staticmethod
      def fStatus(*txArguments, **dxArguments):
        pass;
  
  import os, sys;
  
  import mSSL;
  
  bQuick = False;
  bFull = False;
  for sArgument in sys.argv[1:]:
    if sArgument == "--quick": 
      bQuick = True;
    elif sArgument == "--full": 
      bFull = True;
    elif sArgument == "--debug": 
      assert m0DebugOutput, \
          "This feature requires mDebugOutput!";
      m0DebugOutput.fEnableDebugOutputForModule(mSSL);
    else:
      raise AssertionError("Unknown argument %s" % sArgument);
  assert not bQuick or not bFull, \
      "Cannot test both quick and full!";
  
  sbTestHostname = b"test.domain.name";
  sTestHostname = str(sbTestHostname, "ascii", "strict");
  HEADER = 0xFF0A;
  DELETE_FILE = 0xFF0C;
  DELETE_FOLDER = 0xFF04;
  OVERWRITE_FILE = 0xFF0E;
  
  def fShowDeleteOrOverwriteFileOrFolder(sFileOrFolderPath, bFile, s0NewContent):
    if not bFile:
      oConsole.fOutput(DELETE_FOLDER, " - ", sFileOrFolderPath);
    elif s0NewContent is None:
      oConsole.fOutput(DELETE_FILE, " - ", sFileOrFolderPath);
    else:
      oConsole.fOutput(OVERWRITE_FILE, " * ", sFileOrFolderPath, " => %d bytes." % len(s0NewContent));
  
  import tempfile;
  sCertificateAuthorityFolderPath = os.path.join(tempfile.gettempdir(), "tmp");
  
  oCertificateAuthority = mSSL.cCertificateAuthority(sCertificateAuthorityFolderPath, "mSSL Test");
  oConsole.fOutput("  oCertificateAuthority = ", str(oCertificateAuthority));
  if os.path.isdir(sCertificateAuthorityFolderPath):
    if bQuick:
      oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Reset Certificate Authority folder... ", sPadding = "\u2500");
      oCertificateAuthority.fResetCacheFolder(fShowDeleteOrOverwriteFileOrFolder);
    else:
      oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Delete Certificate Authority folder... ", sPadding = "\u2500");
      oCertificateAuthority.fDeleteCacheFolder(fShowDeleteOrOverwriteFileOrFolder);
  
  oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Ask oCertificateAuthority for cSSLContext for '", sTestHostname, "'...", sPadding = "\u2500");
  o0SSLContext = oCertificateAuthority.fo0GetServersideSSLContextForHostname(sbTestHostname);
  assert o0SSLContext is None, \
      "Expected None, got %s" % repr(o0SSLContext);
  
  oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Ask oCertificateAuthority to generate cSSLContext for '", sTestHostname, "'...", sPadding = "\u2500");
  oSSLContext = oCertificateAuthority.foGenerateServersideSSLContextForHostname(sbTestHostname);
  oConsole.fOutput("  oSSLContext = ", str(oSSLContext));
  
  oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Resetting oCertificateAuthority... ", sPadding = "\u2500");
  oConsole.fOutput("  oCertificateAuthority = ", str(oCertificateAuthority));
  oCertificateAuthority.fResetCacheFolder(fShowDeleteOrOverwriteFileOrFolder);
  oConsole.fOutput("  oCertificateAuthority = ", str(oCertificateAuthority));
  
  oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Ask oCertificateAuthority for cSSLContext for '", sTestHostname, "'...", sPadding = "\u2500");
  o0SSLContext = oCertificateAuthority.fo0GetServersideSSLContextForHostname(sbTestHostname);
  assert o0SSLContext is None, \
      "Expected None, go %s" % repr(o0SSLContext);
  
  oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Ask oCertificateAuthority to generate cSSLContext for '", sTestHostname, "'...", sPadding = "\u2500");
  oSSLContext = oCertificateAuthority.foGenerateServersideSSLContextForHostname(sbTestHostname);
  oConsole.fOutput("  oSSLContext = ", str(oSSLContext));
  
  oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Generate cCertificateStore instance...", sPadding = "\u2500");
  oCertificateStore = mSSL.cCertificateStore();
  
  oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Add oCertificateAuthority to oCertificateStore...", sPadding = "\u2500");
  oCertificateStore.fAddCertificateAuthority(oCertificateAuthority);
  
  oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Ask oCertificateStore for cSSLContext for '", sTestHostname, "'...", sPadding = "\u2500");
  oSSLContext = oCertificateStore.foGetServersideSSLContextForHostname(sbTestHostname);
  
  if not bQuick:
    oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Delete Certificate Authority folder... ", sPadding = "\u2500");
    oCertificateAuthority.fDeleteCacheFolder(fShowDeleteOrOverwriteFileOrFolder);
  
  oConsole.fOutput("+ Done.");
  
except Exception as oException:
  if m0DebugOutput:
    m0DebugOutput.fTerminateWithException(oException, guExitCodeInternalError, bShowStacksForAllThread = True);
  raise;
