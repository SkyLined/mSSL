import json, os, sys;

# Augment the search path to make the test subject a package and have access to its modules folder.
sTestsFolderPath = os.path.dirname(os.path.abspath(__file__));
sMainFolderPath = os.path.dirname(sTestsFolderPath);
sParentFolderPath = os.path.dirname(sMainFolderPath);
sModulesFolderPath = os.path.join(sMainFolderPath, "modules");
asOriginalSysPath = sys.path[:];
sys.path = [sParentFolderPath, sModulesFolderPath] + asOriginalSysPath;
# Load product details
oProductDetailsFile = open(os.path.join(sMainFolderPath, "dxProductDetails.json"), "rb");
try:
  dxProductDetails = json.load(oProductDetailsFile);
finally:
  oProductDetailsFile.close();
# Save the list of names of loaded modules:
asOriginalModuleNames = sys.modules.keys();

__import__(dxProductDetails["sProductName"], globals(), locals(), [], -1);

# Sub-packages should load all modules relative, or they will end up in the global namespace, which means they may get
# loaded by the script importing it if it tries to load a differnt module with the same name. Obviously, that script
# will probably not function when the wrong module is loaded, so we need to check that we did this correctly.
asUnexpectedModules = list(set([
  sModuleName.lstrip("_").split(".", 1)[0] for sModuleName in sys.modules.keys()
  if not (
    sModuleName in asOriginalModuleNames # This was loaded before
    or sModuleName.lstrip("_").split(".", 1)[0] in (
      [dxProductDetails["sProductName"]] +
      dxProductDetails["asDependentOnProductNames"] +
      [
        # This is required
        "mDebugOutput", "mMultiThreading", "mWindowsSDK", 
        # This is optional, not required:
        "oConsole",
        # These built-in modules are expected:
        "base64", "binascii", "cStringIO", "collections", "contextlib",
        "ctypes", "dis", "gc", "heapq", "imp", "inspect", "itertools",
        "keyword", "msvcrt", "opcode", "platform", "Queue", "socket", "ssl",
        "string", "strop", "subprocess", "textwrap", "thread", "threading",
        "time", "token", "tokenize",
      ]
    )
  )
]));
assert len(asUnexpectedModules) == 0, \
      "Module(s) %s was/were unexpectedly loaded!" % ", ".join(sorted(asUnexpectedModules));
for sModuleName in dxProductDetails["asDependentOnProductNames"]:
  assert sModuleName in sys.modules, \
      "%s is listed as a dependency but not loaded by the module!" % sModuleName;

from mDebugOutput import fEnableDebugOutputForModule, fTerminateWithException;
try:
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
