import os, subprocess, sys;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = lambda fx: fx; # NOP
  fShowDebugOutput = lambda x, s0 = None: x; # NOP

from mMultiThreading import cLock;
from mNotProvided import fAssertType;

from .cSSLContext import cSSLContext;

# To turn access to data store in multiple variables into a single transaction, we will create locks.
# These locks should only ever be locked for a short time; if it is locked for too long, it is considered a "deadlock"
# bug, where "too long" is defined by the following value:
gnDeadlockTimeoutInSeconds = 30; # We will be accessing files and executing code, so this should suffice.
# Since we can generate these files, we need a lock to prevent race conditions when
# two files want to generate a certificate for the same domain name.
goCertificateFilesLock = cLock(
  "cCertificateAuthority.py/goCertificateFilesLock",
  # If this lock is held for a long enough time while another thread is attempting to acquire it, report an error:
  n0DeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds,
);
guKeySize = 2048;
guCertificateValidityInDays = 28876;

gsMainFolderPath = os.path.dirname(__file__);
gsOpenSSLFolderPath = os.path.join(gsMainFolderPath, "OpenSSL");
assert os.path.isdir(gsOpenSSLFolderPath), \
    "Cannot find OpenSSL folder %s; please download OpenSSL.exe into this folder." % gsOpenSSLFolderPath;
gsOSISA = "x64" if sys.maxsize > 2**32 else "x86";
gsOpenSSLBinaryFolderPath = os.path.join(gsOpenSSLFolderPath, gsOSISA, "bin");
gsOpenSSLBinaryPath = os.path.join(gsOpenSSLBinaryFolderPath, "OpenSSL.exe");
assert os.path.isfile(gsOpenSSLBinaryPath), \
    "Cannot find OpenSSL binary %s; please download OpenSSL.exe into this folder." % gsOpenSSLBinaryPath;

def fExecuteOpenSSL(*tsArguments):
  asCommandLine = [gsOpenSSLBinaryPath] + list(tsArguments);
  fShowDebugOutput("Executing %s..." % " ".join(asCommandLine));
  oProcess = subprocess.Popen(
    args = asCommandLine,
    cwd = gsOpenSSLBinaryFolderPath,
    stdout = subprocess.PIPE,
    stderr = subprocess.PIPE,
  );
  (sbStdOut, sbStdErr) = oProcess.communicate();
  if oProcess.returncode != 0:
    if sbStdOut:
      for sbLine in sbStdOut.split(b"\n"):
        fShowDebugOutput("> %s" % str(sbLine.rstrip(b"\r"), "ascii", "strict"));
    if sbStdErr:
      for sbLine in sbStdErr.split(b"\n"):
        fShowDebugOutput("> %s" % str(sbLine.rstrip(b"\r"), "ascii", "strict"));
    raise AssertionError("%s error:\n%s\n%s\n" % (" ".join(asCommandLine), repr(sbStdOut), repr(sbStdErr)));

dsDatabaseFileInitialContent_by_sName = {
  "database": "",
  "serial": "0000",
};

def fsReadFile(sPath):
  with open(sPath, "r") as oFile:
    return oFile.read();

def fWriteFile(sPath, sContent):
  with open(sPath, "w") as oFile:
    return oFile.write(sContent);

def fsCreateFileIfNeededAndReturnPath(sFilePath, sContent):
  if not os.path.isfile(sFilePath):
    with open(sFilePath, "w") as oFile:
      oFile.write(sContent);
  return sFilePath;

def fsCreateFolderIfNeededAndReturnPath(sFolderPath):
  if not os.path.isdir(sFolderPath):
    os.makedirs(sFolderPath);
  return sFolderPath;

def fDeleteFolderContents(sFolderPath, f0Callback, bDeleteFolder):
  for sFileOrFolderName in os.listdir(sFolderPath):
    sFileOrFolderPath = os.path.join(sFolderPath, sFileOrFolderName);
    if os.path.isfile(sFileOrFolderPath):
      f0Callback(sFileOrFolderPath, True, None);
      os.remove(sFileOrFolderPath);
    else:
      fDeleteFolderContents(sFileOrFolderPath, f0Callback, bDeleteFolder = True);
  if bDeleteFolder:
    f0Callback(sFolderPath + "\\", False, None);
    os.rmdir(sFolderPath);

gsConfigFileTemplate = fsReadFile(os.path.join(gsMainFolderPath, "Template for openssl.conf"))
gsExtensionFileTemplate = fsReadFile(os.path.join(gsMainFolderPath, "Template for openssl.ext"))

class cCertificateAuthority(object):
  @ShowDebugOutput
  def __init__(oSelf, sBaseFolderPath, sAuthorityName = "SkyLined"):
    oSelf.__sBaseFolderPath = sBaseFolderPath;
    oSelf.__sAuthorityName = sAuthorityName;
    
    oSelf.__oCacheLock = cLock("%s.__oCacheLock" % oSelf.__class__.__name__,
        n0DeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds);
    oSelf.__do0CachedSSLContext_by_sbHost = {};
  
  def fDeleteCacheFolder(oSelf, f0Callback = None): # fCallback(sFilePath, bIsFile, s0Content);
    oSelf.__oCacheLock.fAcquire();
    try:
      # Delete all files
      fDeleteFolderContents(oSelf.__sBaseFolderPath, f0Callback, bDeleteFolder = False);
      oSelf.__do0CachedSSLContext_by_sbHost = {};
    finally:
      oSelf.__oCacheLock.fRelease();
  
  def fResetCacheFolder(oSelf, f0Callback = None): # fCallback(sFilePath, bIsFile, s0Content);
    # Delete all generated certificates, except the root certificate and reset the database.
    oSelf.__oCacheLock.fAcquire();
    try:
      sCertificatesFolderPath = oSelf.__fsCreateCertificatesCacheFolderIfNeededAndReturnPath();
      fDeleteFolderContents(sCertificatesFolderPath, f0Callback, bDeleteFolder = False);
      
      sDatabaseFolderPath = oSelf.__fsCreateDatabaseFolderIfNeededAndReturnPath();
      # delete all database files not needed.
      for sDatabaseFileOrFolderName in os.listdir(sDatabaseFolderPath):
        if sDatabaseFileOrFolderName not in dsDatabaseFileInitialContent_by_sName:
          sDatabaseFileOrFolderPath = os.path.join(sDatabaseFolderPath, sDatabaseFileOrFolderName);
          if os.path.isfile(sDatabaseFileOrFolderPath):
            if f0Callback: f0Callback(sDatabaseFilePath, True, None);
            os.remove(sDatabaseFilePath);
          else:
            fDeleteFolderContents(sDatabaseFileOrFolderPath, f0Callback, bDeleteFolder = True);
      # reset all database files that are required.
      for (sDatabaseFileName, sContent) in dsDatabaseFileInitialContent_by_sName.items():
        sDatabaseFilePath = os.path.join(sDatabaseFolderPath, sDatabaseFileName);
        if f0Callback: f0Callback(sDatabaseFilePath, True, sContent);
        fWriteFile(sDatabaseFilePath, sContent);
      oSelf.__do0CachedSSLContext_by_sbHost = {};
    finally:
      oSelf.__oCacheLock.fRelease();
  
  def __fCreateBaseFolderIfNeeded(oSelf):
    return fsCreateFolderIfNeededAndReturnPath(oSelf.__sBaseFolderPath);
  
  def __fsGetCertificateCacheFolderPath(oSelf):
    return os.path.join(oSelf.__sBaseFolderPath, "Certificates");
  def __fsCreateCertificatesCacheFolderIfNeededAndReturnPath(oSelf):
    oSelf.__fCreateBaseFolderIfNeeded();
    return fsCreateFolderIfNeededAndReturnPath(oSelf.__fsGetCertificateCacheFolderPath());
    
  def __fsCreateDatabaseFolderIfNeededAndReturnPath(oSelf):
    oSelf.__fCreateBaseFolderIfNeeded();
    return fsCreateFolderIfNeededAndReturnPath(os.path.join(oSelf.__sBaseFolderPath, "Database"));
    
  def __fsCreateCAConfigFileIfNeededAndReturnPath(oSelf):
    oSelf.__fCreateBaseFolderIfNeeded();
    sFilePath = os.path.join(oSelf.__sBaseFolderPath, "%s CA openssl.conf" % oSelf.__sAuthorityName);
    sContent = gsConfigFileTemplate % {
      "sDatabaseFolderPath": oSelf.__fsCreateDatabaseFolderIfNeededAndReturnPath().replace(os.sep, os.altsep),
    };
    return fsCreateFileIfNeededAndReturnPath(sFilePath, sContent);
  
  def fsGetRootCertificateFilePath(oSelf):
    return oSelf.__ftsCreateCAPrivateKeyAndCertificateFilesIfNeededAndReturnPaths()[1];
  def __ftsCreateCAPrivateKeyAndCertificateFilesIfNeededAndReturnPaths(oSelf):
    oSelf.__fCreateBaseFolderIfNeeded();
    sCAPrivateKeyFilePath = os.path.join(oSelf.__sBaseFolderPath, "%s CA private key.pem" % oSelf.__sAuthorityName);
    if not os.path.isfile(sCAPrivateKeyFilePath):
      fExecuteOpenSSL(
        "genrsa",
        "-out", sCAPrivateKeyFilePath,
        str(guKeySize),
      );
      assert os.path.isfile(sCAPrivateKeyFilePath), \
          "OpenSSL failed to generate CA private key file %s!" % repr(sCAPrivateKeyFilePath);
    
    sCACertificateFilePath = os.path.join(oSelf.__sBaseFolderPath, "%s CA certificate.pem" % oSelf.__sAuthorityName);
    if not os.path.isfile(sCACertificateFilePath):
      fExecuteOpenSSL(
        "req",
        "-new",
        "-x509",
        "-sha256",
        "-days", str(guCertificateValidityInDays),
        "-subj", "/CN=%s Certificate Authority" % (oSelf.__sAuthorityName,),
        "-key", sCAPrivateKeyFilePath,
        "-out", sCACertificateFilePath,
        "-config", oSelf.__fsCreateCAConfigFileIfNeededAndReturnPath(),
      );
      assert os.path.isfile(sCACertificateFilePath), \
          "OpenSSL failed to generate key file %s!" % repr(sCACertificateFilePath);
    return (sCAPrivateKeyFilePath, sCACertificateFilePath);
  
  @ShowDebugOutput
  def fo0GetClientSSLContextForHost(oSelf, sbHost):
    fAssertType("sbHost", sbHost, bytes);
    # Only return a client-side context if this Certificate Authority has a server-side context.
    if not oSelf.fo0GetServersideSSLContextForHost(sbHost):
      return None;
    oSSLContext = cSSLContext.foForClientWithHost(sbHost);
    oSSLContext.fAddCertificateAuthority(oSelf);
    return oSSLContext;
  
  @ShowDebugOutput
  def fo0GetServersideSSLContextForHost(oSelf, sbHost):
    fAssertType("sbHost", sbHost, bytes);
    oSelf.__oCacheLock.fAcquire();
    try:
      if sbHost in oSelf.__do0CachedSSLContext_by_sbHost:
        return oSelf.__do0CachedSSLContext_by_sbHost[sbHost];
      fShowDebugOutput("Loading context for %s from file..." % sbHost);
      goCertificateFilesLock.fAcquire();
      try:
        sCertificatesCacheFolderPath = oSelf.__fsGetCertificateCacheFolderPath();
        sKeyFilePath = os.path.join(sCertificatesCacheFolderPath, "%s private key.pem" % str(sbHost, "ascii", "strict"));
        if not os.path.isfile(sKeyFilePath):
          fShowDebugOutput("Key file not found at %s." % sKeyFilePath);
          oSelf.__do0CachedSSLContext_by_sbHost[sbHost] = None;
          return None;
        sCertificateFilePath = os.path.join(sCertificatesCacheFolderPath, "%s certificate.pem" % str(sbHost, "ascii", "strict"));
        if os.path.isfile(sCertificateFilePath):
          fShowDebugOutput("Certificate file not found at %s." % sCertificateFilePath);
          oSelf.__do0CachedSSLContext_by_sbHost[sbHost] = None;
          return None;
      finally:
        goCertificateFilesLock.fRelease();
      oSSLContext = cSSLContext.foForServerWithHostAndKeyAndCertificateFilePath(
        sbHost, sKeyFilePath, sCertificateFilePath
      );
      oSelf.__do0CachedSSLContext_by_sbHost[sbHost] = oSSLContext;
      return oSSLContext;
    finally:
      oSelf.__oCacheLock.fRelease();
  
  @ShowDebugOutput
  def foGenerateServersideSSLContextForHost(oSelf, sbHost):
    fAssertType("sbHost", sbHost, bytes);
    sHost = str(sbHost, "ascii", "strict");
    oSelf.__oCacheLock.fAcquire();
    try:
      o0SSLContext = oSelf.__do0CachedSSLContext_by_sbHost.get(sbHost);
      if o0SSLContext:
        return o0SSLContext;
      
      goCertificateFilesLock.fAcquire();
      try:
        sCertificatesCacheFolderPath = oSelf.__fsCreateCertificatesCacheFolderIfNeededAndReturnPath();
        sCertificateFilePath = os.path.join(sCertificatesCacheFolderPath, "%s certificate.crt" % sHost);
        sPrivateKeyFilePath = os.path.join(sCertificatesCacheFolderPath, "%s private key.key" % sHost);
        if not os.path.isfile(sCertificateFilePath) or not os.path.isfile(sPrivateKeyFilePath):
          sCertificateSigningRequestFilePath = os.path.join(sCertificatesCacheFolderPath, "%s certificate signing request.crt" % sHost);
          if not os.path.isfile(sCertificateSigningRequestFilePath) or not os.path.isfile(sPrivateKeyFilePath):
            fExecuteOpenSSL(
              "req",
              "-new",
              "-sha256",
              "-nodes",
              "-newkey", "rsa:%d" % guKeySize,
              "-keyout", sPrivateKeyFilePath,
              "-subj", "/CN=%s" % sHost,
              "-out", sCertificateSigningRequestFilePath,
              "-config", oSelf.__fsCreateCAConfigFileIfNeededAndReturnPath(),
            );
            assert os.path.isfile(sPrivateKeyFilePath), \
                "OpenSSL failed to generate private key file %s!" % repr(sPrivateKeyFilePath);
            assert os.path.isfile(sCertificateSigningRequestFilePath), \
                "OpenSSL failed to generate certificate signing request file %s!" % repr(sCertificateSigningRequestFilePath);
          (sCAPrivateKeyFilePath, sCACertificateFilePath) = oSelf.__ftsCreateCAPrivateKeyAndCertificateFilesIfNeededAndReturnPaths()
          sExtensionFilePath = fsCreateFileIfNeededAndReturnPath(
            os.path.join(sCertificatesCacheFolderPath, "%s extension.ext" % sHost),
            gsExtensionFileTemplate % {
              "sHost": sHost,
            }
          );
          fExecuteOpenSSL(
            "x509",
            "-req",
            "-sha256",
            "-days", str(guCertificateValidityInDays),
            "-in", sCertificateSigningRequestFilePath,
            "-CA", sCACertificateFilePath,
            "-CAkey", sCAPrivateKeyFilePath,
            "-CAcreateserial",
            "-out", sCertificateFilePath,
            "-ext", sExtensionFilePath,
          );
          assert os.path.isfile(sCertificateFilePath), \
              "OpenSSL failed to generate key file %s!" % repr(sCertificateFilePath);
      finally:
        goCertificateFilesLock.fRelease();
      fShowDebugOutput("Loading context from file...");
      oSSLContext = cSSLContext.foForServerWithHostAndKeyAndCertificateFilePath(
        sbHost, sPrivateKeyFilePath, sCertificateFilePath
      );
      oSelf.__do0CachedSSLContext_by_sbHost[sbHost] = oSSLContext;
      return oSSLContext;
    finally:
      oSelf.__oCacheLock.fRelease();
  
  def fasGetDetails(oSelf):
    return [
      "name=%s" % repr(oSelf.__sAuthorityName),
      "folder=%s" % repr(oSelf.__sBaseFolderPath),
      "%d cached contexts" % len(oSelf.__do0CachedSSLContext_by_sbHost),
    ];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));

    