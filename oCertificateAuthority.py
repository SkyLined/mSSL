import os, subprocess;

try: # mDebugOutput use is Optional
  from mDebugOutput import *;
except: # Do nothing if not available.
  ShowDebugOutput = lambda fxFunction: fxFunction;
  fShowDebugOutput = lambda sMessage: None;
  fEnableDebugOutputForModule = lambda mModule: None;
  fEnableDebugOutputForClass = lambda cClass: None;
  fEnableAllDebugOutput = lambda: None;
  cCallStack = fTerminateWithException = fTerminateWithConsoleOutput = None;

from .cSSLContext import cSSLContext;

from mMultiThreading import cLock;

gsMainFolderPath = os.path.dirname(__file__);
# To turn access to data store in multiple variables into a single transaction, we will create locks.
# These locks should only ever be locked for a short time; if it is locked for too long, it is considered a "deadlock"
# bug, where "too long" is defined by the following value:
gnDeadlockTimeoutInSeconds = 30; # We will be accessing files and executing code, so this should suffice.
# Since we can generate these files, we need a lock to prevent race conditions when
# two files want to generate a certificate for the same hostname.
goCertificateFilesLock = cLock(
  "cCertificateAuthority.py/goCertificateFilesLock",
  # If this lock is held for a long enough time while another thread is attempting to acquire it, report an error:
  nzDeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds,
);

dGeneratedCertificatesDatabaseFile_sResetContent_by_sName = {
  "intermediate-database": "",
  "intermediate-serial": "0000",
};

class cCertificateAuthority(object):
  __sOpenSSLFolderPath = os.path.join(gsMainFolderPath, "OpenSSL");
  __sOpenSSLBinaryPath = os.path.join(__sOpenSSLFolderPath, "OpenSSL.exe");
  
  __sOpenSSLCertificateAuthorityFolderPath = os.path.join(gsMainFolderPath, "CA");
  __sOpenSSLIntermediateConfigFilePath = os.path.join(__sOpenSSLCertificateAuthorityFolderPath, "intermediate.conf");
  __sOpenSSLCACertificatesFilePath = os.path.join(__sOpenSSLCertificateAuthorityFolderPath, "root+intermediate.cert.pem");
  
  __sGeneratedCertificatesDatabaseFolderPath = os.path.join(gsMainFolderPath, "Database");
  
  @ShowDebugOutput
  def __init__(oSelf):
    assert os.path.isdir(oSelf.__sOpenSSLFolderPath), \
        "Cannot find OpenSSL folder %s; please download OpenSSL.exe into this folder." % oSelf.__sOpenSSLFolderPath;
    assert os.path.isfile(oSelf.__sOpenSSLBinaryPath), \
        "Cannot find OpenSSL binary %s; please download OpenSSL.exe into this folder." % oSelf.__sOpenSSLBinaryPath;
    
    assert os.path.isdir(oSelf.__sOpenSSLCertificateAuthorityFolderPath), \
        "Cannot find OpenSSL Certificate Authority folder %s" % oSelf.__sOpenSSLCertificateAuthorityFolderPath;
    assert os.path.isfile(oSelf.__sOpenSSLIntermediateConfigFilePath), \
        "Cannot find OpenSSL intermediate config file %s" % oSelf.__sOpenSSLIntermediateConfigFilePath;
    assert os.path.isfile(oSelf.__sOpenSSLCACertificatesFilePath), \
        "Cannot find OpenSSL CA Certificates file %s" % oSelf.__sOpenSSLCACertificatesFilePath;
    
    oSelf.__oCacheLock = cLock("%s.__oCacheLock" % oSelf.__class__.__name__,
        nzDeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds);
    oSelf.__doCachedSSLContext_by_sHostname = {};
    
    if not os.path.isdir(oSelf.__sGeneratedCertificatesDatabaseFolderPath):
      os.mkdir(oSelf.__sGeneratedCertificatesDatabaseFolderPath);
      oSelf.fReset();
  
  def fReset(oSelf):
    # delete everything not needed.
    for sFileName in os.listdir(oSelf.__sGeneratedCertificatesDatabaseFolderPath):
      if sFileName not in dGeneratedCertificatesDatabaseFile_sResetContent_by_sName:
        sFilePath = os.path.join(oSelf.__sGeneratedCertificatesDatabaseFolderPath, sFileName);
        os.remove(sFilePath);
    # reset everything required.
    for (sFileName, sContent) in dGeneratedCertificatesDatabaseFile_sResetContent_by_sName.items():
      sFilePath = os.path.join(oSelf.__sGeneratedCertificatesDatabaseFolderPath, sFileName);
      oFile = open(sFilePath, "wb");
      oFile.write(sContent);
      oFile.close();
    
# This has been deleted but assuming it is still used somewhere, it is kept for
# future reference.
#  @property
#  def sCertificatePath(oSelf):
#    return oSelf.__sOpenSSLCACertificatesFolderPath;
  
  def fVerifyPythonSSLContext(oSelf, oPythonSSLContext):
    oPythonSSLContext.load_verify_locations(oSelf.__sOpenSSLCACertificatesFilePath);
  
  def __fExecuteOpenSSL(oSelf, *tsArguments):
    asCommandLine = [
      sComponent if " " not in sComponent else '"%s"' % sComponent
      for sComponent in [oSelf.__sOpenSSLBinaryPath] + list(tsArguments)
    ];
    fShowDebugOutput("Executing %s..." % " ".join(asCommandLine));
    oProcess = subprocess.Popen(
      args = asCommandLine,
      cwd = oSelf.__sOpenSSLFolderPath,
      stdout = subprocess.PIPE,
      stderr = subprocess.PIPE,
    );
    (sStdOut, sStdErr) = oProcess.communicate();
    if oProcess.returncode != 0:
      if sStdOut:
        for sLine in sStdOut.split("\n"):
          fShowDebugOutput("> %s" % sLine.rstrip("\r"));
      if sStdErr:
        for sLine in sStdErr.split("\n"):
          fShowDebugOutput("> %s" % sLine.rstrip("\r"));
      raise AssertionError("OpenSSL error: " + sStdOut + sStdErr);
  
  @ShowDebugOutput
  def foGetSSLContextForServerWithHostname(oSelf, sHostname):
    oSelf.__oCacheLock.fAcquire();
    try:
      ozSSLContext = oSelf.__doCachedSSLContext_by_sHostname.get(sHostname);
      if ozSSLContext:
        return ozSSLContext;
      fShowDebugOutput("Loading context for %s from file..." % sHostname);
      sKeyFilePath = os.path.join(oSelf.__sGeneratedCertificatesDatabaseFolderPath, "%s.key.pem" % sHostname);
      sCertificateFilePath = os.path.join(oSelf.__sGeneratedCertificatesDatabaseFolderPath, "%s.cert.pem" % sHostname);
      goCertificateFilesLock.fAcquire();
      try:
        if not os.path.isfile(sKeyFilePath):
          fShowDebugOutput("Key file not found at %s." % sKeyFilePath);
          return None;
        if os.path.isfile(sCertificateFilePath):
          fShowDebugOutput("Certificate file not found at %s." % sCertificateFilePath);
          return None;
      finally:
        goCertificateFilesLock.fRelease();
      oSSLContext = cSSLContext.foForServerWithHostnameAndKeyAndCertificateFilePath(
        sHostname, sKeyFilePath, sCertificateFilePath
      );
      oSelf.__doCachedSSLContext_by_sHostname[sHostname] = oSSLContext;
      return oSSLContext;
    finally:
      oSelf.__oCacheLock.fRelease();
  
  @ShowDebugOutput
  def foGenerateSSLContextForServerWithHostname(oSelf, sHostname):
    oSelf.__oCacheLock.fAcquire();
    try:
      ozSSLContext = oSelf.__doCachedSSLContext_by_sHostname.get(sHostname);
      if ozSSLContext:
        return ozSSLContext;
      sKeyFilePath = os.path.join(oSelf.__sGeneratedCertificatesDatabaseFolderPath, "%s.key.pem" % sHostname);
      sCertificateFilePath = os.path.join(oSelf.__sGeneratedCertificatesDatabaseFolderPath, "%s.cert.pem" % sHostname);
      goCertificateFilesLock.fAcquire();
      try:
        if not os.path.isfile(sKeyFilePath) or not os.path.isfile(sCertificateFilePath):
          fShowDebugOutput("Generating certificate signing request file for hostname %s" % sHostname);
          sCertificateSigningRequestFilePath = os.path.join(oSelf.__sGeneratedCertificatesDatabaseFolderPath, "%s.csr.pem" % sHostname);
          oSelf.__fExecuteOpenSSL(
            "req",
            "-config", oSelf.__sOpenSSLIntermediateConfigFilePath,
            "-nodes",
            "-new",
            "-newkey", "rsa:1024",
            "-keyout", sKeyFilePath,
            "-out", sCertificateSigningRequestFilePath,
            "-subj", "/C=NL/O=SkyLined/CN=%s" % sHostname,
          );
          assert os.path.isfile(sCertificateSigningRequestFilePath), \
              "OpenSSL failed to generate the certificate signing request file %s using key file %s for hostname %s" % (
                sCertificateSigningRequestFilePath, sKeyFilePath, sHostname
              );
          fShowDebugOutput("Generating certificate file for hostname %s" % sHostname);
          oSelf.__fExecuteOpenSSL(
            "ca",
            "-batch",
            "-config", oSelf.__sOpenSSLIntermediateConfigFilePath,
            "-extensions", "server_cert",
            "-notext",
            "-in", sCertificateSigningRequestFilePath,
            "-out", sCertificateFilePath,
          );
          assert os.path.isfile(sCertificateFilePath), \
              "OpenSSL failed to generate the certificate file %s using certificate signing request file %s" % (
                sCertificateFilePath, sCertificateSigningRequestFilePath
              );
          os.remove(sCertificateSigningRequestFilePath);
      finally:
        goCertificateFilesLock.fRelease();
      fShowDebugOutput("Loading context from file...");
      oSSLContext = cSSLContext.foForServerWithHostnameAndKeyAndCertificateFilePath(
        sHostname, sKeyFilePath, sCertificateFilePath
      );
      oSelf.__doCachedSSLContext_by_sHostname[sHostname] = oSSLContext;
      return oSSLContext;
    finally:
      oSelf.__oCacheLock.fRelease();

oCertificateAuthority = cCertificateAuthority();