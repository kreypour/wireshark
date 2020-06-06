!define APPID "wiresharkdissect"
!define APPNAME "Wireshark Dissect"
!define DESCRIPTION "Wireshark Libraries for EPAN Dissectors"
!define ENVVAR "WIRESHARK_DISSECT_DIR"

Unicode True
RequestExecutionLevel admin

# this will be in the install/uninstaller title bar
Name "${APPNAME}"
# name of the installer file
Outfile "wiresharkdissect.exe"

# default installation directory
InstallDir $PROGRAMFILES64\wiresharkdissect
DirText "This will install Wireshark Dissect libraries on your computer. Choose a directory."
 
# logic to verify admin user
!include LogicLib.nsh
!macro VerifyUserIsAdmin
UserInfo::GetAccountType
pop $0
${If} $0 != "admin" ;Require admin rights on NT4+
        messageBox mb_iconstop "Administrator rights required!"
        setErrorLevel 740 ;ERROR_ELEVATION_REQUIRED
        quit
${EndIf}
!macroend

### installer ###
function .onInit
    setShellVarContext all
    !insertmacro VerifyUserIsAdmin
functionEnd

Section "install"
    # define the output path for this file
    SetOutPath $INSTDIR

    # files to be installed
    File wiresharkdissect.dll
    File brotlicommon.dll
    File brotlidec.dll
    File cares.dll
    File comerr64.dll
    File glib-2.dll
    File gmodule-2.dll
    File k5sprt64.dll
    File krb5_64.dll
    File libcharset.dll
    File libffi-6.dll
    File libgcrypt-20.dll
    File libgmp-10.dll
    File libgnutls-30.dll
    File libgpg-error-0.dll
    File libhogweed-4.dll
    File libiconv.dll
    File libintl.dll
    File libnettle-6.dll
    File libp11-kit-0.dll
    File libsmi-2.dll
    File libsnappy-1.dll
    File libtasn1-6.dll
    File libwireshark.dll
    File libwiretap.dll
    File libwsutil.dll
    File libxml2.dll
    File lua52.dll
    File lz4.dll
    File lzma.dll
    File nghttp2.dll
    File pcre.dll
    File vcruntime140.dll
    File zlib1.dll
    File zstd.dll

    # uninstaller file
    writeUninstaller "$INSTDIR\uninstall.exe"

    # add system environment variable
    EnVar::SetHKLM
    EnVar::AddValue "${ENVVAR}" "$INSTDIR"
    Pop $0
    DetailPrint "EnVar::AddValue returned=|$0|"

    # reg keys for add-remove programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME} - ${DESCRIPTION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    # There is no option for modifying or repairing the install
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoRepair" 1
SectionEnd

### uninstaller ###
function un.onInit
    SetShellVarContext all
 
    #Verify the uninstaller - last chance to back out
    MessageBox MB_OKCANCEL "Permanantly remove ${APPNAME}?" IDOK next
        Abort
    next:
    !insertmacro VerifyUserIsAdmin
functionEnd

section "uninstall"
    # remove files
    delete $INSTDIR\wiresharkdissect.dll
    delete $INSTDIR\brotlicommon.dll
    delete $INSTDIR\brotlidec.dll
    delete $INSTDIR\cares.dll
    delete $INSTDIR\comerr64.dll
    delete $INSTDIR\glib-2.dll
    delete $INSTDIR\gmodule-2.dll
    delete $INSTDIR\k5sprt64.dll
    delete $INSTDIR\krb5_64.dll
    delete $INSTDIR\libcharset.dll
    delete $INSTDIR\libffi-6.dll
    delete $INSTDIR\libgcrypt-20.dll
    delete $INSTDIR\libgmp-10.dll
    delete $INSTDIR\libgnutls-30.dll
    delete $INSTDIR\libgpg-error-0.dll
    delete $INSTDIR\libhogweed-4.dll
    delete $INSTDIR\libiconv.dll
    delete $INSTDIR\libintl.dll
    delete $INSTDIR\libnettle-6.dll
    delete $INSTDIR\libp11-kit-0.dll
    delete $INSTDIR\libsmi-2.dll
    delete $INSTDIR\libsnappy-1.dll
    delete $INSTDIR\libtasn1-6.dll
    delete $INSTDIR\libwireshark.dll
    delete $INSTDIR\libwiretap.dll
    delete $INSTDIR\libwsutil.dll
    delete $INSTDIR\libxml2.dll
    delete $INSTDIR\lua52.dll
    delete $INSTDIR\lz4.dll
    delete $INSTDIR\lzma.dll
    delete $INSTDIR\nghttp2.dll
    delete $INSTDIR\pcre.dll
    delete $INSTDIR\vcruntime140.dll
    delete $INSTDIR\zlib1.dll
    delete $INSTDIR\zstd.dll

    # delete uninstaller as the last action
    delete $INSTDIR\uninstall.exe

    # try to remove the install directory - this will only happen if it is empty
    rmDir $INSTDIR

    # remove system environment variable
    EnVar::SetHKLM
    EnVar::DeleteValue "${ENVVAR}" "$INSTDIR"
    Pop $0
    DetailPrint "EnVar::DeleteValue returned=|$0|"
    EnVar::Delete "${ENVVAR}"
    Pop $0
    DetailPrint "EnVar::Delete returned=|$0|"

    # remove uninstaller information from the registry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
sectionEnd