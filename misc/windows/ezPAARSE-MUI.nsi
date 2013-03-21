;NSIS Modern User Interface
;ezPAARSE MUI script
;Written by ezPAARSE team 2013/03/20

;--------------------------------
;Include Modern UI

  !include "MUI2.nsh"

;--------------------------------
;General

!define APP_NAME "ezpaarse"
!define APP_VERSION "0.0.4"


;Name and file
Name "${APP_NAME}"
OutFile "${APP_NAME}-${APP_VERSION}-Setup.exe"

;Default installation folder
InstallDir "$LOCALAPPDATA\${APP_NAME}-${APP_VERSION}"

;Get installation folder from registry if available
InstallDirRegKey HKCU "Software\ezPAARSE-Project" ""

;Request application privileges for Windows
RequestExecutionLevel user



;--------------------------------
;Variables

  Var StartMenuFolder
  Var DefaultBrowser

;--------------------------------
;Detecting default browser for shortcut

Section

  FileOpen $0 "$PLUGINSDIR\dummy.htm" "w"
  FileClose $0
  System::Call "Shell32::FindExecutable(t '$PLUGINSDIR\dummy.htm', i 0, t .r1)"
  DetailPrint "Your Default Browser is:"
  DetailPrint $1
  StrCpy $DefaultBrowser $1

SectionEnd

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages

!insertmacro MUI_PAGE_LICENSE "Licence_CeCILL_V2-fr.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY

;Start Menu Folder Page Configuration
!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKCU" 
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\ezPAARSE-Project" 
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"

; ending image
!define MUI_WELCOMEFINISHPAGE_BITMAP "ezPAARSE-HeaderPageNSIS.bmp"

!insertmacro MUI_PAGE_STARTMENU Application $StartMenuFolder

!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Lancer ezPAARSE"
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchEZPAARSE"

!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
  
;--------------------------------
;Languages
 
  !insertmacro MUI_LANGUAGE "French"

;--------------------------------
;Installer Sections

Section "ezPAARSE (required)" SecEZPAARSE

  SetOutPath "$INSTDIR"
  SectionIn RO
  
  ;ADD YOUR OWN FILES HERE...
  File /r "${APP_NAME}-${APP_VERSION}\*.*"

  ;Store installation folder
  WriteRegStr HKCU "Software\ezPAARSE-Project" "" $INSTDIR
  
  ;Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

SectionEnd


Section "Menu ezPAARSE" SecMenuEZPAARSE

  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
    
    ;Create shortcuts
    CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
    CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
    CreateShortCut "$SMPROGRAMS\$StartMenuFolder\1-Lancer ezPAARSE.lnk" "$INSTDIR\node.exe" "app.js" 0
    CreateShortCut "$SMPROGRAMS\$StartMenuFolder\2-Utiliser ezPAARSE.lnk" "$DefaultBrowser" "http://localhost:59599/ws" 0 
    CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Documentation ezPAARSE.lnk" "$DefaultBrowser" "http://localhost:59599/doc" 0 
    CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Site AnalogIST.lnk" "$DefaultBrowser" "http://analogist.couperin.org" 0 
  !insertmacro MUI_STARTMENU_WRITE_END

SectionEnd

;--------------------------------
;Descriptions

  ;Language strings
  LangString DESC_SecEZPAARSE ${LANG_FRENCH} "Section ezPAARSE."

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecEZPAARSE} $(DESC_SecEZPAARSE)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Section "Uninstall"

  Delete "$INSTDIR\Uninstall.exe"

  RMDir /r "$INSTDIR"

  !insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuFolder
    
  RMDir /r "$SMPROGRAMS\$StartMenuFolder"

  DeleteRegKey /ifempty HKCU "Software\ezPAARSE-Project"

SectionEnd

Function LaunchEZPAARSE
  MessageBox MB_OK "Le Web Service ezPAARSE va etre lance $\r$\n \
                   et la Home Page ezPAARSE sera ouverte dans votre navigateur$\r$\n \
                   Cliquer sur la croix pour fermer le Web Service$\r$\n \
                   Le Web Service a besoin des autorisations de votre pare-feu windows"
  ExecShell "" "$SMPROGRAMS\$StartMenuFolder\1-Lancer ezPAARSE.lnk"
  Sleep 5000 ; wait for node startup
  ExecShell "open" "http://localhost:59599/ws"
FunctionEnd
