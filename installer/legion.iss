; Legion — установщик для Windows (Inno Setup 6).
; Собирается скриптом installer\build.ps1, который передаёт параметры через /D.
;
; Что делает установщик:
;   * ставит в %LOCALAPPDATA%\Legion без прав администратора;
;   * регистрирует нативный хост для Google Chrome (Native Messaging);
;   * после установки открывает chrome://extensions и папку расширения;
;   * ярлыка на рабочем столе НЕТ — только меню «Пуск».

#ifndef AppVersion
  #define AppVersion "0.7.0"
#endif
#ifndef StageDir
  #error "StageDir не задан: запускайте installer\build.ps1"
#endif
#ifndef ExtensionId
  #error "ExtensionId не задан: запускайте installer\build.ps1"
#endif
#ifndef OutputDir
  #define OutputDir "output"
#endif

#define AppName "Legion"
#define AppExeServer "legion-server.exe"
#define AppExeHost "legion-host.exe"

[Setup]
AppId={{B6F1D2A4-7C3E-4F8B-9A5D-2E1C0F7B9D31}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Legion
AppComments=Защита от фишинговых сайтов для Google Chrome
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany=Legion
VersionInfoProductName={#AppName}
VersionInfoDescription=Установщик Legion
DefaultDirName={localappdata}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=Legion-Setup
SetupIconFile={#SourcePath}\assets\legion.ico
WizardStyle=modern
WizardImageFile={#SourcePath}\assets\wizard-large.bmp
WizardSmallImageFile={#SourcePath}\assets\wizard-small.bmp
UninstallDisplayIcon={app}\server\{#AppExeServer}
UninstallDisplayName={#AppName}
Compression=lzma2/ultra64
SolidCompression=yes
CloseApplications=no
RestartIfNeededByRun=no
SetupLogging=yes
ShowLanguageDialog=no
DisableWelcomePage=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Files]
; Локальный сервер (PyInstaller onedir) — без .env и без секретов разработчика
Source: "{#StageDir}\server\*"; DestDir: "{app}\server"; Flags: ignoreversion recursesubdirs createallsubdirs
; Нативный хост, который запускает Chrome
Source: "{#StageDir}\host\*"; DestDir: "{app}\host"; Flags: ignoreversion recursesubdirs createallsubdirs
; Расширение для загрузки в Chrome (Режим разработчика → Загрузить распакованное)
Source: "{#StageDir}\extension\*"; DestDir: "{app}\extension"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{app}\logs"

[Icons]
Name: "{group}\Папка расширения Legion"; Filename: "{app}\extension"
Name: "{group}\Удалить Legion"; Filename: "{uninstallexe}"

[Registry]
; Chrome ищет нативный хост по этому ключу (только для текущего пользователя)
Root: HKCU; Subkey: "Software\Google\Chrome\NativeMessagingHosts\com.legion.host"; ValueType: string; ValueName: ""; ValueData: "{app}\native-host.json"; Flags: uninsdeletekey

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /T /IM {#AppExeServer}"; Flags: runhidden; RunOnceId: "StopLegionServer"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /T /IM {#AppExeHost}"; Flags: runhidden; RunOnceId: "StopLegionHost"

[UninstallDelete]
; Файлы, которые создаёт программа во время работы (не входят в список установки)
Type: files; Name: "{app}\native-host.json"
Type: filesandordirs; Name: "{app}\server\data"
Type: filesandordirs; Name: "{app}\logs"
Type: dirifempty; Name: "{app}\server"
Type: dirifempty; Name: "{app}\host"
Type: dirifempty; Name: "{app}\extension"
Type: dirifempty; Name: "{app}"

[Code]
const
  NativeHostName = 'com.legion.host';
  ExtensionIdValue = '{#ExtensionId}';

{ 4 шестнадцатеричные цифры (для \uXXXX) без зависимости от IntToHex }
function Hex4(N: Integer): string;
begin
  Result :=
    Copy('0123456789ABCDEF', (N div 4096) mod 16 + 1, 1) +
    Copy('0123456789ABCDEF', (N div 256) mod 16 + 1, 1) +
    Copy('0123456789ABCDEF', (N div 16) mod 16 + 1, 1) +
    Copy('0123456789ABCDEF', N mod 16 + 1, 1);
end;

function JsonEscape(const S: string): string;
var
  I: Integer;
  Ch: string;
  Code: Integer;
begin
  Result := '';
  for I := 1 to Length(S) do
  begin
    Ch := Copy(S, I, 1);
    Code := Ord(S[I]);
    if Ch = '\' then
      Result := Result + '\\'
    else if Ch = '"' then
      Result := Result + '\"'
    else if (Code < 32) or (Code > 126) then
      Result := Result + '\u' + Hex4(Code)
    else
      Result := Result + Ch;
  end;
end;

{ Манифест нативного хоста. Строго ASCII (не-ASCII экранируется), поэтому кодировка файла не важна. }
function NativeHostManifest(const HostExe: string): string;
begin
  Result :=
    '{' + #13#10 +
    '  "name": "' + NativeHostName + '",' + #13#10 +
    '  "description": "' + JsonEscape('Legion: запуск локального сервера защиты') + '",' + #13#10 +
    '  "path": "' + JsonEscape(HostExe) + '",' + #13#10 +
    '  "type": "stdio",' + #13#10 +
    '  "allowed_origins": [' + #13#10 +
    '    "chrome-extension://' + ExtensionIdValue + '/"' + #13#10 +
    '  ]' + #13#10 +
    '}' + #13#10;
end;

function FindChrome(): string;
var
  S: string;
begin
  Result := '';
  S := '';
  if RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe', '', S) then
  begin
    S := RemoveQuotes(S);
    if FileExists(S) then Result := S;
  end;
  if Result = '' then
  begin
    if RegQueryStringValue(HKCU, 'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe', '', S) then
    begin
      S := RemoveQuotes(S);
      if FileExists(S) then Result := S;
    end;
  end;
  if Result = '' then
    if FileExists(ExpandConstant('{localappdata}\Google\Chrome\Application\chrome.exe')) then
      Result := ExpandConstant('{localappdata}\Google\Chrome\Application\chrome.exe');
  if Result = '' then
    if FileExists(ExpandConstant('{pf}\Google\Chrome\Application\chrome.exe')) then
      Result := ExpandConstant('{pf}\Google\Chrome\Application\chrome.exe');
  if Result = '' then
    if FileExists(ExpandConstant('{pf32}\Google\Chrome\Application\chrome.exe')) then
      Result := ExpandConstant('{pf32}\Google\Chrome\Application\chrome.exe');
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if FindChrome() = '' then
  begin
    if WizardSilent() then Exit;
    if MsgBox(
      'Google Chrome не найден.' + #13#10 + #13#10 +
      'Legion работает только в Google Chrome. Установить Legion сейчас и добавить Chrome позже?',
      mbConfirmation, MB_YESNO) = IDNO then
      Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  RC: Integer;
begin
  Result := '';
  { При обновлении старые процессы могут держать файлы — останавливаем их }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM {#AppExeServer}', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM {#AppExeHost}', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Sleep(500);
end;

procedure ShowFinalSteps();
var
  Chrome: string;
  RC: Integer;
begin
  Chrome := FindChrome();
  Exec(ExpandConstant('{win}\explorer.exe'), ExpandConstant('"{app}\extension"'), '', SW_SHOWNORMAL, ewNoWait, RC);
  if Chrome <> '' then
    Exec(Chrome, 'chrome://extensions/', '', SW_SHOWNORMAL, ewNoWait, RC);
  MsgBox(
    'Legion установлен.' + #13#10 + #13#10 +
    'Последний шаг, он делается один раз:' + #13#10 +
    '1. Откроется страница chrome://extensions' + #13#10 +
    '2. Включите «Режим разработчика» (переключатель в правом верхнем углу).' + #13#10 +
    '3. Нажмите «Загрузить распакованное расширение» и выберите открывшуюся папку «extension».' + #13#10 + #13#10 +
    'Дальше Legion сам запускает свой сервер при каждом запуске Chrome.',
    mbInformation, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  HostExe: string;
begin
  if CurStep = ssPostInstall then
  begin
    HostExe := ExpandConstant('{app}\host\{#AppExeHost}');
    if not SaveStringToFile(ExpandConstant('{app}\native-host.json'), NativeHostManifest(HostExe), False) then
      MsgBox('Не удалось записать native-host.json. Legion не сможет запускать сервер автоматически.', mbError, MB_OK);
  end;
  if (CurStep = ssDone) and (not WizardSilent()) then
    ShowFinalSteps();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usDone) and (not UninstallSilent()) then
    MsgBox('Legion удалён.' + #13#10 + #13#10 +
      'Чтобы убрать расширение из Chrome, откройте chrome://extensions и удалите «Legion».',
      mbInformation, MB_OK);
end;
