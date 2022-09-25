program winsystem;

uses
  Vcl.SvcMgr,
  Unit1 in 'Unit1.pas' {Windows_Service_Drivers_Display: TService};

begin
  if not Application.DelayInitialize or Application.Installing then
    Application.Initialize;
  Application.CreateForm(TWindows_Service_Drivers_Display, Windows_Service_Drivers_Display);
  Application.Run;
end.
