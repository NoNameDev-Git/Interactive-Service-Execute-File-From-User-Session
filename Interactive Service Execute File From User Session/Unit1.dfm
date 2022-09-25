object Windows_Service_Drivers_Display: TWindows_Service_Drivers_Display
  OldCreateOrder = False
  DisplayName = 'Windows_Service_Drivers'
  Interactive = True
  OnContinue = ServiceContinue
  OnPause = ServicePause
  OnStart = ServiceStart
  OnStop = ServiceStop
  Height = 150
  Width = 215
end
