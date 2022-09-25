chcp 1251
cd /d "C:\Users\Home\Desktop\Служба\Win32\Release"
taskkill /IM winsystem.exe /F
net stop Windows_Service_Drivers_Display
sc delete Windows_Service_Drivers_Display