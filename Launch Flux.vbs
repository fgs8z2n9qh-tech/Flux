' Double-click to start Flux from source with no console window.
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = here
' 0 = hidden window, False = don't wait for it to exit
sh.Run "pythonw.exe """ & here & "\vram_monitor.py""", 0, False
