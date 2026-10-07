Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "D:\Projects\aegis-project\aegis"
WshShell.Run "node server.js", 0, False
