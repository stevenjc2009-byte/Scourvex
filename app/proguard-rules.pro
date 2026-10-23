# Shizuku user service is instantiated by class name from another process.
-keep class com.scourvex.app.shizuku.ShellService { *; }
-keep class com.scourvex.app.IShellService { *; }
-keep class com.scourvex.app.IShellService$* { *; }
