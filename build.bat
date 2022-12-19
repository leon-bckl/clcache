@echo off

set CL_FLAGS=/nologo /Zi /W4 /TC /GS- /Gs999999 /DNO_CRT

if /I "%1" == "release" (
	set CL_FLAGS=%CL_FLAGS% /O2 /DNDEBUG
) else (
	set CL_FLAGS=%CL_FLAGS% /Od
)

cl clcache.c %CL_FLAGS% /link /SUBSYSTEM:CONSOLE /NODEFAULTLIB /STACK:0x100000,0x100000 kernel32.lib shell32.lib ole32.lib Version.lib
