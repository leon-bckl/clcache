@echo off

set CL_FLAGS=/nologo /W4 /TC /GS- /Gs999999 /DNO_CRT /Zl

if /I "%1" == "release" (
	set CL_FLAGS=%CL_FLAGS% /O2 /DNDEBUG
) else (
	set CL_FLAGS=%CL_FLAGS% /Od /Zi
)

cl clcache.c %CL_FLAGS% /link /SUBSYSTEM:CONSOLE /STACK:0x10000,0x10000
