# Microsoft Developer Studio Generated NMAKE File, Based on su.dsp
!IF "$(CFG)" == ""
CFG=su - Win32 Debug
!MESSAGE No configuration specified. Defaulting to su - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "su - Win32 Release" && "$(CFG)" != "su - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "su.mak" CFG="su - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "su - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "su - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "su - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\su.lib"


CLEAN :
	-@erase "$(INTDIR)\su.obj"
	-@erase "$(INTDIR)\su_wait.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\su.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /Fp"$(INTDIR)\su.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\su.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\su.lib" 
LIB32_OBJS= \
	"$(INTDIR)\su.obj" \
	"$(INTDIR)\su_wait.obj"

"$(OUTDIR)\su.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "su - Win32 Debug"

OUTDIR=.\.
INTDIR=c:\temp\ipga\su
# Begin Custom Macros
OutDir=.\.
# End Custom Macros

ALL : "$(OUTDIR)\su.lib" "$(OUTDIR)\su.bsc"


CLEAN :
	-@erase "$(INTDIR)\su.obj"
	-@erase "$(INTDIR)\su.sbr"
	-@erase "$(INTDIR)\su_wait.obj"
	-@erase "$(INTDIR)\su_wait.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\su.bsc"
	-@erase "$(OUTDIR)\su.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP_PROJ=/nologo /MDd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /FR"$(INTDIR)\\" /Fp"$(INTDIR)\su.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\su.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\su.sbr" \
	"$(INTDIR)\su_wait.sbr"

"$(OUTDIR)\su.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\su.lib" 
LIB32_OBJS= \
	"$(INTDIR)\su.obj" \
	"$(INTDIR)\su_wait.obj"

"$(OUTDIR)\su.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("su.dep")
!INCLUDE "su.dep"
!ELSE 
!MESSAGE Warning: cannot find "su.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "su - Win32 Release" || "$(CFG)" == "su - Win32 Debug"
SOURCE=.\su.c

!IF  "$(CFG)" == "su - Win32 Release"


"$(INTDIR)\su.obj" : $(SOURCE) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "su - Win32 Debug"


"$(INTDIR)\su.obj"	"$(INTDIR)\su.sbr" : $(SOURCE) "$(INTDIR)"


!ENDIF 

SOURCE=.\su_wait.c

!IF  "$(CFG)" == "su - Win32 Release"


"$(INTDIR)\su_wait.obj" : $(SOURCE) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "su - Win32 Debug"


"$(INTDIR)\su_wait.obj"	"$(INTDIR)\su_wait.sbr" : $(SOURCE) "$(INTDIR)"


!ENDIF 


!ENDIF 

