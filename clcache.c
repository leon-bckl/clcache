#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <shellapi.h>
#include <ShlObj.h>

#ifdef NO_CRT
int _fltused;
#pragma intrinsic(memset,memcpy,memmove,_byteswap_ulong,_byteswap_uint64)
#endif

#pragma warning(push, 0)
#define XXH_INLINE_ALL
#include "xxhash/xxhash.h"
#pragma warning(pop)

/*
 * TODO:
 * - Clean up code
 * - stats (cache hits, misses etc.)
 * - shorten cache path (8 nested directories seems a little too much)
 * - clean up old cache entries
 * - scan files for __TIME__ macro and mark them as uncacheable
 */

/*
 * Macros
 */

#ifdef NDEBUG
	#define ASSERT(expr) (void)(0)
#else
	#define ASSERT(expr) \
		if(!(expr)) \
			*(volatile int*)NULL = 0
#endif

#define KILOBYTES(x) ((x) * 1024ULL)
#define MEGABYTES(x) (KILOBYTES(x) * 1024ULL)
#define GIGABYTES(x) (MEGABYTES(x) * 1024ULL)

#define ALIGN_POW2(val, align) (((val) + (align) - 1) & ~((align) - 1))

#define ALIGNOF(type) offsetof(struct{ char c; type d; }, d)

/*
 * Constants
 */

#define MAX_COMMAND_LINE_LENGTH 32768
#define DEFAULT_CACHE_SIZE      GIGABYTES(20)
#define CACHE_PATH_LENGTH       60 // Length of path to a cached file within .clcache dir (not exact, used to check against MAX_PATH)

static const LPCWSTR HexLookup = L"0123456789abcdef";
static const LPCWSTR ShowIncludeLineStart = L"Note: including file:";

/*
 * Structs
 */

struct string{
	LPCWSTR Data;
	size_t  Length;
};

struct string_buffer{
	LPWSTR Data;
	size_t Size;
	size_t Used;
};

struct cache_config{
	UINT64 CacheSize;
	WCHAR  CachePath[MAX_PATH];
};

struct cache_info{
	UINT64 SizeUsed;
	UINT32 Hits;
	UINT32 Misses;
};

struct memory_arena{
	void* Memory;
	size_t Size;
	size_t Used;
	size_t PrevUsed;
};

struct cl_command_info{
	struct string Executable;
	UINT64 ClVersion;
	BOOL NoLogo;
	BOOL ShowIncludes;
	BOOL GeneratesPdb;
	struct string ObjFile;
	struct string PdbFile;
	struct string SrcFile;
	int CompilerFlagCount;
	struct string* CompilerFlags;
	int IncludePathCount;
	int SystemIncludePathCount;
	struct string* IncludePaths;
	struct string* SystemIncludePaths;
};

struct dependency_entry{
	UINT64        Size;
	UINT64        LastModified;
	UINT64        Hash;
	struct string FileName;
};

struct dependency_info{
	UINT32                   EntryCount;
	struct dependency_entry* Entries;
};

/*
 * Globals
 */

HANDLE              StdoutHandle;
HANDLE              StderrHandle;

WCHAR               ConfigFilePath[MAX_PATH];

struct cache_config GlobalConfig;

/*
 * String
 */

static BOOL IsWhitespace(WCHAR C){ return C == ' ' || C == '\t' || C == '\n' || C == '\r'; }
static BOOL IsDigit(WCHAR C){ return C >= '0' && C <= '9'; }
static BOOL IsPathSeparator(WCHAR C){ return C == '\\' || C == '/'; }

#define STR(str) (struct string){L ## str, sizeof(L ## str) / sizeof(WCHAR) - 1}

static struct string MakeString(LPCWSTR Data, size_t Length){
	struct string Result;

	Result.Data = Data;
	Result.Length = Length;

	return Result;
}

static struct string_buffer MakeStringBuffer(LPWSTR Data, size_t Size){
	struct string_buffer Result;

	Result.Data = Data;
	Result.Size = Size;
	Result.Used = 0;

	return Result;
}

static LPWSTR PushChars(size_t Count, struct string_buffer* Buffer){
	ASSERT(Buffer->Used + Count + 1 <= Buffer->Size);

	LPWSTR Result = Buffer->Data + Buffer->Used;

	Buffer->Used += Count;
	Buffer->Data[Buffer->Used] = '\0';

	return Result;
}

static struct string PushString(struct string Str, struct string_buffer* Buffer){
	struct string Result;

	Result.Data = CopyMemory(PushChars(Str.Length, Buffer), Str.Data, Str.Length * sizeof(WCHAR));
	Result.Length = Str.Length;

	return Result;
}

static struct string PushCmdLineArg(struct string Str, struct string_buffer* Buffer){
	if(Buffer->Used > 0 && !IsWhitespace(Buffer->Data[Buffer->Used]))
		PushString(STR(" "), Buffer);

	BOOL NeedQuotes = FALSE;

	if(Str.Data[0] != '\"'){
		for(size_t i = 0; !NeedQuotes && i < Str.Length; ++i){
			if(IsWhitespace(Str.Data[i])){
				NeedQuotes = TRUE;
				break;
			}
		}
	}

	if(NeedQuotes){
		size_t Length = Str.Length + 2;
		LPWSTR Data = PushChars(Length, Buffer);

		Data[0] = '\"';
		CopyMemory(&Data[1], Str.Data, Str.Length * sizeof(WCHAR));
		Data[Length - 1] = '\"';

		return MakeString(Data, Length);
	}

	return PushString(Str, Buffer);
}

static struct string StringFromWchar(LPCWSTR Str){
	struct string Result;

	Result.Data = Str;
	Result.Length = lstrlenW(Str);

	return Result;
}

static struct string TrimStringLeft(struct string Str){
	while(Str.Length > 0 && IsWhitespace(Str.Data[0])){
		++Str.Data;
		--Str.Length;
	}

	return Str;
}

static struct string TrimStringRight(struct string Str){
	while(Str.Length > 0 && IsWhitespace(Str.Data[Str.Length - 1]))
		--Str.Length;

	return Str;
}

static struct string TrimString(struct string Str){
	return TrimStringRight(TrimStringLeft(Str));
}

static struct string StringLeft(struct string Str, size_t Count){
	Str.Length = min(Str.Length, Count);

	return Str;
}

static struct string StringRight(struct string Str, size_t Count){
	size_t Length = min(Str.Length, Count);

	Str.Data += Str.Length - Length;
	Str.Length = Length;

	return Str;
}

static struct string StringMid(struct string Str, size_t Index, size_t Count){
	if(Index >= Str.Length)
		return MakeString(Str.Data + Str.Length, 0);

	Str.Data += Index;
	Str.Length = Str.Length - Index;
	Str.Length = min(Str.Length, Count);

	return Str;
}

static int CompareStrings(struct string S1, struct string S2){
	return CompareStringOrdinal(S1.Data, (int)S1.Length, S2.Data, (int)S2.Length, FALSE) - 2;
}

static int CompareStringsCaseInsensitive(struct string S1, struct string S2){
	return CompareStringOrdinal(S1.Data, (int)S1.Length, S2.Data, (int)S2.Length, TRUE) - 2;
}

static BOOL StringsAreEqual(struct string S1, struct string S2){
	return S1.Length == S2.Length && CompareStringOrdinal(S1.Data, (int)S1.Length, S2.Data, (int)S2.Length, FALSE) == CSTR_EQUAL;
}

static BOOL StringsAreEqualCaseInsensitive(struct string S1, struct string S2){
	return S1.Length == S2.Length && CompareStringOrdinal(S1.Data, (int)S1.Length, S2.Data, (int)S2.Length, TRUE) == CSTR_EQUAL;
}

static BOOL StringStartsWith(struct string Str, struct string Start){
	return Start.Length <= Str.Length && StringsAreEqual(StringLeft(Str, Start.Length), Start);
}

static BOOL StringStartsWithCaseInsensitive(struct string Str, struct string Start){
	return Start.Length <= Str.Length && StringsAreEqualCaseInsensitive(StringLeft(Str, Start.Length), Start);
}

static BOOL StringEndsWith(struct string Str, struct string End){
	return End.Length <= Str.Length && StringsAreEqual(StringRight(Str, End.Length), End);
}

static BOOL StringEndsWithCaseInsensitive(struct string Str, struct string End){
	return End.Length <= Str.Length && StringsAreEqualCaseInsensitive(StringRight(Str, End.Length), End);
}

static UINT64 StringToUINT64(struct string Str){
	Str = TrimStringLeft(Str);

	UINT64 Result = 0;

	while(Str.Length && IsDigit(*Str.Data)){
		UINT64 OverflowCheck = Result;

		Result *= 10;

		if(Result < OverflowCheck)
			return 0;

		Result += *Str.Data - '0';
		++Str.Data;
		--Str.Length;
	}

	return Result;
}

static struct string UINT64ToString(UINT64 Value, struct string_buffer* Buffer){
	size_t DigitCount = 1;

	for(UINT64 i = 10; i <= Value; i *= 10)
		++DigitCount;

	LPWSTR Data = PushChars(DigitCount, Buffer);

	for(size_t i = DigitCount; i > 0; --i){
		Data[i - 1] = '0' + (WCHAR)(Value % 10);
		Value /= 10;
	}

	return MakeString(Data, DigitCount);
}

static struct string FloatToString(float Value, struct string_buffer* Buffer){
	struct string Result = UINT64ToString((UINT64)Value, Buffer);

	Result.Length += PushString(STR("."), Buffer).Length;
	// 2 digits of precision is enough. This is only used to print percentages for stats.
	Result.Length += UINT64ToString((UINT64)((Value - (float)(UINT64)Value) * 100.0f), Buffer).Length;

	return Result;
}

static struct string FileNameWithoutPath(struct string Path){
	for(size_t i = Path.Length; i > 0; --i){
		if(IsPathSeparator(Path.Data[i - 1]))
			return MakeString(Path.Data + i, Path.Length - i);
	}

	return Path;
}

static struct string FilePathWithoutExtension(struct string Path){
	for(size_t i = Path.Length; i > 0; --i){
		if(Path.Data[i - 1] == '.')
			return MakeString(Path.Data, i - 1);

		if(IsPathSeparator(Path.Data[i - 1]))
			break;
	}

	return Path;
}

static struct string PathWithoutFileName(struct string Path){
	for(size_t i = Path.Length; i > 0; --i){
		if(IsPathSeparator(Path.Data[i - 1]))
			return MakeString(Path.Data, i);
	}

	return MakeString(Path.Data, 0);
}

static void SortStrings(struct string* Strings, int Count){
	struct string Temp;

	for(int i = 1; i < Count; ++i){
		if(CompareStrings(Strings[i], Strings[i - 1]) < 0){
			Temp = Strings[i];
			Strings[i] = Strings[i - 1];
			Strings[i - 1] = Temp;

			for(int j = i - 1; j > 0; --j){
				if(CompareStrings(Strings[j], Strings[j - 1]) < 0){
					Temp = Strings[j];
					Strings[j] = Strings[j - 1];
					Strings[j - 1] = Temp;
				}
			}
		}
	}
}

/*
 * Output
 */

static void WriteStdout(struct string Str){
	WriteConsoleW(StdoutHandle, Str.Data, (DWORD)Str.Length, NULL, NULL);
}

static void WriteStderr(struct string Str){
	WriteConsoleW(StderrHandle, Str.Data, (DWORD)Str.Length, NULL, NULL);
}

/*
 * Error
 */

static __declspec(noreturn) void FatalError(struct string Msg, struct string Context){
	WriteStderr(STR("ERROR: "));
	WriteStderr(Msg);

	if(Context.Length > 0){
		WriteStderr(STR(": "));
		WriteStderr(Context);
	}

	WriteStderr(STR("\n"));
	ExitProcess(1);
}

/*
 * Memory
 */

static struct memory_arena CreateMemory(size_t Size){
	struct memory_arena Arena;

	// No need to free this. Just let the OS clean it all up when the process exits...
	Arena.Memory = VirtualAlloc(NULL, Size, MEM_COMMIT, PAGE_READWRITE);

	if(!Arena.Memory)
		FatalError(STR("Unable to allocate virtual memory"), STR(""));

	Arena.Size = Size;
	Arena.Used = 0;
	Arena.PrevUsed = 0;

	return Arena;
}

static void* PushMem(struct memory_arena* Arena, size_t Size){
	if(Arena->Used + Size > Arena->Size)
		FatalError(STR("Out of memory"), STR(""));

	void* Mem = (BYTE*)Arena->Memory + Arena->Used;

	Arena->PrevUsed = Arena->Used;
	Arena->Used += Size;
	Arena->Used = ALIGN_POW2(Arena->Used, MEMORY_ALLOCATION_ALIGNMENT);

	return Mem;
}

static void PopMem(struct memory_arena* Arena){
	if(Arena->PrevUsed > 0){
		Arena->Used = Arena->PrevUsed;
		Arena->PrevUsed = 0;
	}
}

static void PopPartialMem(struct memory_arena* Arena, size_t Size){
	if(Size < Arena->Used && Arena->Used - Size >= Arena->PrevUsed){
		Arena->Used -= Size;
		Arena->Used = ALIGN_POW2(Arena->Used, MEMORY_ALLOCATION_ALIGNMENT);
		Arena->PrevUsed = 0;
	}
}

/*
 * File system
 */

static void MakePath(struct string Path){
	if(Path.Length >= MAX_PATH)
		FatalError(STR("Path length limit exceeded"), Path);

	WCHAR TempPath[MAX_PATH];

	CopyMemory(TempPath, Path.Data, Path.Length * sizeof(WCHAR));
	TempPath[Path.Length] = '\0';

	for(WCHAR* p = TempPath; *p; ++p){
		while(*p && !IsPathSeparator(*p))
			++p;

		WCHAR Temp = *p;

		*p = '\0';

		DWORD Attribs = GetFileAttributesW(TempPath);

		if(Attribs == INVALID_FILE_ATTRIBUTES || (Attribs & FILE_ATTRIBUTE_DIRECTORY) == 0){
			if(!CreateDirectoryW(TempPath, NULL))
				FatalError(STR("Unable to create directory"), MakeString(TempPath, (size_t)(p - TempPath)));
		}

		*p = Temp;
	}
}

static BOOL FileExists(LPCWSTR Path){
	return GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES;
}

static BOOL GetFileSizeLastModified(LPCWSTR filePath, UINT64* FileSize, UINT64* LastModified){
	WIN32_FILE_ATTRIBUTE_DATA FileAttribData;

	if(GetFileAttributesExW(filePath, GetFileExInfoStandard, &FileAttribData)){
		*FileSize = (UINT64)FileAttribData.nFileSizeHigh << 32 | FileAttribData.nFileSizeLow;
		*LastModified = (UINT64)FileAttribData.ftLastWriteTime.dwHighDateTime << 32 | FileAttribData.ftLastWriteTime.dwLowDateTime;

		return TRUE;
	}

	return FALSE;
}

static void WriteDataToFile(LPCWSTR Path, const void* Data, size_t Size){
	HANDLE File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if(File == INVALID_HANDLE_VALUE)
		FatalError(STR("Unable to open file for writing"), StringFromWchar(Path));

	DWORD NumBytesWritten;

	if(!WriteFile(File, Data, (DWORD)Size, &NumBytesWritten, NULL))
		FatalError(STR("Unable to write to file"), StringFromWchar(Path));

	CloseHandle(File);
}

/*
 * Configuration
 */

static void WriteConfig(struct cache_config* Config){
	WriteDataToFile(ConfigFilePath, Config, sizeof(*Config));
}

static void ReadConfig(struct cache_config* Config){
	if(FileExists(ConfigFilePath)){
		HANDLE File = CreateFileW(ConfigFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if(File == INVALID_HANDLE_VALUE)
			FatalError(STR("Unable to open configuration file for reading"), StringFromWchar(ConfigFilePath));

		DWORD NumBytesRead;
		BOOL Success = ReadFile(File, Config, sizeof(*Config), &NumBytesRead, NULL);

		CloseHandle(File);

		if(!Success)
			FatalError(STR("Unable to read from configuration file"), StringFromWchar(ConfigFilePath));
	}else{ // Initialize config with default values and write it to the file
		PWSTR CachePath;

		ZeroMemory(Config, sizeof(*Config));
		Config->CacheSize = DEFAULT_CACHE_SIZE;
		SHGetKnownFolderPath(&FOLDERID_Profile, 0, NULL, &CachePath);
		lstrcpyW(Config->CachePath, CachePath);
		lstrcatW(Config->CachePath, L"\\.clcache");
		CoTaskMemFree(CachePath);

		if(lstrlenW(Config->CachePath) + CACHE_PATH_LENGTH >= MAX_PATH)
			FatalError(STR("Invalid cache path"), StringFromWchar(Config->CachePath));

		WriteConfig(Config);
	}
}

/*
 * Process
 */

static void StartProcess(LPWSTR CmdLine, LPPROCESS_INFORMATION ProcessInfo, HANDLE Out, HANDLE Err){
	STARTUPINFOW StartupInfo = {0};

	StartupInfo.cb = sizeof(StartupInfo);

	if(Out != INVALID_HANDLE_VALUE || Err != INVALID_HANDLE_VALUE){
		StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
		StartupInfo.hStdOutput = Out == INVALID_HANDLE_VALUE ? StdoutHandle : Out;
		StartupInfo.hStdError = Err == INVALID_HANDLE_VALUE ? StderrHandle : Err;
	}

	ZeroMemory(ProcessInfo, sizeof(*ProcessInfo));

	WriteStdout(STR("CMDLINE: "));
	WriteStdout(StringFromWchar(CmdLine));
	WriteStdout(STR("\n"));

	if(!CreateProcessW(NULL, CmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, 0, NULL, &StartupInfo, ProcessInfo))
		FatalError(STR("Unable to start process"), StringFromWchar(CmdLine));
}

static DWORD WaitForProcessToFinish(LPPROCESS_INFORMATION ProcessInfo){
	DWORD ExitCode = 0;

	WaitForSingleObject(ProcessInfo->hProcess, INFINITE);
	GetExitCodeProcess(ProcessInfo->hProcess, &ExitCode);
	CloseHandle(ProcessInfo->hThread);
	CloseHandle(ProcessInfo->hProcess);

	return ExitCode;
}

/*
 * CacheMain
 */

static UINT64 GetCompilerVersion(LPCWSTR ExecutablePath, struct memory_arena* Arena){
	DWORD  Handle  = 0;
	UINT   Size    = 0;
	LPBYTE Buffer  = NULL;
	DWORD  VerSize = GetFileVersionInfoSizeW( ExecutablePath, &Handle);
	UINT64 Version = 0;

	if(VerSize > 0){
		void* VerData = PushMem(Arena, VerSize);

		if(GetFileVersionInfoW(ExecutablePath, Handle, VerSize, VerData)){
			if(VerQueryValueW(VerData, L"\\", (LPVOID)&Buffer, &Size)){
				if(Size){
					VS_FIXEDFILEINFO* VerInfo = (VS_FIXEDFILEINFO*)Buffer;

					if(VerInfo->dwSignature == 0xfeef04bd)
						Version = ((UINT64)VerInfo->dwFileVersionMS << 32) | VerInfo->dwFileVersionLS;
				}
			}
		}

		PopMem(Arena);
	}

	return Version;
}

static UINT64 HashFileContent(LPCWSTR FilePath, struct memory_arena* Arena){
	HANDLE File = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if(File == INVALID_HANDLE_VALUE)
		FatalError(STR("Unable to open file"), StringFromWchar(FilePath));

	LARGE_INTEGER FileSize;

	if(!GetFileSizeEx(File, &FileSize))
		FatalError(STR("Unable to determine file size"), StringFromWchar(FilePath));

	if(FileSize.QuadPart == 0)
		return 0;

	void* Data = PushMem(Arena, FileSize.QuadPart);
	DWORD NumBytesRead;

	if(!ReadFile(File, Data, (DWORD)FileSize.QuadPart, &NumBytesRead, NULL))
		FatalError(STR("Unable to read from file"), StringFromWchar(FilePath));

	UINT64 Hash = XXH3_64bits(Data, FileSize.QuadPart);

	CloseHandle(File);
	PopMem(Arena);

	return Hash;
}

static BOOL IsLinkerFlag(LPCWSTR flag){
	return (flag[0] == 'F' && IsDigit(flag[1])) ||
	       *flag == 'l' ||
	       *flag == 'L';
}

static BOOL IsPreprocessorFlag(LPCWSTR flag) {
	return (flag[0] == 'A' && flag[1] == 'I') ||
	       *flag == 'C' ||
	       *flag == 'D' ||
	       (flag[0] == 'E' && flag[1] != 'H') ||
	       (flag[0] == 'F' && (flag[1] == 'I' || flag[1] == 'U' || flag[1] == 'x')) ||
	       *flag == 'I' ||
	       *flag == 'P' ||
	       *flag == 'U' ||
	       *flag == 'u' ||
	       *flag == 'X';
}

static BOOL BuildCommandInfo(int argc, LPWSTR* argv, struct cl_command_info* Command, struct memory_arena* Arena){
	ZeroMemory(Command, sizeof(*Command));

	Command->Executable = StringFromWchar(argv[1]);
	Command->ClVersion = GetCompilerVersion(argv[1], Arena);

	if(!Command->ClVersion)
		return FALSE;

	Command->IncludePaths = PushMem(Arena, argc * sizeof(struct string));
	Command->CompilerFlags = PushMem(Arena, (argc - 2) * sizeof(struct string));

	Command->IncludePathCount = 1;
	Command->IncludePaths[0].Data = PushMem(Arena, MAX_PATH);
	Command->IncludePaths[0].Length = GetCurrentDirectoryW(MAX_PATH, (LPWSTR)Command->IncludePaths[0].Data);

	BOOL CompilesToObj = FALSE;

	for(int i = 2; i < argc; ++i){
		if(*argv[i] == '/' || *argv[i] == '-'){
			LPCWSTR Flag = argv[i] + 1;

			if(IsLinkerFlag(Flag))
				return FALSE;

			if(IsPreprocessorFlag(Flag)){
				if(*Flag == 'E' || *Flag == 'P') // Only preprocessor, no compilation so nothing to cache...
					return FALSE;

				if(*Flag == 'I'){
					Command->IncludePaths[Command->IncludePathCount++] = StringFromWchar(Flag + 1);
					continue;
				}
			}else if(*Flag == 'F'){
				switch(Flag[1]){
				case 'o':
					// output file
					Flag += 2; // Skip Fo

					if(*Flag == ':') // ':' is optional
						++Flag;

					Command->ObjFile = TrimString(StringFromWchar(Flag));
					continue;
				// The /FS and /Fd flags are ignored because pdb files are generated individually for each object file
				case 'd':
				case 'S':
					continue;
				}
			}else if(Flag[0] == 'Z' && (Flag[1] == 'i' || Flag[1] == 'I')){
				Command->GeneratesPdb = TRUE;
			}else if(Flag[0] == 'c' && Flag[1] == '\0'){
				CompilesToObj = TRUE;
			}else if(CompareStringOrdinal(Flag, -1, L"nologo", -1, FALSE) == CSTR_EQUAL){
				// /nologo is a commonly used flag whose presence has no effect on the compilation result. So just check if it is present and add it back later after the other options are hashed.
				Command->NoLogo = TRUE;
				continue;
			}else if(CompareStringOrdinal(Flag, -1, L"showIncludes", -1, FALSE) == CSTR_EQUAL){
				// /showIncludes is set by clcache in order to hash all included files. If the flag was also added by the caller, the includes should not be stripped from the command output later.
				Command->ShowIncludes = TRUE;
				continue;
			}
		}else{
			if(Command->SrcFile.Length > 0)
				return FALSE; // Multiple source files are not supported

			Command->SrcFile = StringFromWchar(argv[i]);
			continue;
		}

		// Add flag to compiler command line so it can be hashed later
		Command->CompilerFlags[Command->CompilerFlagCount++] = StringFromWchar(argv[i]);
	}

	if(Command->SrcFile.Length == 0 || Command->SrcFile.Length >= MAX_PATH)
		return FALSE;

	if(!CompilesToObj) // Only compile commands that result in object files are cacheable
		return FALSE;

	// Set object file name if it wasn't explicitly specified

	if(Command->ObjFile.Length == 0){
		struct string SrcFileBaseName = FilePathWithoutExtension(Command->SrcFile);
		void* Mem = PushMem(Arena, (SrcFileBaseName.Length + 4) * sizeof(WCHAR));
		struct string_buffer TempBuffer = MakeStringBuffer(Mem, SrcFileBaseName.Length + 4);
		Command->ObjFile = PushString(SrcFileBaseName, &TempBuffer);
		Command->ObjFile.Length += PushString(STR(".obj"), &TempBuffer).Length;
	}

	// Set pdb file name based on object file name

	if(Command->GeneratesPdb){
		struct string ObjFileBaseName = FilePathWithoutExtension(Command->ObjFile);
		void* Mem = PushMem(Arena, (ObjFileBaseName.Length + 4) * sizeof(WCHAR));
		struct string_buffer TempBuffer = MakeStringBuffer(Mem, ObjFileBaseName.Length + 4);
		Command->PdbFile = PushString(ObjFileBaseName, &TempBuffer);
		Command->PdbFile.Length += PushString(STR(".pdb"), &TempBuffer).Length;
	}

	// Collect system include paths from the INCLUDE environment variable

	LPWSTR EnvVarBuffer = PushMem(Arena, MAX_COMMAND_LINE_LENGTH * sizeof(WCHAR));
	DWORD EnvVarLength = GetEnvironmentVariableW(L"INCLUDE", EnvVarBuffer, MAX_COMMAND_LINE_LENGTH);

	if(EnvVarLength > 0){
		PopPartialMem(Arena, (MAX_COMMAND_LINE_LENGTH - EnvVarLength) * sizeof(WCHAR));

		Command->SystemIncludePathCount = 1;

		for(LPCWSTR c = EnvVarBuffer; *c; ++c){
			if(*c == ';')
				++Command->SystemIncludePathCount;
		}

		Command->SystemIncludePaths = PushMem(Arena, Command->SystemIncludePathCount * sizeof(struct string));

		struct string* Path = Command->SystemIncludePaths;
		Path->Data = EnvVarBuffer;
		Path->Length = 0;

		for(LPCWSTR c = EnvVarBuffer; *c; ++c){
			if(*c == ';'){
				++Path;
				Path->Data = c + 1;
				Path->Length = 0;
				continue;
			}

			++Path->Length;
		}
	}else{
		PopMem(Arena);
	}

	return TRUE;
}

static struct string HashToPath(UINT64 Hash, struct string_buffer* Buffer){
	BYTE* Bytes = (BYTE*)&Hash;
	size_t Length = 20; // AA/BB/CCCC/DDDDDDDD/
	LPWSTR Chars = PushChars(Length, Buffer);

	Chars[0] = HexLookup[Bytes[0] & 0x0F];
	Chars[1] = HexLookup[(Bytes[0] >> 4) & 0x0F];
	Chars[2] = '\\';

	Chars[3] = HexLookup[Bytes[1] & 0x0F];
	Chars[4] = HexLookup[(Bytes[1] >> 4) & 0x0F];
	Chars[5] = '\\';

	Chars[6] = HexLookup[Bytes[2] & 0x0F];
	Chars[7] = HexLookup[(Bytes[2] >> 4) & 0x0F];
	Chars[8] = HexLookup[Bytes[3] & 0x0F];
	Chars[9] = HexLookup[(Bytes[3] >> 4) & 0x0F];
	Chars[10] = '\\';

	Chars[11] = HexLookup[Bytes[4] & 0x0F];
	Chars[12] = HexLookup[(Bytes[4] >> 4) & 0x0F];
	Chars[13] = HexLookup[Bytes[5] & 0x0F];
	Chars[14] = HexLookup[(Bytes[5] >> 4) & 0x0F];
	Chars[15] = HexLookup[Bytes[6] & 0x0F];
	Chars[16] = HexLookup[(Bytes[6] >> 4) & 0x0F];
	Chars[17] = HexLookup[Bytes[7] & 0x0F];
	Chars[18] = HexLookup[(Bytes[7] >> 4) & 0x0F];
	Chars[19] = '\\';

	return MakeString(Chars, Length);
}

static struct string HashToDirName(UINT32 Hash, struct string_buffer* Buffer){
	BYTE* Bytes = (BYTE*)&Hash;
	size_t Length = sizeof(UINT32) * 2; // 2 chars per byte
	LPWSTR Chars = PushChars(Length, Buffer);

	for(int i = 0; i < (int)sizeof(UINT32); ++i) {
		int Index = i * 2;

		Chars[Index] = HexLookup[Bytes[i] & 0x0F];
		Chars[Index + 1] = HexLookup[(Bytes[i] >> 4) & 0x0F];
	}

	return MakeString(Chars, Length);
}

static struct string ClVersionToString(UINT64 Version, struct string_buffer* Buffer){
	struct string Str = UINT64ToString(Version >> 48, Buffer);
	Str.Length += PushString(STR("."), Buffer).Length;
	Str.Length += UINT64ToString((Version >> 32) & 0xFFFF, Buffer).Length;
	Str.Length += PushString(STR("."), Buffer).Length;
	Str.Length += UINT64ToString((Version >> 16) & 0xFFFF, Buffer).Length;
	Str.Length += PushString(STR("."), Buffer).Length;
	Str.Length += UINT64ToString(Version & 0xFFFF, Buffer).Length;

	return Str;
}

static LPWSTR BuildCommandLine(const struct cl_command_info* Command, struct memory_arena* Arena, struct string* CompilerFlags){
	struct string_buffer CmdLineBuffer = MakeStringBuffer(PushMem(Arena, MAX_COMMAND_LINE_LENGTH * sizeof(WCHAR)), MAX_COMMAND_LINE_LENGTH);
	PushCmdLineArg(Command->Executable, &CmdLineBuffer);

	// Skip the first include path because that's the current directory which was added in BuildCommandInfo but shouldn't actually be passed to cl.exe
	for(int i = 1; i < Command->IncludePathCount; ++i){
		PushCmdLineArg(STR("\"/I"), &CmdLineBuffer);
		PushString(Command->IncludePaths[i], &CmdLineBuffer);
		PushString(STR("\""), &CmdLineBuffer);
	}

	SortStrings(Command->CompilerFlags, Command->CompilerFlagCount);

	*CompilerFlags = PushCmdLineArg(Command->CompilerFlags[0], &CmdLineBuffer); // There's always at least one compiler flag (/c)

	for(int i = 1; i < Command->CompilerFlagCount; ++i)
		CompilerFlags->Length += PushCmdLineArg(Command->CompilerFlags[i], &CmdLineBuffer).Length;

	if(Command->NoLogo)
		PushCmdLineArg(STR("/nologo"), &CmdLineBuffer);

	PushCmdLineArg(STR("/showIncludes"), &CmdLineBuffer); // showIncludes is always needed because the command output is parsed to get all included files
	PushCmdLineArg(Command->SrcFile, &CmdLineBuffer);
	PushCmdLineArg(STR("\"/Fo:"), &CmdLineBuffer);
	PushString(Command->ObjFile, &CmdLineBuffer);
	PushString(STR("\""), &CmdLineBuffer);

	if(Command->GeneratesPdb){
		ASSERT(Command->PdbFile.Length > 0);
		PushCmdLineArg(STR("\"/Fd:"), &CmdLineBuffer);
		PushString(Command->PdbFile, &CmdLineBuffer);
	}

	PushString(STR("\0"), &CmdLineBuffer);
	PopPartialMem(Arena, CmdLineBuffer.Size - CmdLineBuffer.Used);

	return CmdLineBuffer.Data;
}

static struct string_buffer BuildCachePath(const struct cl_command_info* Command, struct memory_arena* Arena, struct string CompilerFlags){
	struct string_buffer PathBuffer = MakeStringBuffer(PushMem(Arena, MAX_PATH * sizeof(WCHAR)), MAX_PATH);

	// Hash input source file

	PathBuffer.Data[PushString(Command->SrcFile, &PathBuffer).Length] = '\0';

	UINT64 FileHash = HashFileContent(PathBuffer.Data, Arena);

	// Build hash path using compiler version, source file hash and compiler command line hash

	CopyMemory(PathBuffer.Data, GlobalConfig.CachePath, MAX_PATH * sizeof(WCHAR));
	PathBuffer.Used = lstrlenW(PathBuffer.Data);

	if(PathBuffer.Data[PathBuffer.Used] != '\\')
		PushString(STR("\\"), &PathBuffer);

	ClVersionToString(Command->ClVersion, &PathBuffer);
	PushString(STR("\\"), &PathBuffer);
	HashToPath(FileHash, &PathBuffer);
	HashToDirName(XXH32(CompilerFlags.Data, CompilerFlags.Length * sizeof(WCHAR), 0), &PathBuffer);
	PushString(STR("\\"), &PathBuffer);
	PathBuffer.Data[PathBuffer.Used] = '\0';

	return PathBuffer;
}

static struct dependency_info ReadDepFile(LPCWSTR Path, struct memory_arena* Arena){
	HANDLE File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if(File == INVALID_HANDLE_VALUE)
		FatalError(STR("Unable to open dependency file for reading"), StringFromWchar(Path));

	LARGE_INTEGER FileSize;

	if(!GetFileSizeEx(File, &FileSize))
		FatalError(STR("Unable to determine file size"), StringFromWchar(Path));

	BYTE* Buffer = PushMem(Arena, FileSize.QuadPart);
	DWORD NumBytesRead;

	if(!ReadFile(File, Buffer, (DWORD)FileSize.QuadPart, &NumBytesRead, NULL))
		FatalError(STR("Unable to read from dependency file"), StringFromWchar(Path));

	CloseHandle(File);

	struct dependency_info DepInfo;
	DepInfo.EntryCount = *((UINT32*)Buffer);
	Buffer += sizeof(UINT64);
	DepInfo.Entries = PushMem(Arena, sizeof(struct dependency_entry) * DepInfo.EntryCount);

	for(UINT32 i = 0; i < DepInfo.EntryCount; ++i){
		DepInfo.Entries[i].Size = *((UINT64*)Buffer);
		Buffer += sizeof(UINT64);
		DepInfo.Entries[i].LastModified = *((UINT64*)Buffer);
		Buffer += sizeof(UINT64);
		DepInfo.Entries[i].Hash = *((UINT64*)Buffer);
		Buffer += sizeof(UINT64);
	}

	for(UINT32 i = 0; i < DepInfo.EntryCount; ++i){
		DepInfo.Entries[i].FileName.Length = *((UINT16*)Buffer);
		Buffer += sizeof(UINT16);
		DepInfo.Entries[i].FileName.Data = (LPCWSTR)Buffer;
		Buffer += DepInfo.Entries[i].FileName.Length * sizeof(WCHAR);
	}

	return DepInfo;
}

static void WriteDepFile(LPCWSTR Path, const struct dependency_info* Deps, struct memory_arena* Arena){
	DWORD FileSize = sizeof(UINT64) + Deps->EntryCount * sizeof(UINT64) * 3 + Deps->EntryCount * sizeof(UINT16);

	for(UINT32 i = 0; i < Deps->EntryCount; ++i)
		FileSize += (DWORD)Deps->Entries[i].FileName.Length * sizeof(WCHAR);

	void* Buffer = PushMem(Arena, FileSize);
	BYTE* BufferPos = Buffer;

	*((UINT32*)BufferPos) = Deps->EntryCount;
	BufferPos += sizeof(UINT64);

	for(UINT32 i = 0; i < Deps->EntryCount; ++i){
		*((UINT64*)BufferPos) = Deps->Entries[i].Size;
		BufferPos += sizeof(UINT64);
		*((UINT64*)BufferPos) = Deps->Entries[i].LastModified;
		BufferPos += sizeof(UINT64);
		*((UINT64*)BufferPos) = Deps->Entries[i].Hash;
		BufferPos += sizeof(UINT64);
	}

	for(UINT32 i = 0; i < Deps->EntryCount; ++i){
		*((UINT16*)BufferPos) = (UINT16)Deps->Entries[i].FileName.Length;
		BufferPos += sizeof(UINT16);
		CopyMemory(BufferPos, Deps->Entries[i].FileName.Data, Deps->Entries[i].FileName.Length * sizeof(WCHAR));
		BufferPos += Deps->Entries[i].FileName.Length * sizeof(WCHAR);
	}

	HANDLE File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if(File == INVALID_HANDLE_VALUE)
		FatalError(STR("Unable to open dependency file for writing"), StringFromWchar(Path));

	DWORD NumBytesWritten;

	if(!WriteFile(File, Buffer, FileSize, &NumBytesWritten, NULL))
		FatalError(STR("Unable to write to dependency file"), StringFromWchar(Path));

	CloseHandle(File);
	PopMem(Arena);
}

static struct dependency_info GenerateDeps(const struct cl_command_info* Command, struct string CommandStdout, struct memory_arena* Arena){
	UINT64 StrIndex = 0;
	struct string LineStart = StringFromWchar(ShowIncludeLineStart);

	struct include_file{
		struct include_file* Next;
		struct string        IncludePath;
		struct string        FileName;
	};

	struct include_file* First = NULL;
	struct include_file** Temp = &First;
	struct dependency_info Deps;

	Deps.EntryCount = 0;

	while(StrIndex < CommandStdout.Length){
		struct string Line = StringMid(CommandStdout, StrIndex, 0);

		while(StrIndex + Line.Length < CommandStdout.Length && Line.Data[Line.Length] != '\n')
			++Line.Length;

		Line.Length += Line.Data[Line.Length] == '\n';

		if(StringStartsWith(Line, LineStart)){
			struct string IncludePath = STR("");
			struct string FilePath = TrimString(StringRight(Line, Line.Length - LineStart.Length));
			BOOL FoundFile = FALSE;

			for(int i = 0; i < Command->IncludePathCount; ++i){
				if(StringStartsWithCaseInsensitive(FilePath, Command->IncludePaths[i])){
					IncludePath = Command->IncludePaths[i];
					FilePath = StringRight(FilePath, FilePath.Length - IncludePath.Length);
					FoundFile = TRUE;
					break;
				}
			}

			if(!FoundFile){
				for(int i = 0; i < Command->SystemIncludePathCount; ++i){
					if(StringStartsWithCaseInsensitive(FilePath, Command->SystemIncludePaths[i])){
						IncludePath = Command->SystemIncludePaths[i];
						FilePath = StringRight(FilePath, FilePath.Length - IncludePath.Length);
						FoundFile = TRUE;
						break;
					}
				}
			}

			*Temp = PushMem(Arena, sizeof(struct include_file));
			(*Temp)->IncludePath = IncludePath;
			(*Temp)->FileName = FilePath;
			(*Temp)->Next = NULL;
			Temp = &(*Temp)->Next;
			++Deps.EntryCount;
		}

		StrIndex += Line.Length;
	}

	Deps.Entries = PushMem(Arena, Deps.EntryCount * sizeof(struct dependency_entry));

	struct include_file* Inc = First;

	for(UINT32 i = 0; i < Deps.EntryCount; ++i){
		WCHAR TempPath[MAX_PATH];

		CopyMemory(TempPath, Inc->IncludePath.Data, Inc->IncludePath.Length * sizeof(WCHAR));
		CopyMemory(&TempPath[Inc->IncludePath.Length], Inc->FileName.Data, Inc->FileName.Length * sizeof(WCHAR));
		TempPath[Inc->IncludePath.Length + Inc->FileName.Length] = '\0';

		GetFileSizeLastModified(TempPath, &Deps.Entries[i].Size, &Deps.Entries[i].LastModified);
		Deps.Entries[i].Hash = HashFileContent(TempPath, Arena);
		Deps.Entries[i].FileName = Inc->FileName;
		Inc = Inc->Next;
	}

	return Deps;
}

static BOOL CacheUpToDate(const struct cl_command_info* Command, struct string_buffer* CachePathBuffer, struct memory_arena* Arena){
	struct string CachePath = MakeString(CachePathBuffer->Data, CachePathBuffer->Used);
	(void)CachePath;
	ASSERT(CachePath.Length > 0);
	ASSERT(CachePath.Data[CachePath.Length - 1] == '\\');

	size_t CachePathLength = CachePathBuffer->Used;
	PushString(STR("dep\0"), CachePathBuffer);

	CachePathBuffer->Used = CachePathLength; // Reset here already. The buffer is not used anymore so the pushed data stays valid.

	if(!FileExists(CachePathBuffer->Data))
		return FALSE;

	struct dependency_info Deps = ReadDepFile(CachePathBuffer->Data, Arena);

	for(UINT32 i = 0; i < Deps.EntryCount; ++i){
		WCHAR TempBufferData[MAX_PATH];
		struct string_buffer TempBuffer = MakeStringBuffer(TempBufferData, ARRAYSIZE(TempBufferData));
		struct string FileName = Deps.Entries[i].FileName;
		BOOL FoundFile = FALSE;

		for(int j = 0; j < Command->IncludePathCount; ++j){
			if(Command->IncludePaths[j].Length + FileName.Length + 2 >= MAX_PATH)
				continue;

			TempBuffer.Used = 0;
			PushString(Command->IncludePaths[j], &TempBuffer);
			PushString(STR("\\"), &TempBuffer);
			PushString(FileName, &TempBuffer);
			TempBufferData[TempBuffer.Used] = '\0';

			if(FileExists(TempBufferData)){
				FoundFile = TRUE;
				break;
			}
		}

		if(!FoundFile){
			for(int j = 0; j < Command->SystemIncludePathCount; ++j){
				if(Command->SystemIncludePaths[j].Length + FileName.Length + 2 >= MAX_PATH)
					continue;

				TempBuffer.Used = 0;
				PushString(Command->SystemIncludePaths[j], &TempBuffer);
				PushString(STR("\\"), &TempBuffer);
				PushString(FileName, &TempBuffer);
				TempBufferData[TempBuffer.Used] = '\0';

				if(FileExists(TempBufferData)){
					FoundFile = TRUE;
					break;
				}
			}
		}

		UINT64 Size;
		UINT64 LastModified;

		if(FoundFile && GetFileSizeLastModified(TempBufferData, &Size, &LastModified)){
			if(Size == Deps.Entries[i].Size){
				if(LastModified != Deps.Entries[i].LastModified){
					if(HashFileContent(TempBufferData, Arena) != Deps.Entries[i].Hash)
						return FALSE;
				}
			}else{
				return FALSE;
			}
		}
	}

	return TRUE;
}

static void WriteConsoleFiltered(struct string Str, HANDLE OutputHandle, struct string ExcludeFilter){
	if(ExcludeFilter.Length == 0){
		WriteConsoleW(OutputHandle, Str.Data, (DWORD)Str.Length, NULL, NULL);
	}else{
		UINT64 StrIndex = 0;

		while(StrIndex < Str.Length){
			struct string Line = StringMid(Str, StrIndex, 0);

			while(StrIndex + Line.Length < Str.Length && Line.Data[Line.Length] != '\n')
				++Line.Length;

			Line.Length += Line.Data[Line.Length] == '\n';

			if(!StringStartsWith(Line, ExcludeFilter))
				WriteConsoleW(OutputHandle, Line.Data, (DWORD)Line.Length, NULL, NULL);

			StrIndex += Line.Length;
		}
	}
}

static void DumpWCharTextFileToConsole(LPCWSTR Path, HANDLE OutputHandle, struct string ExcludeFilter, struct memory_arena* Arena){
	if(!FileExists(Path))
		return;

	HANDLE File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if(File == INVALID_HANDLE_VALUE)
		return;

	LARGE_INTEGER FileSize;

	if(GetFileSizeEx(File, &FileSize)){
		LPWSTR Content = PushMem(Arena, FileSize.QuadPart);
		DWORD NumBytesRead;

		if(ReadFile(File, Content, (DWORD)FileSize.QuadPart, &NumBytesRead, NULL)){
			CloseHandle(File);
			WriteConsoleFiltered(MakeString(Content, FileSize.QuadPart / sizeof(WCHAR)), OutputHandle, ExcludeFilter);
		}

		PopMem(Arena);
	}else{
		CloseHandle(File);
	}
}

static struct string ReadUtf8FileToString(HANDLE File, struct memory_arena* Arena){
	if(File == INVALID_HANDLE_VALUE)
		return STR("");

	SetFilePointer(File, 0, NULL, FILE_BEGIN);

	LARGE_INTEGER FileSize;

	if(GetFileSizeEx(File, &FileSize)){
		LPWSTR StringData = PushMem(Arena, FileSize.QuadPart * sizeof(WCHAR));
		size_t StringLength = 0;
		LPSTR Utf8Buffer = PushMem(Arena, FileSize.QuadPart);
		DWORD NumBytesRead;

		if(ReadFile(File, Utf8Buffer, (DWORD)FileSize.QuadPart, &NumBytesRead, NULL))
			StringLength = (size_t)MultiByteToWideChar(CP_UTF8, 0, Utf8Buffer, (int)FileSize.QuadPart, StringData, (int)FileSize.QuadPart);

		PopMem(Arena);

		return MakeString(StringData, StringLength);
	}

	return STR("");
}

static int InvokeCompiler(LPWSTR CmdLine, const struct cl_command_info* Command, struct string_buffer* CachePathBuffer, struct memory_arena* Arena){
		WCHAR StdoutTempFileName[MAX_PATH];
		WCHAR StderrTempFileName[MAX_PATH];

		GetTempFileNameW(L".", L"err", 0, StdoutTempFileName);
		GetTempFileNameW(L".", L"out", 0, StderrTempFileName);

		SECURITY_ATTRIBUTES SecurityAttributes;
		SecurityAttributes.nLength = sizeof(SecurityAttributes);
		SecurityAttributes.lpSecurityDescriptor = NULL;
		SecurityAttributes.bInheritHandle = TRUE;

		HANDLE StdoutFile = CreateFileW(StdoutTempFileName,
																		GENERIC_READ | GENERIC_WRITE,
																		FILE_SHARE_READ | FILE_SHARE_WRITE,
																		&SecurityAttributes,
																		OPEN_ALWAYS,
																		FILE_ATTRIBUTE_NORMAL,
																		NULL);
		HANDLE StderrFile = CreateFileW(StderrTempFileName,
																		GENERIC_READ | GENERIC_WRITE,
																		FILE_SHARE_READ | FILE_SHARE_WRITE,
																		&SecurityAttributes,
																		OPEN_ALWAYS,
																		FILE_ATTRIBUTE_NORMAL,
																		NULL);
		PROCESS_INFORMATION Process;

		StartProcess(CmdLine, &Process, StdoutFile, StderrFile);

		int ExitCode = (int)WaitForProcessToFinish(&Process);

		struct string StdoutString = ReadUtf8FileToString(StdoutFile, Arena);
		struct string StderrString = ReadUtf8FileToString(StderrFile, Arena);

		CloseHandle(StdoutFile);
		CloseHandle(StderrFile);
		DeleteFileW(StdoutTempFileName);
		DeleteFileW(StderrTempFileName);
		WriteConsoleFiltered(StdoutString, StdoutHandle, Command->ShowIncludes ? STR("") : StringFromWchar(ShowIncludeLineStart));
		WriteConsoleFiltered(StderrString, StderrHandle, STR(""));

		size_t CachePathLength = CachePathBuffer->Used;

		MakePath(MakeString(CachePathBuffer->Data, CachePathBuffer->Used));

		WCHAR TempPath[MAX_PATH];

		CopyMemory(TempPath, Command->ObjFile.Data, Command->ObjFile.Length * sizeof(WCHAR));
		TempPath[Command->ObjFile.Length] = '\0';
		PushString(STR("obj"), CachePathBuffer);
		CopyFileW(TempPath, CachePathBuffer->Data, FALSE);

		if(Command->GeneratesPdb){
			CopyMemory(TempPath, Command->PdbFile.Data, Command->PdbFile.Length * sizeof(WCHAR));
			TempPath[Command->PdbFile.Length] = '\0';
			CachePathBuffer->Used = CachePathLength;
			PushString(STR("pdb"), CachePathBuffer);
			CopyFileW(TempPath, CachePathBuffer->Data, FALSE);
		}

		CachePathBuffer->Used = CachePathLength;
		PushString(STR("out"), CachePathBuffer);
		WriteDataToFile(CachePathBuffer->Data, StdoutString.Data, StdoutString.Length * sizeof(WCHAR));

		CachePathBuffer->Used = CachePathLength;
		PushString(STR("err"), CachePathBuffer);
		WriteDataToFile(CachePathBuffer->Data, StderrString.Data, StderrString.Length * sizeof(WCHAR));

		struct dependency_info Deps = GenerateDeps(Command, StdoutString, Arena);
		CachePathBuffer->Used = CachePathLength;
		PushString(STR("dep"), CachePathBuffer);
		WriteDepFile(CachePathBuffer->Data, &Deps, Arena);

		return ExitCode;
}

static int CacheMain(int argc, LPWSTR* argv){
	if(!StringsAreEqual(FileNameWithoutPath(StringFromWchar(argv[1])), STR("cl.exe"))){
		WriteStderr(STR("ERROR: First argument is expected to be the path to cl.exe"));

		return 1;
	}

	struct cl_command_info Command;
	struct memory_arena Arena = CreateMemory(GIGABYTES(1));

	if(BuildCommandInfo(argc, argv, &Command, &Arena)){
		struct string CompilerFlags;
		LPWSTR CmdLine = BuildCommandLine(&Command, &Arena, &CompilerFlags);
		struct string_buffer CachePathBuffer = BuildCachePath(&Command, &Arena, CompilerFlags);

		if(CacheUpToDate(&Command, &CachePathBuffer, &Arena)){
			size_t CachePathLength = CachePathBuffer.Used;

			PushString(STR("obj"), &CachePathBuffer);

			WCHAR TempPath[MAX_PATH];

			CopyMemory(TempPath, Command.ObjFile.Data, Command.ObjFile.Length * sizeof(WCHAR));
			TempPath[Command.ObjFile.Length] = '\0';

			if(!CopyFileW(CachePathBuffer.Data, TempPath, FALSE)){
				WriteStderr(STR("Unable to copy cached obj file to destination: "));
				WriteStderr(MakeString(CachePathBuffer.Data, CachePathBuffer.Used));
				WriteStderr(STR(" -> "));
				WriteStderr(StringFromWchar(TempPath));
				WriteStderr(STR("\n"));
				CachePathBuffer.Used = CachePathLength;
				return InvokeCompiler(CmdLine, &Command, &CachePathBuffer, &Arena);
			}

			if(Command.GeneratesPdb){
				CopyMemory(TempPath, Command.PdbFile.Data, Command.PdbFile.Length * sizeof(WCHAR));
				TempPath[Command.PdbFile.Length] = '\0';

				CachePathBuffer.Used = CachePathLength;
				PushString(STR("pdb"), &CachePathBuffer);

				if(!CopyFileW(CachePathBuffer.Data, TempPath, FALSE)){
					WriteStderr(STR("Unable to copy cached pdb file to destination: "));
					WriteStderr(MakeString(CachePathBuffer.Data, CachePathBuffer.Used));
					WriteStderr(STR(" -> "));
					WriteStderr(StringFromWchar(TempPath));
					WriteStderr(STR("\n"));
					CachePathBuffer.Used = CachePathLength;
					return InvokeCompiler(CmdLine, &Command, &CachePathBuffer, &Arena);
				}
			}

			CachePathBuffer.Used = CachePathLength;
			PushString(STR("out"), &CachePathBuffer);
			DumpWCharTextFileToConsole(CachePathBuffer.Data, StdoutHandle, Command.ShowIncludes ? STR("") : StringFromWchar(ShowIncludeLineStart), &Arena);

			CachePathBuffer.Used = CachePathLength;
			PushString(STR("err"), &CachePathBuffer);
			DumpWCharTextFileToConsole(CachePathBuffer.Data, StderrHandle, STR(""), &Arena);

			return 0;
		}else{
			return InvokeCompiler(CmdLine, &Command, &CachePathBuffer, &Arena);
		}
	}else{ // Uncacheable so pass command line directly to cl.exe
		LPWSTR CmdLine = GetCommandLineW();

		// Strip clcache.exe from command line. Either quoted or unquoted
		if(*CmdLine == '\"'){
			++CmdLine;

			while(*CmdLine && *CmdLine != '\"')
				++CmdLine;

			if(*CmdLine == '\"')
				++CmdLine;

			while(IsWhitespace(*CmdLine))
				++CmdLine;
		}else{
			while(!IsWhitespace(*CmdLine))
				++CmdLine;

			while(IsWhitespace(*CmdLine))
				++CmdLine;
		}

		PROCESS_INFORMATION Process;

		StartProcess(CmdLine, &Process, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE);

		return (int)WaitForProcessToFinish(&Process);
	}
}

/*
 * Main
 */

static void PrintHelpText(void){
	WriteStdout(STR(
		"Available options:\n"
		" -h      show this help\n"
		" -i      show info\n"
		" -m<n>   set maximum cache size to n gigabytes\n"
		" -p<dir> set cache path to <dir>\\.clcache\n"
	));
}

#ifdef NO_CRT
int mainCRTStartup(){
	int argc = 0;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
#else
int wmain(int argc, LPWSTR* argv){
#endif
	StdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	StderrHandle = GetStdHandle(STD_ERROR_HANDLE);

	if(argc <= 1){
		WriteStderr(STR(
			"Usage:\n"
			"    clcache.exe <path_to_cl.exe> <cl_args>\n"
			"  or\n"
			"    clcache.exe <options> # -h for a list of available options\n"
		));

		ExitProcess(1);
	}

	// Initialize config file path
	{
		PWSTR LocalAppData;

		ConfigFilePath[0] = '\0';
		SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &LocalAppData);
		lstrcpyW(ConfigFilePath, LocalAppData);
		CoTaskMemFree(LocalAppData);
		lstrcatW(ConfigFilePath, L"\\clcache");
		MakePath(StringFromWchar(ConfigFilePath));
		lstrcatW(ConfigFilePath, L"\\cache.config");
	}

	ReadConfig(&GlobalConfig);

	if(*argv[1] == '-'){
		for(int i = 1; i < argc; ++i){
			LPWSTR Arg = argv[i] + 1;

			switch(*Arg){
			case 'h':
				PrintHelpText();
				break;
			case 'i':
				{
					WriteStdout(STR("Configuration: "));
					WriteStdout(StringFromWchar(ConfigFilePath));
					WriteStdout(STR("\nCache path:    "));
					WriteStdout(StringFromWchar(GlobalConfig.CachePath));
					WriteStdout(STR("\nCache size:    "));

					WCHAR BufferData[20]; // 20 chars is the max length for a UINT64
					struct string_buffer Buffer = MakeStringBuffer(BufferData, ARRAYSIZE(BufferData));

					WriteStdout(UINT64ToString(GlobalConfig.CacheSize / GIGABYTES(1), &Buffer));
					WriteStdout(STR(" GB\n"));
					break;
				}
			case 'm':
				{
					++Arg;

					if(*Arg == '\0' && i != argc - 1)
							Arg = argv[++i];

					if(!IsDigit(*Arg)){
						WriteStderr(STR("The -m option expects a number in gigabytes"));

						ExitProcess(1);
					}

					UINT64 NewCacheSize = StringToUINT64(StringFromWchar(Arg));

					if(NewCacheSize >= 1){
						GlobalConfig.CacheSize = GIGABYTES(NewCacheSize); // TODO: Clean up the cache if necessary
						WriteConfig(&GlobalConfig);
					}else{
						WriteStderr(STR("ERROR: Cache size must be at least 1 gigabyte"));

						ExitProcess(1);
					}
				}

				break;
			case 'p':
				{
					++Arg;

					if(*Arg == '\0' && i != argc - 1)
						Arg = argv[++i];

					if(*Arg == '\0' || *Arg == '-'){
						WriteStderr(STR("ERROR: the -p option expects a path as an argument"));

						ExitProcess(1);
					}

					WCHAR Buffer[MAX_PATH];

					while(*Arg == ' ' || *Arg == '\t')
						++Arg;

					DWORD PathLength = GetFullPathNameW(Arg, MAX_PATH, Buffer, NULL);

					if(PathLength + CACHE_PATH_LENGTH >= MAX_PATH || PathLength == 0){
						WriteStderr(STR("Invalid cache path"));

						ExitProcess(1);
					}

					Arg = Buffer + lstrlenW(Buffer);

					while(Arg != Buffer && IsPathSeparator(*(Arg - 1))){ // Remove trailing path separators
						--Arg;
						*Arg = '\0';
					}

					if(!StringEndsWith(StringFromWchar(Buffer), STR("\\.clcache")))
						lstrcatW(Buffer, L"\\.clcache");

					lstrcpyW(GlobalConfig.CachePath, Buffer);
					WriteConfig(&GlobalConfig);
				}

				break;
			default:
				WriteStderr(STR("Unknown option: "));
				WriteStderr(StringFromWchar(argv[i]));
				WriteStderr(STR("\n"));

				ExitProcess(1);
			}
		}
	}else{
		ExitProcess(CacheMain(argc, argv));
	}

	ExitProcess(0);
}

/*
 * crt
 */

#ifdef NO_CRT
#pragma function(memset,memcpy,memmove)

void* CDECL memset(void* Dest, int Fill, size_t Size){
	const BYTE Val = (BYTE)Fill;

	for(BYTE* D = Dest; Size; --Size, ++D)
		*D = Val;

	return Dest;
}

void* CDECL memcpy(void* Dest, const void* Src, size_t Size){
	const BYTE* SrcByte = Src;
	BYTE* DestByte = Dest;

	while(Size){
		*DestByte = *SrcByte;
		++DestByte;
		++SrcByte;
		--Size;
	}

	return Dest;
}

void* CDECL memmove(void* Dest, const void* Src, size_t Size){
	if(Dest == Src || Size == 0)
		return Dest;

	if((BYTE*)Dest >= (BYTE*)Src + Size || Dest > Src){
		memcpy(Dest, Src, Size);
	}else{
		while(Size){
			--Size;
			((BYTE*)Dest)[Size] = ((BYTE*)Src)[Size];
		}
	}

	return Dest;
}
#endif