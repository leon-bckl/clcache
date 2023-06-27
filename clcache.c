#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <shellapi.h>
#include <ShlObj.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "Version.lib")

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
 * - if an error occurs like not being able to read a file, just invoke the compiler and don't call FatalError
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

#define IS_POW2(x) ((x) && !((x) & ((x) - 1)))
#define ALIGN_POW2(val, align) (((val) + (align) - 1) & ~((align) - 1))

#define ALIGNOF(type) offsetof(struct{ char c; type d; }, d)

/*
 * Constants
 */

#define INVALID_INDEX (-1)
#define MAX_COMMAND_LINE_LENGTH 32768
#define DEFAULT_CACHE_SIZE      GIGABYTES(20)
#define CACHE_PATH_LENGTH       60 // Length of path to a cached file within .clcache dir (not exact, used to check against MAX_PATH)

/*
 * Structs
 */

struct cstring{
	const char* Data;
	size_t      Length;
};

#define CSTR(str) (struct cstring){str, sizeof(str) - 1}

struct string{
	const WCHAR* Data;
	size_t       Length;
};

#define STR(str) (struct string){L ## str, sizeof(L ## str) / sizeof(WCHAR) - 1}

struct string_list{
	struct string* Strings;
	size_t         Count;
};

struct string_buffer{
	LPWSTR Data;
	size_t Size;
	size_t Used;
};

struct index_hash{
	int*         HashIndices;
	int*         Indices;
	unsigned int HashCount;
	unsigned int IndexCount;
};

struct cache_config{
	BOOL   UseStderr; // cl.exe writes warnings and errors to stdout this is optionally redirected to stderr by clcache
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
	BOOL GeneratesPdb;
	struct string ObjFile;
	struct string PdbFile;
	struct string SrcFile;
	struct string_list CompilerFlags;
	struct string_list IncludePaths;
	struct string_list ExternalIncludePaths;
	struct string_list SystemIncludePaths;
};

#define INCLUDE_FILE_LOCAL    1
#define INCLUDE_FILE_EXTERNAL 2
#define INCLUDE_FILE_SYSTEM   3

struct dependency_entry{
	UINT64        IncludePathType;
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

HANDLE              g_StdoutHandle;
HANDLE              g_StderrHandle;

WCHAR               g_ConfigFilePath[MAX_PATH];

struct cache_config g_Config;

/*
 * Helpers
 */

static UINT32 NextPowerOfTwo(UINT32 V){
	V--;
	V |= V >> 1;
	V |= V >> 2;
	V |= V >> 4;
	V |= V >> 8;
	V |= V >> 16;
	V++;

	return V + (V == 0);
}

static UINT32 PreviousPowerOfTwo(UINT32 V){
	V = NextPowerOfTwo(V);

	if(V != 1) /* We don't want this to create super high values when v == 1 */
		V >>= 1;

	return V;
}

static UINT32 NearestPowerOfTwo(UINT32 V){
	UINT32 a = PreviousPowerOfTwo(V);
	UINT32 b = NextPowerOfTwo(V);

	return (V - a) < (b - V) ? a : b;
}

/*
 * Output
 */

static void WriteStdout(struct cstring Str){
	DWORD NumBytesWritten;
	WriteFile(g_StdoutHandle, Str.Data, (DWORD)Str.Length, &NumBytesWritten, NULL);
}

static void WriteStderr(struct cstring Str){
	DWORD NumBytesWritten;
	WriteFile(g_StderrHandle, Str.Data, (DWORD)Str.Length, &NumBytesWritten, NULL);
}

/*
 * Error
 */

static __declspec(noreturn) void FatalError(struct cstring Msg){
	WriteStderr(CSTR("ERROR: "));
	WriteStderr(Msg);
	WriteStderr(CSTR("\n"));
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
		FatalError(CSTR("Failed to allocate virtual memory"));

	Arena.Size = Size;
	Arena.Used = 0;
	Arena.PrevUsed = 0;

	return Arena;
}

static void* PushMem(struct memory_arena* Arena, size_t Size){
	if(Arena->Used + Size > Arena->Size)
		FatalError(CSTR("Out of memory"));

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
 * String
 */

static BOOL IsWhitespace(WCHAR C){ return C == ' ' || C == '\t' || C == '\n' || C == '\r'; }
static BOOL IsDigit(WCHAR C){ return C >= '0' && C <= '9'; }
static BOOL IsPathSeparator(WCHAR C){ return C == '\\' || C == '/'; }

static struct cstring MakeCString(const char* Data, size_t Length){
	struct cstring Result;

	Result.Data = Data;
	Result.Length = Length;

	return Result;
}

static struct string MakeString(const WCHAR* Data, size_t Length){
	struct string Result;

	Result.Data = Data;
	Result.Length = Length;

	return Result;
}

static struct string_buffer MakeStringBuffer(WCHAR* Data, size_t Size){
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

static void PushStringWithEscapedQuotes(struct string Str, struct string_buffer* Buffer){
	struct string Temp = Str;
	Temp.Length = 0;

	for(size_t i = 0; i < Str.Length; ++i){
		if(Str.Data[i] == '\"'){
			PushString(Temp, Buffer);
			PushString(STR("\\\""), Buffer);
			Temp = MakeString(Str.Data + i + 1, 0);
		}else{
			++Temp.Length;
		}
	}

	PushString(Temp, Buffer);
}

static void PushCmdLineArg(struct string Flag, struct string Arg, struct string_buffer* Buffer){
	if(Buffer->Used > 0 && !IsWhitespace(Buffer->Data[Buffer->Used]))
		PushString(STR(" \""), Buffer);
	else
		PushString(STR("\""), Buffer);

	PushStringWithEscapedQuotes(Flag, Buffer);

	if(Arg.Length > 0)
		PushStringWithEscapedQuotes(Arg, Buffer);

	PushString(STR("\""), Buffer);
}

static struct cstring StringFromChar(const char* Str){
	struct cstring Result;

	Result.Data = Str;
	Result.Length = lstrlenA(Str);

	return Result;
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
	while(Str.Length > 0 && IsWhitespace(Str.Data[Str.Length - 1])){
		++Str.Data;
		--Str.Length;
	}

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

static struct cstring UINT64ToCString(UINT64 Value, char* Buffer){
	size_t DigitCount = 1;

	for(UINT64 i = 10; i <= Value; i *= 10)
		++DigitCount;

	for(size_t i = DigitCount; i > 0; --i){
		Buffer[i - 1] = '0' + (Value % 10);
		Value /= 10;
	}

	return MakeCString(Buffer, DigitCount);
}

static struct string UINT64ToString(UINT64 Value, struct string_buffer* Buffer){
	size_t DigitCount = 1;

	for(UINT64 i = 10; i <= Value; i *= 10)
		++DigitCount;

	WCHAR* Dest = PushChars(DigitCount, Buffer);

	for(size_t i = DigitCount; i > 0; --i){
		Dest[i - 1] = '0' + (Value % 10);
		Value /= 10;
	}

	return MakeString(Dest, DigitCount);
}

static struct cstring FloatToString(float Value, char* Buffer){
	struct cstring Result = UINT64ToCString((UINT64)Value, Buffer);

	Buffer[Result.Length++] = '.';
	// 2 digits of precision is enough. This is only used to print percentages for stats.
	Result.Length += UINT64ToCString((UINT64)((Value - (float)(UINT64)Value) * 100.0f), Buffer).Length;

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

static void SortStrings(struct string_list List){
	struct string Temp;

	for(int i = 1; i < List.Count; ++i){
		if(CompareStrings(List.Strings[i], List.Strings[i - 1]) < 0){
			Temp = List.Strings[i];
			List.Strings[i] = List.Strings[i - 1];
			List.Strings[i - 1] = Temp;

			for(int j = i - 1; j > 0; --j){
				if(CompareStrings(List.Strings[j], List.Strings[j - 1]) < 0){
					Temp = List.Strings[j];
					List.Strings[j] = List.Strings[j - 1];
					List.Strings[j - 1] = Temp;
				}
			}
		}
	}
}

struct string_list SplitString(struct string Str, WCHAR Separator, struct memory_arena* Arena){
	struct string_list List = {0};

	for(size_t i = 0; i < Str.Length; ++i){
		if(Str.Data[i] == Separator)
			++List.Count;
	}

	if(List.Count == 0)
		return List;

	List.Strings = PushMem(Arena, List.Count * sizeof(struct string));

	struct string* Path = List.Strings;
	Path->Data = Str.Data;
	Path->Length = 0;

	for(size_t i = 0; i < Str.Length; ++i){
		if(Str.Data[i] == Separator){
			++Path;
			Path->Data = Str.Data + i + 1;
			Path->Length = 0;
			continue;
		}

		++Path->Length;
	}

	return List;
}

/*
 * Index hash
 */

static void InitializeIndexHash(struct index_hash* Hash, int* HashIndices, unsigned int HashCount, int* Indices, unsigned int IndexCount){
	ASSERT(IS_POW2(HashCount));

	Hash->HashIndices = HashIndices;
	Hash->Indices = Indices;
	Hash->HashCount = HashCount;
	Hash->IndexCount = IndexCount;

	for(unsigned int i = 0; i < Hash->HashCount; ++i)
		Hash->HashIndices[i] = INVALID_INDEX;
}

static void InsertHashIndex(struct index_hash* Hash, UINT32 HashValue, int Index){
	ASSERT(Hash->IndexCount > (unsigned int)Index);

	unsigned int HashIndex = (unsigned int)(HashValue & (Hash->HashCount - 1));
	Hash->Indices[Index] = Hash->HashIndices[HashIndex];
	Hash->HashIndices[HashIndex] = Index;
}

static void RemoveHashIndex(struct index_hash* Hash, int Index){
	int* Tmp = NULL;

	/* Search for Index in the hash array */

	for(unsigned int i = 0; i < Hash->HashCount; ++i){
		if(Hash->HashIndices[i] == Index){
			Tmp = &Hash->HashIndices[i];
			break;
		}
	}

	/* If not found, search for Index in the Indices array */

	if(!Tmp){
		for(unsigned int i = 0; i < Hash->IndexCount; ++i){
			if(Hash->Indices[i] == Index){
				Tmp = &Hash->Indices[i];
				break;
			}
		}
	}

	/* If found, remove Index and replace with next value */

	if(Tmp){
		do{
			int* NextIndex = &Hash->Indices[*Tmp];

			*Tmp = *NextIndex;
			Tmp = NextIndex;
		}while(*Tmp != INVALID_INDEX);
	}
}

static int FirstHashIndex(const struct index_hash* Hash, UINT32 HashValue){
	return Hash->HashCount > 0 ? Hash->HashIndices[HashValue & (Hash->HashCount - 1)] : INVALID_INDEX;
}

static int NextHashIndex(const struct index_hash* Hash, int Index){
	return Hash->Indices[Index];
}

/*
 * File system
 */

static void MakePath(struct string Path){
	if(Path.Length >= MAX_PATH)
		FatalError(CSTR("Path length limit exceeded"));

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
				FatalError(CSTR("Failed to create directory"));
		}

		*p = Temp;
	}
}

static BOOL FileExists(LPCWSTR Path){
	return GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES;
}

static BOOL GetFileSizeLastModified(LPCWSTR filePath, UINT64* FileSize, UINT64* LastModified){
	WIN32_FILE_ATTRIBUTE_DATA FileAttribData;

	if(GetFileAttributesExW(filePath, GetFileExInfoStandard, &FileAttribData) && (FileAttribData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0){
		*FileSize = (UINT64)FileAttribData.nFileSizeHigh << 32 | FileAttribData.nFileSizeLow;
		*LastModified = (UINT64)FileAttribData.ftLastWriteTime.dwHighDateTime << 32 | FileAttribData.ftLastWriteTime.dwLowDateTime;

		return TRUE;
	}

	return FALSE;
}

static void* ReadDataFromFileHandle(HANDLE Handle, struct memory_arena* Arena, size_t* Size){
	if(SetFilePointer(Handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		FatalError(CSTR("Failed to read compiler output file"));

	LARGE_INTEGER FileSize;

	if(!GetFileSizeEx(Handle, &FileSize))
		FatalError(CSTR("Failed to determine file size"));

	*Size = FileSize.QuadPart;

	void* Content = PushMem(Arena, FileSize.QuadPart);
	DWORD NumBytesRead;

	if(!ReadFile(Handle, Content, (DWORD)FileSize.QuadPart, &NumBytesRead, NULL))
		FatalError(CSTR("Failed to read from file"));

	return Content;
}

static void* ReadDataFromFile(LPCWSTR Path, struct memory_arena* Arena, size_t* Size){
	HANDLE File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if(File == INVALID_HANDLE_VALUE)
		FatalError(CSTR("Failed to open file for reading"));

	void* Content = ReadDataFromFileHandle(File, Arena, Size);

	CloseHandle(File);

	return Content;
}

static void WriteDataToFile(LPCWSTR Path, const void* Data, size_t Size){
	HANDLE File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if(File == INVALID_HANDLE_VALUE)
		FatalError(CSTR("Failed to open file for writing"));

	DWORD NumBytesWritten;

	if(!WriteFile(File, Data, (DWORD)Size, &NumBytesWritten, NULL))
		FatalError(CSTR("Failed to write to file"));

	CloseHandle(File);
}

/*
 * Configuration
 */

static void WriteConfig(struct cache_config* Config){
	WriteDataToFile(g_ConfigFilePath, Config, sizeof(*Config));
}

static void ReadConfig(struct cache_config* Config){
	if(FileExists(g_ConfigFilePath)){
		HANDLE File = CreateFileW(g_ConfigFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if(File == INVALID_HANDLE_VALUE)
			FatalError(CSTR("Failed to open configuration file for reading"));

		DWORD NumBytesRead;
		BOOL Success = ReadFile(File, Config, sizeof(*Config), &NumBytesRead, NULL);

		CloseHandle(File);

		if(!Success)
			FatalError(CSTR("Failed to read from configuration file"));
	}else{ // Initialize config with default values and write it to the file
		PWSTR CachePath;

		ZeroMemory(Config, sizeof(*Config));
		Config->CacheSize = DEFAULT_CACHE_SIZE;
		SHGetKnownFolderPath(&FOLDERID_Profile, 0, NULL, &CachePath);
		lstrcpyW(Config->CachePath, CachePath);
		lstrcatW(Config->CachePath, L"\\.clcache");
		// CoTaskMemFree(CachePath);

		if(lstrlenW(Config->CachePath) + CACHE_PATH_LENGTH >= MAX_PATH)
			FatalError(CSTR("Invalid cache path"));

		WriteConfig(Config);
	}
}

/*
 * Process
 */

static void StartProcess(LPWSTR CmdLine, LPPROCESS_INFORMATION ProcessInfo, BOOL Detached, HANDLE Out, HANDLE Err){
	STARTUPINFOW StartupInfo = {0};
	DWORD CreationFlags = 0;

	StartupInfo.cb = sizeof(StartupInfo);

	if(Detached){
		CreationFlags |= DETACHED_PROCESS;
	}else if(Out != INVALID_HANDLE_VALUE || Err != INVALID_HANDLE_VALUE){
		StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
		StartupInfo.hStdOutput = Out == INVALID_HANDLE_VALUE ? g_StdoutHandle : Out;
		StartupInfo.hStdError = Err == INVALID_HANDLE_VALUE ? g_StderrHandle : Err;
	}

	ZeroMemory(ProcessInfo, sizeof(*ProcessInfo));

	if(!CreateProcessW(NULL, CmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &StartupInfo, ProcessInfo))
		FatalError(CSTR("Failed to start process"));
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
		FatalError(CSTR("Failed to open file"));

	LARGE_INTEGER FileSize;

	if(!GetFileSizeEx(File, &FileSize))
		FatalError(CSTR("Failed to determine file size"));

	if(FileSize.QuadPart == 0)
		return 0;

	void* Data = PushMem(Arena, FileSize.QuadPart);
	DWORD NumBytesRead;

	if(!ReadFile(File, Data, (DWORD)FileSize.QuadPart, &NumBytesRead, NULL))
		FatalError(CSTR("Failed to read from file"));

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

static void NormalizePaths(struct string_list PathList, struct memory_arena* Arena){
	WCHAR* Buffer = PushMem(Arena, PathList.Count * MAX_PATH * sizeof(WCHAR));
	WCHAR TempBuffer[MAX_PATH];

	for(size_t i = 0; i < PathList.Count; ++i){
		struct string Path = PathList.Strings[i];

		if(Path.Length >= MAX_PATH)
			continue;

		CopyMemory(TempBuffer, Path.Data, Path.Length * sizeof(WCHAR));
		TempBuffer[Path.Length] = '\0';
		DWORD Len = GetFullPathNameW(TempBuffer, MAX_PATH, Buffer, NULL);
		PathList.Strings[i] = MakeString(Buffer, Len);
		Buffer += MAX_PATH;
	}
}

static BOOL BuildCommandInfo(int argc, LPWSTR* argv, struct cl_command_info* Command, struct memory_arena* Arena){
	ZeroMemory(Command, sizeof(*Command));

	Command->Executable = StringFromWchar(argv[1]);
	Command->ClVersion = GetCompilerVersion(argv[1], Arena);

	if(!Command->ClVersion)
		return FALSE;

	Command->IncludePaths.Strings = PushMem(Arena, argc * sizeof(struct string));
	Command->CompilerFlags.Strings = PushMem(Arena, (argc - 2) * sizeof(struct string));

	Command->IncludePaths.Count = 1;
	Command->IncludePaths.Strings[0].Data = PushMem(Arena, MAX_PATH);
	Command->IncludePaths.Strings[0].Length = GetCurrentDirectoryW(MAX_PATH, (LPWSTR)Command->IncludePaths.Strings[0].Data);

	Command->ExternalIncludePaths.Count = 0;
	Command->ExternalIncludePaths.Strings = PushMem(Arena, argc * sizeof(struct string));

	BOOL CompilesToObj = FALSE;

	for(int i = 2; i < argc; ++i){
		if(*argv[i] == '/' || *argv[i] == '-'){
			LPCWSTR Flag = argv[i] + 1;

			if(IsLinkerFlag(Flag))
				return FALSE;

			BOOL External = FALSE;

			if(lstrcmpW(Flag, L"external:") == 0){
				Flag += sizeof("external:") + 1;

				while(IsWhitespace(*Flag))
					++Flag;

				External = TRUE;
			}

			if(IsPreprocessorFlag(Flag)){
				if(*Flag == 'E' || *Flag == 'P') // Only preprocessor, no compilation so nothing to cache...
					return FALSE;

				if(*Flag == 'I'){
					if(External)
						Command->ExternalIncludePaths.Strings[Command->ExternalIncludePaths.Count++] = StringFromWchar(Flag + 1);
					else
						Command->IncludePaths.Strings[Command->IncludePaths.Count++] = StringFromWchar(Flag + 1);

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
				return FALSE;
			}
		}else{
			if(Command->SrcFile.Length > 0)
				return FALSE; // Multiple source files are not supported

			Command->SrcFile = StringFromWchar(argv[i]);
			continue;
		}

		// Add flag to compiler command line so it can be hashed later
		Command->CompilerFlags.Strings[Command->CompilerFlags.Count++] = StringFromWchar(argv[i]);
	}

	if(Command->SrcFile.Length == 0 || Command->SrcFile.Length >= MAX_PATH)
		return FALSE;

	if(!CompilesToObj) // Only compile commands that result in object files are cacheable
		return FALSE;

	// Set object file name if it wasn't explicitly specified

	if(Command->ObjFile.Length == 0){
		struct string SrcFileBaseName = FilePathWithoutExtension(Command->SrcFile);
		void* Mem = PushMem(Arena, (SrcFileBaseName.Length + 5) * sizeof(WCHAR));
		struct string_buffer TempBuffer = MakeStringBuffer(Mem, SrcFileBaseName.Length + 5);
		Command->ObjFile = PushString(SrcFileBaseName, &TempBuffer);
		Command->ObjFile.Length += PushString(STR(".obj"), &TempBuffer).Length;
	}

	// Set pdb file name based on object file name

	if(Command->GeneratesPdb){
		struct string ObjFileBaseName = FilePathWithoutExtension(Command->ObjFile);
		void* Mem = PushMem(Arena, (ObjFileBaseName.Length + 5) * sizeof(WCHAR));
		struct string_buffer TempBuffer = MakeStringBuffer(Mem, ObjFileBaseName.Length + 5);
		Command->PdbFile = PushString(ObjFileBaseName, &TempBuffer);
		Command->PdbFile.Length += PushString(STR(".pdb"), &TempBuffer).Length;
	}

	// Collect system include paths from the INCLUDE environment variable

	LPWSTR EnvVarBuffer = PushMem(Arena, MAX_COMMAND_LINE_LENGTH * sizeof(WCHAR));
	DWORD EnvVarLength = GetEnvironmentVariableW(L"INCLUDE", EnvVarBuffer, MAX_COMMAND_LINE_LENGTH);

	if(EnvVarLength > 0){
		PopPartialMem(Arena, (MAX_COMMAND_LINE_LENGTH - EnvVarLength) * sizeof(WCHAR));
		Command->SystemIncludePaths = SplitString(MakeString(EnvVarBuffer, EnvVarLength), ';', Arena);
	}else{
		PopMem(Arena);
	}

	NormalizePaths(Command->IncludePaths, Arena);
	NormalizePaths(Command->ExternalIncludePaths, Arena);
	NormalizePaths(Command->SystemIncludePaths, Arena);

	return TRUE;
}

static struct string HashToPath(UINT64 Hash, struct string_buffer* Buffer){
	const LPCWSTR HexLookup = L"0123456789abcdef";
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
	const LPCWSTR HexLookup = L"0123456789abcdef";
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
	PushCmdLineArg(Command->Executable, STR(""), &CmdLineBuffer);

	// Skip the first include path because that's the current directory which was added in BuildCommandInfo but shouldn't actually be passed to cl.exe
	for(int i = 1; i < Command->IncludePaths.Count; ++i)
		PushCmdLineArg(STR("/I"), Command->IncludePaths.Strings[i], &CmdLineBuffer);

	for(int i = 0; i < Command->ExternalIncludePaths.Count; ++i)
		PushCmdLineArg(STR("/external:I"), Command->ExternalIncludePaths.Strings[i], &CmdLineBuffer);

	SortStrings(Command->CompilerFlags);

	size_t CompilerFlagsStart = CmdLineBuffer.Used;
	CompilerFlags->Data = CmdLineBuffer.Data + CmdLineBuffer.Used;

	for(int i = 0; i < Command->CompilerFlags.Count; ++i)
		PushCmdLineArg(Command->CompilerFlags.Strings[i], STR(""), &CmdLineBuffer);

	CompilerFlags->Length = CmdLineBuffer.Used - CompilerFlagsStart;

	if(Command->NoLogo)
		PushCmdLineArg(STR("/nologo"), STR(""), &CmdLineBuffer);

	PushCmdLineArg(STR("/showIncludes"), STR(""), &CmdLineBuffer); // showIncludes is always needed because the command output is parsed to get all included files
	PushCmdLineArg(Command->SrcFile, STR(""), &CmdLineBuffer);
	PushCmdLineArg(STR("/Fo:"), Command->ObjFile, &CmdLineBuffer);

	if(Command->GeneratesPdb)
		PushCmdLineArg(STR("/Fd:"), Command->PdbFile, &CmdLineBuffer);

	PopPartialMem(Arena, CmdLineBuffer.Size - CmdLineBuffer.Used);

	return CmdLineBuffer.Data;
}

static struct string_buffer BuildCachePath(const struct cl_command_info* Command, struct memory_arena* Arena, struct string CompilerFlags){
	struct string_buffer PathBuffer = MakeStringBuffer(PushMem(Arena, MAX_PATH * sizeof(WCHAR)), MAX_PATH);

	// Hash input source file

	PathBuffer.Data[PushString(Command->SrcFile, &PathBuffer).Length] = '\0';

	UINT64 FileHash = HashFileContent(PathBuffer.Data, Arena);

	// Build hash path using compiler version, source file hash and compiler command line hash

	CopyMemory(PathBuffer.Data, g_Config.CachePath, MAX_PATH * sizeof(WCHAR));
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
		FatalError(CSTR("Failed to open dependency file for reading"));

	LARGE_INTEGER FileSize;

	if(!GetFileSizeEx(File, &FileSize))
		FatalError(CSTR("Failed to determine file size"));

	BYTE* Buffer = PushMem(Arena, FileSize.QuadPart);
	DWORD NumBytesRead;

	if(!ReadFile(File, Buffer, (DWORD)FileSize.QuadPart, &NumBytesRead, NULL))
		FatalError(CSTR("Failed to read from dependency file"));

	CloseHandle(File);

	struct dependency_info DepInfo;
	DepInfo.EntryCount = *((UINT32*)Buffer);
	Buffer += sizeof(UINT64);
	DepInfo.Entries = PushMem(Arena, sizeof(struct dependency_entry) * DepInfo.EntryCount);

	for(UINT32 i = 0; i < DepInfo.EntryCount; ++i){
		DepInfo.Entries[i].IncludePathType = *((UINT64*)Buffer);
		Buffer += sizeof(UINT64);
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
		*((UINT64*)BufferPos) = Deps->Entries[i].IncludePathType;
		BufferPos += sizeof(UINT64);
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
		FatalError(CSTR("Failed to open dependency file for writing"));

	DWORD NumBytesWritten;

	if(!WriteFile(File, Buffer, FileSize, &NumBytesWritten, NULL))
		FatalError(CSTR("Failed to write to dependency file"));

	CloseHandle(File);
	PopMem(Arena);
}

static int FindIncludePathFromFile(struct string_list IncludePaths, struct string FilePath){
	for(int i = 0; i < IncludePaths.Count; ++i){
		if(StringStartsWithCaseInsensitive(FilePath, IncludePaths.Strings[i]))
			return i;
	}

	return -1;
}

static struct dependency_info GenerateDeps(const struct cl_command_info* Command, struct string_list IncludedFiles, struct memory_arena* Arena){
	struct include_file{
		struct include_file* Next;
		struct string        IncludePath;
		struct string        FileName;
		UINT64               IncludePathType;
	};

	struct include_file* First = NULL;
	struct include_file** Current = &First;
	struct dependency_info Deps;

	Deps.EntryCount = 0;

	for(size_t FileIndex = 0; FileIndex < IncludedFiles.Count; ++FileIndex){
		struct string IncludePath = STR("");
		struct string FilePath = IncludedFiles.Strings[FileIndex];
		struct string* FoundIncludePath = NULL;

		int Index = FindIncludePathFromFile(Command->IncludePaths, FilePath);
		UINT64 IncPathType = 0;

		if(Index >= 0){
			FoundIncludePath = Command->IncludePaths.Strings + Index;
			IncPathType = INCLUDE_FILE_LOCAL;
		}else{
			Index = FindIncludePathFromFile(Command->ExternalIncludePaths, FilePath);

			if(Index >= 0){
				FoundIncludePath = Command->ExternalIncludePaths.Strings + Index;
				IncPathType = INCLUDE_FILE_EXTERNAL;
			}else{
				Index = FindIncludePathFromFile(Command->SystemIncludePaths, FilePath);

				if(Index >= 0){
					FoundIncludePath = Command->SystemIncludePaths.Strings + Index;
					IncPathType = INCLUDE_FILE_SYSTEM;
				}
			}
		}

		if(FoundIncludePath){
			IncludePath = *FoundIncludePath;
			FilePath = StringRight(FilePath, FilePath.Length - IncludePath.Length);

			while(FilePath.Data[0] == '\\'){
				++FilePath.Data;
				--FilePath.Length;
			}
		}

		*Current = PushMem(Arena, sizeof(struct include_file));
		(*Current)->IncludePath = IncludePath;
		(*Current)->FileName = FilePath;
		(*Current)->IncludePathType = IncPathType;
		(*Current)->Next = NULL;
		Current = &(*Current)->Next;
		++Deps.EntryCount;
	}

	Deps.Entries = PushMem(Arena, Deps.EntryCount * sizeof(struct dependency_entry));

	struct include_file* Inc = First;

	for(UINT32 i = 0; i < Deps.EntryCount; ++i){
		WCHAR PathBufferData[MAX_PATH];
		struct string_buffer PathBuffer = MakeStringBuffer(PathBufferData, ARRAYSIZE(PathBufferData));

		PushString(Inc->IncludePath, &PathBuffer);

		if(Inc->IncludePath.Length > 0 && Inc->IncludePath.Data[Inc->IncludePath.Length - 1] != '\\')
			PushString(STR("\\"), &PathBuffer);

		PushString(Inc->FileName, &PathBuffer);
		GetFileSizeLastModified(PathBuffer.Data, &Deps.Entries[i].Size, &Deps.Entries[i].LastModified);
		Deps.Entries[i].Hash = HashFileContent(PathBuffer.Data, Arena);
		Deps.Entries[i].FileName = Inc->FileName;
		Deps.Entries[i].IncludePathType = Inc->IncludePathType;
		Inc = Inc->Next;
	}

	return Deps;
}

static struct string GetIncludeFileFullPath(struct string FileName, struct string_list IncludePaths, struct string_buffer* Buffer){
	size_t BufferInitialUsed = Buffer->Used;

	for(int i = 0; i < IncludePaths.Count; ++i){
		Buffer->Used = BufferInitialUsed;

		if(IncludePaths.Strings[i].Length + FileName.Length + 2 >= Buffer->Size - Buffer->Used)
			continue;

		PushString(IncludePaths.Strings[i], Buffer);
		PushString(STR("\\"), Buffer);
		PushString(FileName, Buffer);

		if(FileExists(Buffer->Data + BufferInitialUsed))
			return MakeString(Buffer->Data + BufferInitialUsed, Buffer->Used - BufferInitialUsed);
	}

	return STR("");
}

static BOOL CacheUpToDate(const struct cl_command_info* Command, struct string_buffer* CachePathBuffer, struct memory_arena* Arena){
	struct string CachePath = MakeString(CachePathBuffer->Data, CachePathBuffer->Used);
	(void)CachePath;
	ASSERT(CachePath.Length > 0);
	ASSERT(CachePath.Data[CachePath.Length - 1] == '\\');

	size_t CachePathLength = CachePathBuffer->Used;
	PushString(STR("dep"), CachePathBuffer);
	LPCWSTR DepFilePath = CachePathBuffer->Data;

	CachePathBuffer->Used = CachePathLength; // Reset here already. The buffer is not used anymore so the pushed data stays valid.

	if(!FileExists(DepFilePath))
		return FALSE;

	struct dependency_info Deps = ReadDepFile(DepFilePath, Arena);
	BOOL UpdateDepFile = FALSE;

	for(UINT32 DepIndex = 0; DepIndex < Deps.EntryCount; ++DepIndex){
		struct string FileName = Deps.Entries[DepIndex].FileName;
		// Local, external and system include paths are ordered based on the include path type to have as few lookups as possible
		struct string_list IncludePaths[3];

		if(Deps.Entries[DepIndex].IncludePathType == INCLUDE_FILE_EXTERNAL){
			IncludePaths[0] = Command->ExternalIncludePaths;
			IncludePaths[1] = Command->IncludePaths;
			IncludePaths[2] = Command->SystemIncludePaths;
		}else if(Deps.Entries[DepIndex].IncludePathType == INCLUDE_FILE_SYSTEM){
			IncludePaths[0] = Command->SystemIncludePaths;
			IncludePaths[1] = Command->ExternalIncludePaths;
			IncludePaths[2] = Command->IncludePaths;
		}else{
			IncludePaths[0] = Command->IncludePaths;
			IncludePaths[1] = Command->ExternalIncludePaths;
			IncludePaths[2] = Command->SystemIncludePaths;
		}

		WCHAR TempBufferData[MAX_PATH];
		struct string_buffer TempBuffer = MakeStringBuffer(TempBufferData, ARRAYSIZE(TempBufferData));
		struct string FilePath = {0};

		for(int i = 0; i < ARRAYSIZE(IncludePaths); ++i){
			FilePath = GetIncludeFileFullPath(FileName, IncludePaths[i], &TempBuffer);

			if(FilePath.Length > 0)
				break;
		}

		UINT64 Size;
		UINT64 LastModified;

		if(FilePath.Length > 0 && GetFileSizeLastModified(FilePath.Data, &Size, &LastModified)){
			if(Size == Deps.Entries[DepIndex].Size){
				if(LastModified != Deps.Entries[DepIndex].LastModified){
					UINT64 Hash = HashFileContent(FilePath.Data, Arena);

					if(Hash != Deps.Entries[DepIndex].Hash)
						return FALSE;

					// Update dependency file if timestamp has changed but the content is the same
					Deps.Entries[DepIndex].LastModified = LastModified;
					UpdateDepFile = TRUE;
				}
			}else{
				return FALSE;
			}
		}
	}

	if(UpdateDepFile)
		WriteDepFile(DepFilePath, &Deps, Arena);

	return TRUE;
}

static struct string ReadUtf8FileToString(HANDLE File, struct memory_arena* Arena){
	if(SetFilePointer(File, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		FatalError(CSTR("Failed to read compiler output file"));

	LARGE_INTEGER FileSize;

	if(!GetFileSizeEx(File, &FileSize))
		FatalError(CSTR("Failed to read compiler output file"));

	WCHAR* StringData = PushMem(Arena, FileSize.QuadPart * sizeof(WCHAR));
	size_t ArenaPrevUsed = Arena->Used;
	size_t StringLength = 0;
	char* Utf8Buffer = PushMem(Arena, FileSize.QuadPart);
	DWORD NumBytesRead;

	if(!ReadFile(File, Utf8Buffer, (DWORD)FileSize.QuadPart, &NumBytesRead, NULL))
		FatalError(CSTR("Failed to read compiler output file"));

	StringLength = (size_t)MultiByteToWideChar(CP_UTF8, 0, Utf8Buffer, (int)FileSize.QuadPart, StringData, (int)FileSize.QuadPart);
	PopMem(Arena);
	Arena->PrevUsed = ArenaPrevUsed;

	return MakeString(StringData, StringLength);
}

static struct string_list ExtractIncludedFilesFromCompilerOutput(struct string Text, struct memory_arena* Arena, struct string* Output){
	const struct string IncludeLineStart = STR("Note: including file:");
	struct string_list List = SplitString(Text, '\n', Arena);
	WCHAR* OutputBufferData = PushMem(Arena, (Text.Length + 1) * sizeof(WCHAR));
	struct string_buffer OutputBuffer = MakeStringBuffer(OutputBufferData, Text.Length + 1);
	struct string* Current = List.Strings;
	size_t FileCount = 0;

	for(size_t i = 0; i < List.Count; ++i){
		const struct string Line = List.Strings[i];

		if(StringStartsWith(List.Strings[i], IncludeLineStart)){
			*Current = TrimString(StringRight(Line, Line.Length - IncludeLineStart.Length));
			++Current;
			++FileCount;
		}else{
			// Include the newline in the pushed string
			PushString(MakeString(Line.Data, Line.Length + 1), &OutputBuffer);
		}
	}

	List.Count= FileCount;
	*Output = MakeString(OutputBuffer.Data, OutputBuffer.Used);
	PopPartialMem(Arena, (OutputBuffer.Size - OutputBuffer.Used) * sizeof(WCHAR));

	struct index_hash IndexHash;
	UINT32 HashSize = NearestPowerOfTwo((UINT32)List.Count);
	int* Indices = PushMem(Arena, (HashSize + List.Count) * sizeof(int));
	InitializeIndexHash(&IndexHash, Indices, HashSize, Indices + HashSize, (UINT32)List.Count);

	struct string_list FullPathList;
	FullPathList.Strings = PushMem(Arena, List.Count * sizeof(struct string));
	FullPathList.Count = 0;

	for(size_t i = 0; i < List.Count; ++i){
		struct string Path = List.Strings[i];
		// HACK: Avoid copying the strings by adding a zero-terminator in the original buffer
		((WCHAR*)Path.Data)[Path.Length] = '\0';

		WCHAR* Buffer = PushMem(Arena, MAX_PATH * sizeof(WCHAR));
		DWORD Length = GetFullPathNameW(Path.Data, MAX_PATH, Buffer, NULL);

		if(Length == 0 || Length >= MAX_PATH) // This should never fail since the compiler errors out earlier
			FatalError(CSTR("Path length limit exceeded"));

		struct string FullPath = MakeString(Buffer, Length);
		UINT32 HashValue = XXH32(FullPath.Data, FullPath.Length * sizeof(WCHAR), 0);
		BOOL AlreadyHaveFile = FALSE;

		for(int HashIndex = FirstHashIndex(&IndexHash, HashValue); HashIndex != INVALID_INDEX; HashIndex = NextHashIndex(&IndexHash, HashIndex)){
			if(StringsAreEqualCaseInsensitive(FullPathList.Strings[HashIndex], FullPath)){
				AlreadyHaveFile = TRUE;
				break;
			}
		}

		if(!AlreadyHaveFile){
			int Index = (int)FullPathList.Count++;
			InsertHashIndex(&IndexHash, HashValue, Index);
			FullPathList.Strings[Index] = FullPath;
		}
	}

	return FullPathList;
}

static int InvokeCompiler(LPWSTR CmdLine, const struct cl_command_info* Command, struct string_buffer* CachePathBuffer, struct memory_arena* Arena){
	WCHAR StdoutTempFileName[MAX_PATH];
	WCHAR StderrTempFileName[MAX_PATH];

	GetTempFileNameW(L".", L"out", 0, StdoutTempFileName);
	GetTempFileNameW(L".", L"err", 0, StderrTempFileName);

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

	StartProcess(CmdLine, &Process, FALSE, StdoutFile, StderrFile);

	int ExitCode = (int)WaitForProcessToFinish(&Process);

	struct string StdoutString = ReadUtf8FileToString(StdoutFile, Arena);
	CloseHandle(StdoutFile);
	DeleteFileW(StdoutTempFileName);

	{
		// Remove name of source file from first line of stdout because it is printed elsewhere
		struct string SrcFileName = FileNameWithoutPath(Command->SrcFile);

		if(StringStartsWith(StdoutString, SrcFileName)){
			StdoutString.Data += SrcFileName.Length;
			StdoutString.Length -= SrcFileName.Length;
			StdoutString = TrimStringLeft(StdoutString);
		}
	}

	struct cstring StderrContent;
	StderrContent.Data = ReadDataFromFileHandle(StderrFile, Arena, &StderrContent.Length);
	CloseHandle(StderrFile);
	DeleteFileW(StderrTempFileName);

	struct string_list IncludedFiles = ExtractIncludedFilesFromCompilerOutput(StdoutString, Arena, &StdoutString);
	char* StdoutBuffer = PushMem(Arena, StdoutString.Length * 2);
	int StdoutLen = WideCharToMultiByte(CP_UTF8, 0, StdoutString.Data, (int)StdoutString.Length, StdoutBuffer, (int)StdoutString.Length * 2, NULL, FALSE);
	struct cstring StdoutContent = MakeCString(StdoutBuffer, (size_t)StdoutLen);

	if(StdoutContent.Length > 0){
		if(g_Config.UseStderr)
			WriteStderr(StdoutContent);
		else
			WriteStdout(StdoutContent);
	}

	if(StderrContent.Length > 0)
		WriteStderr(StderrContent);

	if(ExitCode == 0){
		WCHAR TempPath[MAX_PATH];

		size_t CachePathLength = CachePathBuffer->Used;
		MakePath(MakeString(CachePathBuffer->Data, CachePathBuffer->Used));

		// Generate dep file

		struct dependency_info Deps = GenerateDeps(Command, IncludedFiles, Arena);
		CachePathBuffer->Used = CachePathLength;
		PushString(STR("dep"), CachePathBuffer);
		WriteDepFile(CachePathBuffer->Data, &Deps, Arena);

		// Write stdout to file

		if(StdoutContent.Length > 0){
			CachePathBuffer->Used = CachePathLength;
			PushString(STR("out"), CachePathBuffer);
			WriteDataToFile(CachePathBuffer->Data, StdoutContent.Data, StdoutContent.Length);
		}

		// Write stderr to file

		if(StderrContent.Length > 0){
			CachePathBuffer->Used = CachePathLength;
			PushString(STR("err"), CachePathBuffer);
			WriteDataToFile(CachePathBuffer->Data, StderrContent.Data, StderrContent.Length);
		}

		// Copy obj to cache

		CopyMemory(TempPath, Command->ObjFile.Data, Command->ObjFile.Length * sizeof(WCHAR));
		TempPath[Command->ObjFile.Length] = '\0';
		CachePathBuffer->Used = CachePathLength;
		PushString(STR("obj"), CachePathBuffer);
		CopyFileW(TempPath, CachePathBuffer->Data, FALSE);

		// Copy pdb to cache

		if(Command->GeneratesPdb){
			CopyMemory(TempPath, Command->PdbFile.Data, Command->PdbFile.Length * sizeof(WCHAR));
			TempPath[Command->PdbFile.Length] = '\0';
			CachePathBuffer->Used = CachePathLength;
			PushString(STR("pdb"), CachePathBuffer);
			CopyFileW(TempPath, CachePathBuffer->Data, FALSE);
		}
	}

	return ExitCode;
}

static int CacheMain(int argc, LPWSTR* argv){
	if(!StringsAreEqual(FileNameWithoutPath(StringFromWchar(argv[1])), STR("cl.exe"))){
		WriteStderr(CSTR("ERROR: First argument is expected to be the path to cl.exe"));
		return 1;
	}

	struct cl_command_info Command;
	struct memory_arena Arena = CreateMemory(MEGABYTES(128));

	if(BuildCommandInfo(argc, argv, &Command, &Arena)){
#if 0
		WriteStdout(FileNameWithoutPath(Command.SrcFile));
		WriteStdout(STR("\n"));
#endif

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
				WriteStderr(CSTR("Failed to copy cached obj file to destination: "));
#if 0
				WriteStderr(MakeString(CachePathBuffer.Data, CachePathBuffer.Used));
				WriteStderr(STR(" -> "));
				WriteStderr(StringFromWchar(TempPath));
				WriteStderr(STR("\n"));
#endif
				CachePathBuffer.Used = CachePathLength;
				return InvokeCompiler(CmdLine, &Command, &CachePathBuffer, &Arena);
			}

			if(Command.GeneratesPdb){
				CopyMemory(TempPath, Command.PdbFile.Data, Command.PdbFile.Length * sizeof(WCHAR));
				TempPath[Command.PdbFile.Length] = '\0';

				CachePathBuffer.Used = CachePathLength;
				PushString(STR("pdb"), &CachePathBuffer);

				if(!CopyFileW(CachePathBuffer.Data, TempPath, FALSE)){
					WriteStderr(CSTR("Failed to copy cached pdb file to destination: "));
#if 0
					WriteStderr(MakeString(CachePathBuffer.Data, CachePathBuffer.Used));
					WriteStderr(STR(" -> "));
					WriteStderr(StringFromWchar(TempPath));
					WriteStderr(STR("\n"));
#endif
					CachePathBuffer.Used = CachePathLength;
					return InvokeCompiler(CmdLine, &Command, &CachePathBuffer, &Arena);
				}
			}

			LPCWSTR FilePath = CachePathBuffer.Data;
			UINT64 FileSize;
			UINT64 FileLastModified;

			// Write stdout
			{
				CachePathBuffer.Used = CachePathLength;
				PushString(STR("out"), &CachePathBuffer);

				// Most of the time the stderr file is emtpy
				if(GetFileSizeLastModified(FilePath, &FileSize, &FileLastModified) && FileSize > 0){
					size_t Size;
					const char* Data = ReadDataFromFile(FilePath, &Arena, &Size);
					struct cstring Out = MakeCString(Data, Size);

					if(g_Config.UseStderr)
						WriteStderr(Out);
					else
						WriteStdout(Out);

					PopMem(&Arena);
				}
			}

			// Write stderr
			{
				CachePathBuffer.Used = CachePathLength;
				PushString(STR("err"), &CachePathBuffer);

				// Most of the time the stderr file is emtpy
				if(GetFileSizeLastModified(FilePath, &FileSize, &FileLastModified) && FileSize > 0){
					size_t Size;
					const char* Data = ReadDataFromFile(FilePath, &Arena, &Size);
					WriteStderr(MakeCString(Data, Size));
					PopMem(&Arena);
				}
			}

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

		StartProcess(CmdLine, &Process, FALSE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE);

		return (int)WaitForProcessToFinish(&Process);
	}
}

/*
 * Main
 */

static void PrintHelpText(void){
	WriteStdout(CSTR(
		"Available options:\n"
		" -h      show this help\n"
		" -i      show info\n"
		" -m<n>   set maximum cache size to n gigabytes\n"
		" -p<dir> set cache path to <dir>\\.clcache\n"
		" -e<1/0> enable or disable redirection of errors to stderr\n"
	));
}

#ifdef NO_CRT
int mainCRTStartup(){
	int argc = 0;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
#else
int wmain(int argc, LPWSTR* argv){
#endif
	g_StdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	g_StderrHandle = GetStdHandle(STD_ERROR_HANDLE);

	if(argc <= 1){
		WriteStderr(CSTR(
			"Usage:\n"
			"    clcache.exe <path_to_cl.exe> <cl_args>\n"
			"  or\n"
			"    clcache.exe <options> (-h for a list of available options)\n"
		));

		ExitProcess(1);
	}

	// Initialize config file path
	{
		PWSTR LocalAppData;

		g_ConfigFilePath[0] = '\0';
		SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &LocalAppData);
		lstrcpyW(g_ConfigFilePath, LocalAppData);
		// CoTaskMemFree(LocalAppData);
		lstrcatW(g_ConfigFilePath, L"\\clcache");
		MakePath(StringFromWchar(g_ConfigFilePath));
		lstrcatW(g_ConfigFilePath, L"\\clcache.config");
	}

	ReadConfig(&g_Config);

	if(*argv[1] == '-'){
		for(int i = 1; i < argc; ++i){
			LPCWSTR Arg = argv[i] + 1;

			switch(*Arg){
			case 'h':
				PrintHelpText();
				break;
			case 'i':
				{
					char Buffer[MAX_PATH];

					WriteStdout(CSTR("Configuration:   "));
					WideCharToMultiByte(CP_UTF8, 0, g_ConfigFilePath, -1, Buffer, ARRAYSIZE(Buffer), NULL, FALSE);
					WriteStdout(StringFromChar(Buffer));
					WriteStdout(CSTR("\nCache path:      "));
					WideCharToMultiByte(CP_UTF8, 0, g_Config.CachePath, -1, Buffer, ARRAYSIZE(Buffer), NULL, FALSE);
					WriteStdout(StringFromChar(Buffer));
					WriteStdout(CSTR("\nMax cache size:  "));
					WriteStdout(UINT64ToCString(g_Config.CacheSize / GIGABYTES(1), Buffer));
					WriteStdout(CSTR(" GB\nErrors:          "));
					WriteStdout(g_Config.UseStderr ? CSTR("redirected to stderr\n") : CSTR("stdout (cl.exe default)\n"));
					break;
				}
			case 'm':
				{
					++Arg;

					if(*Arg == '\0' && i != argc - 1)
							Arg = argv[++i];

					if(!IsDigit(*Arg)){
						WriteStderr(CSTR("The -m option expects a number in gigabytes"));
						ExitProcess(1);
					}

					UINT64 NewCacheSize = StringToUINT64(StringFromWchar(Arg));

					if(NewCacheSize >= 1){
						g_Config.CacheSize = GIGABYTES(NewCacheSize); // TODO: Clean up the cache if necessary
						WriteConfig(&g_Config);
					}else{
						WriteStderr(CSTR("ERROR: Cache size must be at least 1 gigabyte"));
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
						WriteStderr(CSTR("ERROR: the -p option expects a path as an argument"));
						ExitProcess(1);
					}

					WCHAR Buffer[MAX_PATH];
					DWORD PathLength = GetFullPathNameW(Arg, MAX_PATH, Buffer, NULL);

					if(PathLength + CACHE_PATH_LENGTH >= MAX_PATH || PathLength == 0){
						WriteStderr(CSTR("Invalid cache path"));
						ExitProcess(1);
					}

					WCHAR* Temp = Buffer + lstrlenW(Buffer);

					while(Temp != Buffer && IsPathSeparator(*(Temp - 1))){ // Remove trailing path separators
						--Temp;
						*Temp = '\0';
					}

					if(!StringEndsWith(StringFromWchar(Buffer), STR("\\.clcache")))
						lstrcatW(Buffer, L"\\.clcache");

					lstrcpyW(g_Config.CachePath, Buffer);
					WriteConfig(&g_Config);
				}

				break;
			case 'e':
				g_Config.UseStderr = Arg[1] == '1';
				WriteConfig(&g_Config);
				break;
			default:
				WriteStderr(CSTR("Unknown option\n"));
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
