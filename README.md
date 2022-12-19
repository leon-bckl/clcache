# clcache
 clcache is a compiler cache for the Microsoft Visual Studio compiler. It is a small executable that intercepts calls to the compiler driver (cl.exe) and checks for the existence of a cached object file.
 If found it can simply be copied into the destination directory, avoiding compilation and thus reducing overall build time.
 In case there isn't a cached object file already, the compiler is invoked normally and the result is then copied into the cache to be used the next time that particular source file is compiled.

## How it works
Instead of calling the compiler directly, clcache is used as a wrapper. The resulting command looks as follows:
```
clcache <path to cl.exe> <compiler options>
```
Whichever build system you are using most likely has an option for such a compiler wrapper executable (e.g. `CMAKE_CXX_COMPILER_LAUNCHER` for cmake).

Once clcache is called, it inspects the compiler command line and checks if it is cacheable. Only compiler commands that produce an object file (`/c`) can be cached.
If an unsupported command line is detected, the call is directly passed through to cl.exe. Otherwise, it is first checked whether a cached file exists by going through the following steps:
  1. Hash the input source file
  2. Hash the relevant compiler options (ignoring stuff like `/nologo` which has no effect on the compiled result).
  3. Combine compiler version, source file hash and command line hash into cache lookup path
  4. Check for dependency file in the cache path (simply called `dep`)
     - If it exists:
       1. Check if any dependencies (header files) have changed by comparing the file size and last modified timestamp or the file hash if the former fails
       2. If all dependencies are up-to-date, copy the obj file and the pdb if one exists to the build directory and print stdout and stderr of the compilation which are stored in text files next to the obj
       3. If one dependent file is outdated, run the compiler again and cache the new result
     - If it doesn't exist:
       1. Run the compiler, producing an obj and optionally pdb file
       2. Parse the output to find all dependent files
       3. Store the file size, last modified time and hash for each dependency
       4. Copy the obj, pdb, stdout and stderr files into the cache directory

## Building
Run `build.bat release` from inside of an x64 Visual Studio command prompt.

## TODO:
- Clean up code
- Record stats (cache hits, misses etc.)
- Add option to clean up old cache entries
- Mark files that contain the `__TIME__` macro as uncacheable
