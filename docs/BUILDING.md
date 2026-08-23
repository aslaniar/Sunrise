# Building Sunrise

This repository produces two separate Windows binaries:

| Target | Output binary | What it is |
|---|---|---|
| Client mod | `steam_api64.dll` | The offline exploration mod. It installs into the game folder and loads alongside the game process. |
| Dedicated server | `sunrise-server.exe` | A standalone dedicated server you can run on the same machine or another one. |

Two toolchains are supported:

1. **Windows**: Visual Studio with the checked-in `.sln` / `.vcxproj` files.
2. **Linux / macOS**: CMake + Ninja cross-compiling through one of the two
   checked-in toolchain files.

Both toolchains build the same two targets from the same sources.

---

## Toolchain 1: Visual Studio (Windows)

Requirements:

- Visual Studio with the *Desktop development with C++* workload.
- A Windows SDK matching the project files (they target `10.0.26100.0`; any
  recent SDK close to that works).

The solution file `Sunrise.sln` sits at the repository root:

| Project | Configuration type | Produces |
|---|---|---|
| `Sunrise/Sunrise.vcxproj` | Dynamic library | `steam_api64.dll` |
| `Sunrise/sunrise-server.vcxproj` | Console application | `sunrise-server.exe` |

Build the **Release | x64** configuration. Outputs land in:

- `build/x64/Release/steam_api64.dll` (client mod)
- `build/server/x64/Release/sunrise-server.exe` (dedicated server)

No extra linker or project settings are required on this toolchain - the
MSVC project files already carry everything they need.

---

## Toolchain 2: CMake + Ninja (Linux and macOS)

Both targets are Windows x86_64 binaries even when you build on Linux or
macOS, so this toolchain is always a cross-compile. Requirements:

- CMake >= 3.20
- Ninja
- Clang (see the per-OS setup below)
- The `CMakeLists.txt` lives in the `Sunrise/` subdirectory, not the repo root.

### Linux: `linux-to-win-toolchain.cmake`

This toolchain drives `clang-cl` / `lld-link` against a Windows SDK and CRT
pulled in by [xwin](https://github.com/Jake-Shadle/xwin) (the same flow the
upstream project documents). The toolchain expects the SDK/CRT under
`.xwin-cache/` next to the toolchain file (`sdk/` and `crt/` subdirectories),
so populate that cache first, then configure:

```sh
cmake -S Sunrise -B build-cmake \
    -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=linux-to-win-toolchain.cmake \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build-cmake --parallel
```

### macOS: `Sunrise/toolchain-llvm-mingw.cmake`

This toolchain uses [llvm-mingw](https://github.com/mstorsjo/llvm-mingw)
(`x86_64-w64-mingw32-clang++`). Edit the `MINGW` variable at the top of the
file so it points at your own llvm-mingw install - the value checked into the
tree is a single-machine leftover and will not exist on your system.

```sh
cmake -S Sunrise -B build-cmake \
    -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=Sunrise/toolchain-llvm-mingw.cmake \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build-cmake --parallel 8
```

With Ninja, both binaries land in the build directory root:

- `build-cmake/steam_api64.dll`
- `build-cmake/sunrise-server.exe`

---

## Three build rules

These have each cost someone a real debugging session. Treat them as rules,
not suggestions.

### Rule 1: keep the C language enabled in CMake

The CMake project declaration must enable C explicitly, e.g.:

```cmake
project(SunrisePort LANGUAGES CXX C RC)
```

The vendored SQLite amalgamation (`vendor/sqlite/sqlite3.c`) is plain C. If
the project enables only `CXX`, CMake **silently skips compiling it - no
error, no warning at configure or compile time** - and the failure surfaces
only at link time as an explosion of unresolved `sqlite3_*` symbols. If you
ever re-create or trim the CMake project, check the `LANGUAGES` list first.

(The Visual Studio route does not have this hazard: MSVC compiles `.c` files
regardless.)

### Rule 2: the standalone server needs an 8 MiB stack

The `sunrise-server` target must carry this linker option:

```cmake
target_link_options(sunrise-server PRIVATE -Wl,--stack,8388608)
```

A standalone executable gets whatever small default stack the linker picks.
Server startup initializes the full account/state model in one call with a
large stack-allocated structure, and that overflows the default stack -
the process dies during startup with no obvious message. The client DLL never
needed this setting because it rides the game process's much larger host
stack, which is why the bug only shows up in freshly built standalone exes.

(MSVC's own default for the `.vcxproj` server target happens to be
sufficient, so there is no equivalent setting there.)

### Rule 3: always build parallel

Always pass `-j` / `--parallel` (or set it in your IDE). A fully serial build
of this tree through the Windows-pipeline-style compilation order takes long
enough that it looks hung somewhere near the 90 minute mark. Nothing is
wrong; it is just slow. Parallel builds finish in a fraction of that.

---

## After rebuilding the server: refresh the cache identity

The server validates its extracted-content cache,
`Sunrise/cache/build_data.bin` under the server home, against the identity of
the exact `sunrise-server.exe` that produced it. Rebuilding the exe changes
its PE timestamp and size, and the next boot then hard-fails the content swap
with an identity mismatch.

Fix: patch the two little-endian u32 identity fields at fixed header offsets
in `cache/build_data.bin` -

| Offset | Field | Value to write |
|---|---|---|
| 12 | image timestamp | `expected_ts` from the failing boot's log line |
| 16 | image size | `expected_size` from the failing boot's log line |

The boot log prints both expected values when the check fails, so no PE
parsing is needed.

The third identity-ish field, the configured-equipment hash stored at offset
20, is **not** something you need to maintain here: the server re-stamps it
by itself whenever an equipment or ability change commits, so it stays in
step with persisted state on its own. Only the two fields above go stale on
a rebuild.

---

## Installing the outputs

- **Client mod**: copy `steam_api64.dll` into the game installation as
  `Game/bin/x64/steam_api64.dll`, replacing the original file (keep a backup
  of the original - it is the game's own Steam wrapper). First launch creates
  `Game/bin/x64/Sunrise/settings.json` and a logs folder next to it.
- **Dedicated server**: put `sunrise-server.exe` in any empty folder (the
  *server home*). First launch creates the `Sunrise/` data folder beside it
  containing `settings.json`, `cache/build_data.bin`, the persistence
  database, and `logs/sunrise.log`.

See [CONFIGURATION.md](CONFIGURATION.md) for both config files and
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) for known log signatures.
