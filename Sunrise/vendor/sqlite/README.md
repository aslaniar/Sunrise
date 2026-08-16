# Vendored SQLite amalgamation (S1 persistence layer)

The standalone sunrise-server target (S1 lane) persists account/character/item/unlock state
to SQLite. The fork had NO sqlite dependency (verified 2026-08-14: grep src/** for sqlite
returns only the build_data cache and sign-on key paths), so the public-domain amalgamation
is vendored here per the S1 spec §3.2 rule ("vendor the amalgamation (public domain) into a
third-party dir and document it; do NOT add external package dependencies").

- Files: sqlite3.c (9,089,564 B), sqlite3.h, sqlite3ext.h
- Source: https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip
- Version: SQLite 3.46.1 (2024-08-13 release), amalgamation archive dated 2024
- sha256(sqlite3.c) = 6C35BC5F7F85EAC9C49928BACBB02BB694B547AABF69197E058CCA245AD80E83
  (verified at vendoring time, 2026-08-14)
- License: SQLite is in the PUBLIC DOMAIN (https://www.sqlite.org/copyright.html).
- Build notes:
  - sqlite3.c is compiled with per-file warning suppression (TurnOffAllWarnings) in
    sunrise-server.vcxproj; the project's global /W4 /WX stays on for fork code.
  - Preprocessor definitions for the sqlite3.c compile unit:
    SQLITE_THREADSAFE=1 (the server touches the DB from the service loop),
    SQLITE_OMIT_LOAD_EXTENSION=1 (no dynamic extension loading on a headless server).
  - The schema is created/migrated by src/server/persistence/persistence.cpp
    (PRAGMA user_version = 1; WAL; foreign_keys ON).
