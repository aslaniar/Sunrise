#!/usr/bin/env python3
"""Restamp build_data.bin's identity header after rebuilding sunrise-server.exe.

The cache header stores the identity of the exact sunrise-server.exe that
produced it as two little-endian u32 fields: the image timestamp at byte
offset 12 and the image size at offset 16. Rebuilding the exe changes both,
and the next boot hard-fails content_swap with an identity mismatch until
they match again. This tool rewrites just those two fields.

The third identity-like field, the configured-equipment hash at offset 20,
is deliberately left untouched: the server re-stamps that field itself
whenever an equipment or ability change commits, so it stays in step with
persisted state on its own.

New values come either from explicit flags or straight from the failing
boot's own log line:

  restamp_build_data.py --ts 0x6A86B4BA --size 0x27BA000
  restamp_build_data.py --ts 1787786410 --size 41586688        # decimal works too
  restamp_build_data.py --from-log <server home>/Sunrise/logs/sunrise.log

--ts/--size accept hex (0x-prefixed) or decimal. With --from-log, the
expected_ts and expected_size values are extracted by regex from the last
"ev=build_data stage=identity result=mismatch" line in the log. Only those
two fields are read: nothing after them on that line (the expected_eq value,
which the log truncates mid-line leaving trailing garbage) is parsed or
trusted.

Without --apply the tool prints before/after values and changes nothing.
The payload checksum does not cover these identity fields, so no checksum
update is needed.
"""

import argparse
import os
import re
import struct
import sys

MAGIC = b"SUNRISEB"
TS_OFFSET = 12
SIZE_OFFSET = 16

IDENTITY_LINE_RE = re.compile(r"ev=build_data\s+stage=identity\s+result=mismatch")
VALUE_RE = r"(0[xX][0-9a-fA-F]+|\d+)"
EXPECTED_TS_RE = re.compile(r"expected_ts=" + VALUE_RE)
EXPECTED_SIZE_RE = re.compile(r"expected_size=" + VALUE_RE)


def fail(msg):
    print("error: %s" % msg, file=sys.stderr)
    sys.exit(1)


def parse_int(text):
    return int(text, 0)


def fmt(value):
    return "%d (%#010x)" % (value, value)


def values_from_log(log_path):
    """Pull expected_ts/expected_size from the last identity-mismatch line."""
    if not os.path.isfile(log_path):
        fail("log file not found: %s" % log_path)
    try:
        with open(log_path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        fail("cannot read log %s: %s" % (log_path, exc))
    # Decode leniently: truncated lines can contain NUL bytes and other garbage.
    text = raw.decode("utf-8", errors="replace")
    chosen = None
    for line in text.splitlines():
        if IDENTITY_LINE_RE.search(line):
            chosen = line
    if chosen is None:
        fail('no "ev=build_data stage=identity result=mismatch" line in %s' % log_path)
    ts_match = EXPECTED_TS_RE.search(chosen)
    size_match = EXPECTED_SIZE_RE.search(chosen)
    if not ts_match or not size_match:
        fail("identity line found but expected_ts/expected_size could not be read")
    # Intentionally ignore everything else on this line, including expected_eq.
    return parse_int(ts_match.group(1)), parse_int(size_match.group(1))


def main():
    parser = argparse.ArgumentParser(
        description="Rewrite build_data.bin's u32 image-timestamp/image-size "
                    "identity fields (offsets %d and %d). The equipment hash "
                    "at offset 20 is never touched." % (TS_OFFSET, SIZE_OFFSET)
    )
    parser.add_argument("--ts", help="new u32 image timestamp (hex or decimal)")
    parser.add_argument("--size", help="new u32 image size (hex or decimal)")
    parser.add_argument("--from-log", metavar="LOGFILE",
                        help="take both values from the failing boot's "
                             "identity-mismatch line in this log")
    parser.add_argument("--cache",
                        default=os.path.join("Sunrise", "cache", "build_data.bin"),
                        help="cache file to patch (default: %(default)s relative "
                             "to the current directory)")
    parser.add_argument("--apply", action="store_true",
                        help="write the new values (default: dry run)")
    args = parser.parse_args()

    if args.from_log is not None:
        if args.ts or args.size:
            fail("--from-log cannot be combined with --ts/--size")
        new_ts, new_size = values_from_log(args.from_log)
    elif args.ts and args.size:
        try:
            new_ts = parse_int(args.ts)
            new_size = parse_int(args.size)
        except ValueError:
            fail("--ts and --size must be hex (0x...) or decimal integers")
    else:
        fail("give either --from-log LOGFILE or both --ts and --size")

    for name, value in (("ts", new_ts), ("size", new_size)):
        if not 0 <= value <= 0xFFFFFFFF:
            fail("%s value %d does not fit in a u32" % (name, value))

    if not os.path.isfile(args.cache):
        fail("cache file not found: %s" % args.cache)
    try:
        with open(args.cache, "rb") as fh:
            data = bytearray(fh.read())
    except OSError as exc:
        fail("cannot read cache %s: %s" % (args.cache, exc))
    if data[:len(MAGIC)] != MAGIC:
        fail("%s does not look like a Sunrise build-data cache "
             "(expected %r header)" % (args.cache, MAGIC))
    if len(data) < SIZE_OFFSET + 4:
        fail("%s is too short to hold the identity fields" % args.cache)

    old_ts = struct.unpack_from("<I", data, TS_OFFSET)[0]
    old_size = struct.unpack_from("<I", data, SIZE_OFFSET)[0]

    print("cache : %s" % args.cache)
    print("before: image_timestamp=%s  image_size=%s" % (fmt(old_ts), fmt(old_size)))
    print("after : image_timestamp=%s  image_size=%s" % (fmt(new_ts), fmt(new_size)))
    print("patching offsets %d (timestamp) and %d (size); equipment hash at "
          "offset 20 left untouched" % (TS_OFFSET, SIZE_OFFSET))

    if (old_ts, old_size) == (new_ts, new_size):
        print("MATCH - no restamp needed")
        return

    if not args.apply:
        print("dry run - nothing written (pass --apply to write)")
        return

    struct.pack_into("<II", data, TS_OFFSET, new_ts, new_size)
    try:
        with open(args.cache, "wb") as fh:
            fh.write(data)
    except OSError as exc:
        fail("cannot write cache %s: %s" % (args.cache, exc))
    print("wrote %s" % args.cache)


if __name__ == "__main__":
    main()
