# YAFFS2 decompile/disasm evidence — excerpts only, how to regenerate

**Why this file exists.** The `20261114-yaffs-*.c` and `20261114-yaffs2_scan_backwards.disasm`
files in this directory are **decompiler / disassembler output derived from Google's
copyrighted kernel binary** (`boot.img` → `work/vmlinux-3.78.elf`). They are derivative works
of proprietary code, so this repo keeps only the **short sections F38 actually cites**, not the
full function dumps. Do not re-add the full output to version control (see the publishing
discussion in `notes/findings.md` / project history). The full output is trivially
**regenerable** by anyone who has lawfully obtained their own OTA — the steps are below.

## Prerequisites

- The 3.78.540761 OTA, unpacked per `scripts/fetch-ota.sh` → `boot.img`.
- `work/vmlinux-3.78.elf`: symbolized kernel ELF produced from `boot.img` with
  [`vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) (25,362 kallsyms, base
  `0xc0008000`; see `firmware-summary.md` §2.2). Nothing below needs the OTA checked in.

Function of interest: `yaffs2_scan_backwards` @ `0xc0293bcc`–`0xc0294bfc` (0x1030 B).

## 1. Disassembly (`*.disasm`)

Done in the podman sandbox (official `debian:12-slim` + `binutils-arm-linux-gnueabi`,
firmware mounted read-only at `/fw`):

```sh
arm-linux-gnueabi-objdump -d \
  --start-address=0xc0293bcc --stop-address=0xc0294bfc \
  work/vmlinux-3.78.elf
```

Add `--stop-address=0xc028d2b0 --start-address=0xc028d180` for `yaffs_retype_obj`,
and `0xc028ea04`/`0xc028ea40` for `yaffs_oh_to_size`.

## 2. Decompiles (`*.c`)

Ghidra decompiler output, driven through REA (default provider, headless Ghidra):

```sh
source scripts/rea-env.sh
rea decompile "$PWD/work/vmlinux-3.78.elf" \
  --target-format raw-binary --architecture arm --entry-point 0xc0008000 \
  --provider ghidra --function yaffs2_scan_backwards --json
# likewise --function yaffs_retype_obj / yaffs_oh_to_size / yaffs_new_obj
```

(or the `rea` MCP `decompile` tool with `provider_id: "ghidra"`). Decompiler output is
heuristic — the `undefined`/`param_N` typing and `[obj,#100]`-style field offsets are
Ghidra's, not ground truth; the struct-offset reconstruction F38 calls for is still open.
