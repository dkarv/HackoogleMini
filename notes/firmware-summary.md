# googlehomemini — firmware knowledge & unknowns (from the OTA)

Standalone summary of everything we know about the Google Home Mini firmware, and what
remains unknown, **based on the OTA image we obtained**. Compiled 2026-11-14 from
`notes/findings.md` (F7–F37), the unpacked OTA in `target/ota-540761/`, and the evidence
files cited inline. This is a reading guide over the findings, not a new investigation —
every claim here is traceable to a finding ID and an evidence file.

---

## 0. The one caveat that governs everything below

**The firmware we have is not the firmware on the target device.**

| | Firmware we HAVE (the OTA) | The TARGET device |
| --- | --- | --- |
| Build | **3.78.540761** | **3.75.468362** |
| Source | spoofed Omaha check from a *second*, already-provisioned Mini (F20) | the unprovisioned `GoogleHome4983` unit (E1) |
| Locale | `de-DE` | `FR` / `fr` |
| Board | `joplin-b4`, `mushroom` | `mushroom` (same product) |
| OTA history | current stable build | **never took an OTA** (`has_update:false`, `new_version:0.0.0.0`, F1) — runs its **factory** image |

Both are the gen-1 Home Mini (`product_name: mushroom`, H0A, Marvell Armada 1500
Mini-Plus, ARMv7-LE). They run the same software family, so the **architecture** carries
over. But every **version-specific** fact (kernel patch level, Chrome version, daemon
versions, which bug is fixed) is measured on 3.78 and is **assumed, not proven**, for the
3.75 target. The target has never been measured on its own binaries — see §5 (U3). Google
only ever offers the current build over Omaha, and the 40-hex CDN URL suffix for old
builds is unknown (F20), so we cannot currently download 3.75.468362.

Treat the rest of this document as: **"what the 3.78 OTA proves, and where the target may
differ."**

---

## 1. What the OTA actually is, and how we got it

- **Acquisition (F18→F20).** `scripts/omaha_spoof.py` (mitmproxy addon) rewrote the
  device's `tools.google.com/service/update2/json` check to `version 468362`; Google
  answered `status: ok` with a **full** (not delta) OTA — the current 3.78.540761 build.
  The `codebase` URL on `redirector.gvt1.com` is **public, unauthenticated, not
  device-bound** — anyone can download it. `scripts/fetch-ota.sh` downloaded, verified
  (sha256 `79180a03…72d32`, 95,990,069 B) and unpacked it.
  Evidence: `evidence/20261107-omaha-spoof-468362.json`,
  `evidence/20261107-ota-540761-inventory.txt`.
- **Format (F20, F25).** Android recovery-style **signed zip** (SignApk; `otacert`
  `O=Chromecast`, valid 2017–2037), with an `updater-script`. **Not** an A/B `payload.bin`
  — so Chrome OS `delta_generator` is not needed; images are flashed with
  `write_raw_image` / `/bin/flash_bootloader`.
- **`updater-script` enforces anti-downgrade in software**:
  `assert(!less_than_int(1781234529, getprop("ro.build.date.utc")))` — refuses to flash a
  build older than itself. This is a **software-only** check (bypassed by a raw NAND
  write, but that needs hardware; F12/Piste 12).
- **Build identity (`ramdisk/build.prop`):**
  `ro.build.fingerprint = google/mushroom/mushroom:3.78/3.78_shortlived_522686_ff/540761:user/release-keys`,
  `ro.board.platform = mv88de3015` (Marvell Armada-1500 family),
  `ro.build.date = Fri Jun 12 2026` (packaging), `ro.build.have_selinux = false`,
  `ro.build.trustzone = enabled`, `ro.secure = 1`, `ro.debuggable = 0`.
  (Note: the **kernel** inside was built **Fri Sep 20 2024** — older than the 2026
  packaging date; the kernel tree is frozen relative to the OTA wrapper.)

### Image/partition map

Chain images (from `target/ota-540761/zip/`) map onto the courk-documented H0A NAND
partitions (F10). dm-verity is over `mtdblock7` (confirmed in `ramdisk/dmtable`, F20).

| OTA file | Partition(s) written | mtd | What it is | Modifiable without the signing key? |
| --- | --- | --- | --- | --- |
| `bootloader.joplin-b4` (128 KB) | prebootloader | mtd1 | Marvell BootROM-loaded, **signed + encrypted** (F26) | No — fused RKEK anchor |
| `tz_en.joplin-b4` (1.2 MB) | TZ, TZ-B | mtd2/3 | TrustZone, **signed + encrypted** (carries IV) | No |
| `post-bootloader.joplin-b4` (120 KB) | postbootloader, -B | mtd4/5 | **signed, NOT encrypted** — plaintext Thumb-ARM, verifies the kernel. **Auditable** (F26, Piste 5/11) | No (but auditable for a parser bug) |
| `boot.img` (4.1 MB) | kernel | mtd6 | figo header → `ANDROID!` boot image: Linux 3.8.13+ zImage + ramdisk | No — SHA1+RSA verified by postbootloader |
| `system.img` (90 MB) | rootfs | mtd7 | SquashFS 4.0 (zlib), **dm-verity** protected | No — root hash in signed boot.img ramdisk |
| — | cache | **mtd8** | **YAFFS2, rw, OUTSIDE verified boot** — the historical exploit target (Piste 2) | **Yes** (writable), but see F22 |
| — | factory_store | mtd10 | YAFFS2 ro: device TLS cert + private key, serial | — (dump before any write, F13) |

**Image container format (F25/F26):** every chain image starts `01 00 00 00`, then LE
magic **`0xC0DE`** at offset 4, a type byte, a 16-byte hash/IV field, image length at
offset 40, an RSA-signature-sized block, then the payload ("figo" / Marvell secure
image).

---

## 2. What we KNOW about the firmware (verified from the OTA)

All verified by static analysis of `target/ota-540761/` unless noted. "Verified" = read
off the binaries/strings; "inferred" items are in §4.

### 2.1 Secure boot & cryptography — fully mapped (F26, F25, F28)

- **Verification chain (confirmed by postbootloader strings):** Marvell ARMADA 1500
  Mini-Plus BootROM (fused RKEK) → prebootloader (enc) → TZ (enc) → **post-bootloader
  RSA-verifies the kernel with SHA1** (`bootimg SHA1 verify fail`, `Boot image verify
  header failed!`, `Verify k_buff image failed!`) → **rootfs is dm-verity** (F20).
- **Key store** is hardware-anchored: indexed RSA keys loaded into on-chip DTCM
  (`RSA KEY INDEX:%1X`, `RKEK CRC`, `AESK0 CRC`, `SIGNK7 CRC`), plus a **Customer Key
  Store** flashed by `/bin/flash_custk` — anchored to the SoC fused RKEK, so **you cannot
  swap your own public key without the Marvell root key.**
- **OTA update layer** (`chrome/update_engine`) verifies with **RSA-PSS + SHA-256** and
  enforces `targetversionprefix` (anti-downgrade). No weakness observed.
- **Net:** replacing any **pre-kernel** stage needs the Google/Marvell signing key;
  replacing the **kernel** needs the key **or** a bug in post-bootloader; the **rootfs**
  can't be modified in place at all (dm-verity). Userland `/bin/flash_image`,
  `/bin/flash_custk` are raw MTD writers but are **post-exploit primitives, not bypasses**
  (the stage above re-verifies at next boot).

### 2.2 Kernel (F20, F22)

- **Linux 3.8.13+**, built **Fri Sep 20 2024** (XZ zImage inside `boot.img`).
- Symbolized with `vmlinux-to-elf` → `work/vmlinux-3.78.elf` (25,362 kallsyms, base
  `0xc0008000`); the on-device `Image` keeps **kallsyms** (function names), so static
  kernel questions can be answered with names in Ghidra.
- **The YAFFS2 object-confusion bug (Piste 2 / F7) is PATCHED in this 3.78 kernel**
  (F22). `yaffs_retype_obj` exists and `yaffs2_scan_backwards` contains exactly the fixed
  mismatch branch (the 2014 upstream fix). **Piste 2 does not work against a 3.78 kernel.**
  Evidence: `evidence/20261108-kernel-3.78-yaffs-fix.txt`.

### 2.3 Rootfs userland & versions (F20, F21, F37, F33)

- **Chrome/Cast:** `chrome/cast_shell` (66 MB, ARM32 PIE) = **Chrome/92.0.4515.0**,
  **V8 9.2.230**, WebRTC source stamp **2021-05-19**, `CrKey/3.78.540761`. This is the
  M92 **branch base** — Cast Chrome is frozen here (F33).
- **Root LAN/RF daemons (versions verified, all run as root, F37):** `dnsmasq 2.78`,
  `wpa_supplicant v2.6-devel-3.78`, `hostapd v2.6-devel-3.78`, `dhcpcd 6.8.2`.
- **Hardening posture (F21, F35):** `ro.build.have_selinux=false` (SELinux **off**);
  `cast_shell` and `assistant` share uid `chrome` (group `grpc`); renderer **is**
  sandboxed (`process.json` has `--gpu-sandbox-failures-fatal=yes`,
  `--no-unsandboxed-zygote`, no `--no-sandbox` anywhere); kernel exports seccomp-bpf;
  unprivileged userns appears off; `/data` is a bind of writable YAFFS2 `/cache`.

### 2.4 Assistant architecture — the local gRPC/UDS seam (F21, F23, F24, F29–F32)

This is the deepest body of knowledge in the OTA, because it is what "replace the agent"
would target. On device the Assistant is **two processes with a local socket seam**:

- **Process split (F21).** `init.rc` starts `service assistant` =
  `/system/chrome/bin/assistant` (386 KB **thin launcher**, uid `chrome`). The actual
  engine (S3 cloud client + libassistant) is **`chrome/libhvc_perception_joplin.so`**
  (16 MB) — the only file carrying the `S3Bidi` / `S3OnePlatform` strings. `cast_shell`
  (66 MB) is the embedder. **There is no separate `libassistant.so`** (contradicts F13).
- **Entrypoint (F30, F31).** `libhvc` exports one public symbol,
  `NewLibassistantEntrypoint(nullptr)`; everything is behind that factory, configured by a
  JSON string. It returns a small (~4-method) vtable object whose method names/ABI are
  **not** recovered — so stubbing `libhvc` is impractical; **replacing the `assistant`
  process and speaking the sockets is the recommended path (option a).**
- **Sockets (F21, F24).** The engine serves gRPC + audio over unix sockets in `/tmp/grpc/`:
  `libassist_grpc.socket`, `libassist_uds_audio_{input,output}.socket` (+ gRPC audio
  variants). `libas_customer.use_client_audio_service: true` — the engine takes mic audio
  from `cast_shell` over the socket.
- **Local API surface (F21, F23).** Engine serves `assistant.api.*`: `ConversationService`
  (21 methods incl. `SendTextQuery`, `StartInteraction`), `AlarmTimerService` (20),
  `AudioUtilsService` (`PlayTtsText`), `BootupSettingsService` (`SetS3ApiKey`,
  `SetConfigString`), `EventNotificationService`, … `cast_shell` serves back
  `ClientAudioService`, `EmbedderUtilityService`, `SecureFileService`,
  `DeviceActionService`.
- **Protobuf schemas recovered without symbols (F21, F24).** The protos are protobuf
  **lite** (no descriptors). `scripts/recover_lite_protos.py` decodes **1080 messages /
  5607 fields** from `libhvc` via the `TcParseTable` data (field numbers, wire kinds,
  cardinality all resolved). **Field names are absent**; 915 sub-message refs unnamed;
  `string` vs `bytes` uncertain. Evidence:
  `evidence/20261108-libhvc-recovered-protos.txt`.
- **UDS audio framing — SOLVED (F29, F31).** Plain `AF_UNIX` **stream**; each protobuf
  message is `[u16 big-endian length][payload]`, max 65,535 B, one frame per message,
  confirmed on **both** client (`ml_framework`/`cast_shell`) and server (`libhvc`) sides.
  - `StreamAudioInputRequest` (client→engine): `f4`=SourceType, `f5.f1`=AudioBufferFormat
    (`int32 sample_rate`, `enum sample_format`, `int32 num_channels`), `f5.f3`=AudioBuffer
    (`bytes PCM`, `int64 ts`, `int32 frames`). `sample_format`: 1=S16, 2=S32, 3=F32.
  - `StreamAudioInputResponse.f1`: **1 = PAUSE, 2 = RESUME** (engine gates the mic).
  - Audio output is pull-based (client requests N bytes); encodings must be ≤ 5.
  - Evidence: `evidence/20261108-uds-audio-framing-ml_framework.txt`,
    `evidence/20261108-libhvc-uds-server-and-entrypoint.txt`,
    `evidence/20261108-config-output-bootup.txt`.
- **Boot handshake (F23, F32).** `cast_shell` caches config/S3 key/tokens until the engine
  is ready, registers via `CustomerRegistrationService/RegisterCustomer`, flushes
  `BootupSettingsService` setters, subscribes with `RegisterEventHandler` + heartbeat, then
  `Cast.Assistant.Bootup.End`. **`cast_shell` does NOT need faked Google auth to boot**
  (F32): the three *critical* signals (`silence_played_`, `last_reboot_src_notified_`,
  `privacy_mode_notified_`) are all **local to cast_shell** (ALSA/reboot-file/mic-mute),
  not engine replies; missing engine signals cost one ~30 s timeout and degrade "ready",
  they don't block boot. There is a `MarkShouldIgnoreAuthentication` escape.
- **Config (F32).** Engine endpoint is a config value (`internal.s3_grpc_server_uri`).
  Built-in hosts: `assistant-streaming-s3-pa.googleapis.com:443`,
  `embeddedassistant.googleapis.com:443`, an autopush sandbox host. The config file is
  dm-verity protected on disk.
- **Modules (F21).** `modular_updater/prebuilt_images/localhome.squashfs` =
  `localhomeplatform_binary` (Local Home / smart-home mesh + seccomp policy). The signed
  `modular_manifest.pb` names an `assistant` module **v1.61 not in the OTA** (runtime
  download?).

**Implication (the project's north star):** a local-LLM agent need not reimplement
Google's cloud S3 protocol. On-device it can take the place of the `assistant` process and
serve `assistant.api.*` + the two UDS audio sockets (framing now fully known) to an
**unmodified** `cast_shell`. That needs code execution as uid `chrome` at runtime — **not
root, not a modified rootfs** — but **would not persist** across reboots (dm-verity blocks
rootfs edits, and the launch is in `init.rc`).

### 2.5 Assistant cloud protocol (from network capture, F19)

From the **second Mini** boot capture (not the OTA, but same firmware family):
- Assistant traffic is **Google-internal S3** (`speech.s3.S3StubbyClientConnectorService/
  S3Bidi` on `assistant-s3-pa.googleapis.com`), **not** the public EmbeddedAssistant
  v1alpha2 (contradicts the old F13). The S3 schema is not public.
- One OAuth token per linked user (scope `androidathome`) + a fixed firmware-baked API key.
- Audio config 16 kHz confirmed on the wire.
- The Mini runs Home Assistant's Local Home SDK app and forwards smart-home intents to HA's
  webhook over the LAN.
- Evidence: `evidence/mitm-boot-mini2.flows`, `notes/mitm-capture.md`.

### 2.6 Security posture of the firmware (defensive register, F33–F37)

| # | Finding | Status |
| --- | --- | --- |
| F33 | Cast Chrome/V8 frozen at M92 branch base (2021-05-19) → inside the CVE-2021-30563 window, lacks all post-2021-05-19 V8/Chrome fixes | **Plausible by provenance, not proven** — needs V8 patch-diff or live PoC |
| F34 | "Unauth Cast LAUNCH runs arbitrary JS" (README Chain A) — cast_shell enforces an app-support **allowlist** (`ALLOWLISTED_BY_POLICY`, `aogh_url_whitelist_*`) | **Unverified** — likely gated; must decompile the LAUNCH handler + live test |
| F35 | A renderer V8 RCE lands **seccomp-confined as uid chrome** — takeover needs a 2nd-stage sandbox escape or kernel LPE | Verified (sandbox positive, SELinux off) |
| F36 | **Device trusts the full 128-root Mozilla CA set (incl. eMudhra) with no effective pinning** on its cloud channels → on-path attacker can MITM Assistant/S3 and inject client-ops (`tts.OUTPUT`, `device.UPDATE_VOLUME`, `bluetooth.*`) = **remote command without root** | **Strongest remote finding.** Empirically MITM'd in F19. Blocker to full PoC: undocumented S3 schema + device OAuth tokens. Exception: `lycraservice-pa` uses device mTLS and resisted |
| F37 | Root LAN/RF daemons (dnsmasq 2.78 < 2.83 DNSpooq class, wpa_supplicant/hostapd 2.6-devel, dhcpcd 6.8.2) all run as root | Versions verified; **per-CVE applicability depends on Google's `-3.78` backports — not yet cross-checked** |

Evidence: `evidence/20261114-phase1-firmware-static.txt`.

---

## 3. What this resolves about the device (U-series, firmware-relevant)

- **U2 — RESOLVED.** `product_name: mushroom` / `model_name: Google Home Mini` ⇒ gen-1
  H0A, Marvell Armada 1500 Mini-Plus, ARMv7-LE (E1). Board string `mv88de3015` (build.prop).
- **U3 — PARTIALLY RESOLVED.** The full **3.78.540761** OTA is downloaded and unpacked
  (rootfs, kernel, ramdisk, all chain images). **The target's own 3.75.468362 image is
  still missing** (§5).
- **U4 — verified boot CONFIRMED for this build.** dm-verity over mtdblock7 (F20),
  SHA1+RSA kernel verification by postbootloader (F26). Google's images cannot be patched
  in place. The historical bypass (YAFFS2 cache exploit) is **patched in the 3.78 kernel**
  (F22).

---

## 4. What is UNKNOWN or only INFERRED

### 4.1 The central gap: the target (3.75.468362) is unmeasured

Everything in §2 is from **3.78**. For the **target's factory 3.75** image, all of these
are **open** because we don't have the image (U3):

- Its **kernel build date** and therefore whether the **YAFFS2 bug is patched** (F22
  patched 3.78, but 3.75 is older — if built after courk's tested Jun-2019 kernel it's
  *probably* patched too, unproven).
- Its **Chrome/V8 version** (3.78 is 92.0.4515.0; 3.75 is older and unmeasured — bears on
  Magellan F16 and the CVE window F33).
- Its **daemon versions** (dnsmasq/wpa_supplicant/hostapd/dhcpcd — F37 versions are 3.78's).
- Whether its assistant process split, socket protocol and config schema match 3.78 (very
  likely same family, but not verified).

**Blocker:** Omaha only offers the current build; the 40-hex CDN suffix for 468362 is
unknown (F20). Options to close it: (a) provision the target and capture its own OTA
check-in (risks auto-updating it away from 3.75 — the thing that makes it interesting);
(b) a NAND dump of the target (needs hardware, U5); (c) an archived 3.75 image from
elsewhere.

### 4.2 Firmware questions still open on 3.78 itself

| Topic | Open question | Finding |
| --- | --- | --- |
| Postbootloader parsers | Is there a memory-corruption bug in the USB-image loader / mkbootimg header parser reachable **before/around** signature verification? (plaintext Thumb-ARM, auditable) | F27, Piste 5/11 |
| Rollback counter | Does post-bootloader enforce a **fused rollback counter**? If not, an old Google-signed vulnerable kernel could be NAND-written to revive Piste 2 | F25, Piste 12 |
| Chain A delivery | Can an arbitrary attacker receiver URL actually be loaded via Cast LAUNCH, or is it allowlist-gated? | F34 |
| V8 exploitability | Is CVE-2021-30563 (or later) actually exploitable on the frozen M92 tree? Needs patch-diff or PoC | F33 |
| Daemon CVEs | Which DNSpooq / wpa_supplicant / dhcpcd CVEs survive Google's `-3.78` backports? | F37 |
| Assistant protocol | **Field names** (lite protos — numbers only); `string` vs `bytes`; 915 unnamed sub-message refs; type-card bit layout assumed, not verified against the exact protobuf rev | F21, F24 |
| Boot signals | The engine-event → bootup-signal mapping (which proto event sets `received_authentication_`, language, etc.) | F32 |
| Config override | Whether `SetConfigString` can override `s3_grpc_server_uri` at runtime (would let an unmodified engine be pointed at a local server) | F32 |
| Runtime audio | The actual mic sample rate/format and output encoding values on the socket (runtime-determined; 16 kHz seen cloud-side but not proven on the socket) | F29, F32 |
| libhvc ABI | What `NewLibassistantEntrypoint` returns — method names/args of the ~4-method vtable | F30, F31 |
| Where libassistant lives | `cast_shell` vs `bin/assistant` vs `libhvc` — resolved to `libhvc` for the S3 client, but module v1.61 in the manifest isn't in the OTA | F20, F21 |

### 4.3 Hardware unknowns gating the firmware attacks (U5, U6)

- **U5** — gen-1 H0A has **no UART/JTAG/USB data path** (F2, F9); the only board-level
  route is physical NAND access (NandBug). No boot-log shortcut.
- **U6** — are the Mini's micro-USB D+/D- lines routed/tappable? The post-bootloader has a
  full USB-boot path (`Booting from NAND failed, booting from USB`), so if the data lines
  reach the SoC the USB parsers (F27/Piste 11) become reachable **without** opening the
  NAND. Needs a PCB continuity probe.

---

## 5. Bottom line

**What the OTA gave us:** a complete, verified map of the gen-1 Mini's **secure-boot
chain** (unbreakable without the Marvell key), its **rootfs** (frozen Chrome M92, SELinux
off, sandboxed renderer, root network daemons), and — most valuably — the **on-device
Assistant seam**: a two-process split where an unmodified `cast_shell` talks to a
replaceable engine over `/tmp/grpc` unix sockets whose framing and message layout we have
now largely reverse-engineered. That makes the realistic on-device goal **"serve the
`assistant.api.*` + UDS audio sockets as uid `chrome` at runtime"**, not "patch the
firmware."

**What the OTA did NOT give us:** code execution (dm-verity + signed boot hold; the
historical YAFFS2 bypass is patched in 3.78), and — critically — **anything measured on
the target's own 3.75.468362 factory image**, which we still cannot download. Every
version-specific conclusion is 3.78's and must be re-checked on 3.75 before it can be
relied on for the target.

**Strongest security takeaway (owner-defensive, F36):** the device validates its cloud
channels against 128 public CAs with no effective pinning, so an on-path attacker with any
trusted mis-issued cert can MITM the Assistant stream and inject device commands without
root. Mitigation is owner-side (segment/limit the Mini's egress) — the trust-store
decision is Google's.

---

### Source map

- Findings: `notes/findings.md` — F7–F12 (research), F13/F19 (cloud protocol), F20–F32
  (OTA deep-dive), F33–F37 (Phase-1 hardening).
- OTA tree: `target/ota-540761/` (`zip/`, `rootfs/`, `ramdisk/`, `boot.img`→`kernel.bin`,
  `Image`, `localhome/`).
- Key evidence: `evidence/20261107-ota-540761-inventory.txt`,
  `evidence/20261108-ota-540761-grpc-surface.txt`,
  `evidence/20261108-libhvc-recovered-protos.txt`,
  `evidence/20261108-kernel-3.78-yaffs-fix.txt`,
  `evidence/20261108-postbootloader-secureboot.txt`,
  `evidence/20261108-uds-audio-framing-ml_framework.txt`,
  `evidence/20261108-libhvc-uds-server-and-entrypoint.txt`,
  `evidence/20261108-config-output-bootup.txt`,
  `evidence/20261108-assistant-host-entrypoint.txt`,
  `evidence/20261114-phase1-firmware-static.txt`, `evidence/mitm-boot-mini2.flows`.
- Related notes: `notes/architecture.md`, `notes/mitm-capture.md`,
  `notes/firmware-plan.md`, `notes/ondevice-plan.md`.
