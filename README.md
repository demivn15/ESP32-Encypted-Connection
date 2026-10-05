# ESP32 Encrypted Connection

Authenticated text messaging between two ESP32 boards over ESP-NOW. The firmware establishes a fresh session, encrypts short messages with AES-128-GCM, and verifies each record before delivering its plaintext. An encrypted acknowledgment confirms reception and provides a round-trip measurement for each text.

The application is written in C++ with the Arduino framework and PlatformIO. It targets two NodeMCU-32S boards, each connected to a computer through USB. Participant A starts the session, and participant B responds automatically. The computers upload firmware and display the serial consoles. The boards exchange messages directly on ESP-NOW channel 1.

## Contents

- [Requirements](#requirements)
- [First run](#first-run)
- [Serial commands](#serial-commands)
- [Session protocol](#session-protocol)
- [Packet format](#packet-format)
- [Security experiments](#security-experiments)
- [Metrics and repeated measurements](#metrics-and-repeated-measurements)
- [Native C++ tests](#native-c-tests)
- [Recorded results](#recorded-results)
- [Troubleshooting](#troubleshooting)
- [Repository layout](#repository-layout)
- [Documentation and references](#documentation-and-references)

## Requirements

### Hardware

- Two NodeMCU-32S ESP32 boards.
- Two USB data cables.
- One computer per board, or a single computer with two available serial ports.

Keep the boards close together for the first test. Record their placement and distance when collecting performance results.

### Software

- Visual Studio Code with the PlatformIO IDE extension.
- PlatformIO Core, available through the extension's terminal.
- A working USB serial driver for each board.
- Windows and PowerShell for the supplied native build and measurement scripts.

The firmware configuration pins `espressif32@6.12.0`, Arduino 2.0.17, and the `nodemcu-32s` board definition. PlatformIO downloads the firmware dependencies during the first build. The native Windows tools compile against the bundled mbedTLS source.

## First run

### 1. Obtain the project

Clone the repository:

```powershell
git clone https://github.com/demivn15/ESP32-Encypted-Connection.git
cd ESP32-Encypted-Connection
cd Project
```

Open the `Project` folder in VS Code. It contains `platformio.ini`. From the command palette, select **PlatformIO: New Terminal**.

All shell commands below run from `Project`. Commands such as `connect`, `/reset`, and `/attack` belong in the ESP32 serial monitor, not in PowerShell.

### 2. Provision the pair credential

The authorized boards need the same private 32-byte credential in `include/pair_secret.h`. This file is excluded from Git. A fresh public checkout does not contain it.

On one participant's Windows computer, install the native compiler and run the build script:

```powershell
pio pkg install --global --tool platformio/toolchain-gccmingw32
powershell -NoProfile -ExecutionPolicy Bypass -File .\compilar.ps1
```

The script compiles the native test, measurement, and credential-generation programs. It then creates `include/pair_secret.h` if the file is absent. If a credential already exists, the generator preserves it.

Share that exact header privately with the other participant and place it in their `Project/include` folder **before uploading firmware**. Generate the credential once for the pair. Independently generated credentials will cause HMAC authentication to fail.

An existing private project copy can keep its credential and proceed to firmware upload. Changing the credential requires rebuilding and uploading both authorized boards. Keep the header, private distribution archives, and firmware containing the credential out of public uploads.

### 3. Upload the two roles

Close any active serial monitor before uploading.

On the computer connected to A:

```powershell
pio run -e esp_a -t upload
```

On the computer connected to B:

```powershell
pio run -e esp_b -t upload
```

Both boards must run the same protocol version, with different roles. The three environments are:

| Environment | Role | Purpose |
|---|---|---|
| `esp_a` | A, initiator | Starts the authenticated session. |
| `esp_b` | B, responder | Responds to A and exchanges protected records. |
| `intruso` | Unauthorized initiator | Tests a connection attempt with a false credential. |

When several serial devices are connected, run `pio device list` and select the correct port through PlatformIO or the command's port option.

For example, specify A's port for both upload and monitoring:

```powershell
pio run -e esp_a -t upload --upload-port COM5
pio device monitor -e esp_a --port COM5
```

Replace `COM5` with the port reported for that board. When both boards share one computer, select each board's port separately.

### 4. Start the consoles

On A:

```powershell
pio device monitor -e esp_a
```

On B:

```powershell
pio device monitor -e esp_b
```

The project configures 115200 baud, LF line endings, local echo, and send-on-Enter input. Press Enter after each command. The `log2file` filter saves the console output under `logs/device-monitor-*.log`.

If the startup message is missing, press the board's EN/RST button once with its monitor connected. Check `[BOOT]` for role A or B and channel 1.

The firmware's explanatory console messages are currently in Spanish. The command names, packet types, and CSV identifiers match the examples in this README.

### 5. Establish the session

Enter the following in **both** serial monitors, one line at a time:

```text
/demo on
/reset
```

Then enter this **only on A**:

```text
connect
```

Wait for `[SESSION OK]` in both consoles. B responds automatically. The exchange also prints `HANDSHAKE_MS`, public ECDH values, and the session identifier when demo output is enabled.

### 6. Exchange a text

In A's monitor:

```text
HELLO_FROM_A
```

The complete exchange produces:

- `[CIPHERTEXT]` and `[TAG GCM]` on A with demo output enabled.
- `[SUCCESS]` and the recovered text on B.
- `[CONFIRMADO]` and `METRIC,RTT_TEXT,...` on A after its ACK passes verification.

Wait for confirmation before sending the next text. Then send a reply from B:

```text
HELLO_FROM_B
```

A now displays the recovered text, and B receives the authenticated confirmation. The payload limit is **128 UTF-8 bytes**. Accented characters can occupy more than one byte.

## Serial commands

| Input | Action |
|---|---|
| `connect` | Start negotiation from A. B waits for A. |
| Plain text followed by Enter | Encrypt and send a TEXT record after session confirmation. |
| `/help` | Display the command list. |
| `/reset` | Clear the local session and pending measurements. Run on both boards before reconnecting. |
| `/demo on` | Display public ECDH values, packet details, ciphertext, tags, and metric explanations. |
| `/demo off` | Reduce console output while retaining CSV metrics and result messages. |
| `/metricas` | Display the metric columns and units. |
| `/ping` | Exchange an encrypted ping/pong and record its RTT. |
| `/stats` | Display counters, free heap, minimum heap, queue drops, session state, and pending-text status. |
| `/attack ciphertext TEXT` | Flip one ciphertext bit in a protected record. |
| `/attack tag TEXT` | Flip one authentication-tag bit. |
| `/attack forged TEXT` | Replace ciphertext and tag with random bytes. |
| `/attack replay` | Retransmit the last normally sent TEXT with a valid, timely ACK. |
| `/attack sender TEXT` | Alter the declared sender address. |
| `/attack sid TEXT` | Alter the session identifier. |
| `/attack seq TEXT` | Alter the sequence and adjust its nonce without recalculating the tag. |

One normal text can be pending per sender. A local ping and a local text measurement cannot run at the same time. Wait for confirmation or the five-second timeout before starting the next measurement.

`/stats` counts accepted application records and enqueued protected records, including ACK and ping/pong traffic. Its TX and RX counters are not text-message counts. `/reset` preserves these counters and the demo setting. A physical restart resets them.

## Session protocol

![System architecture](Project/docs/architecture-en.png)

The following mechanisms handle negotiation and record protection:

| Mechanism | Responsibility |
|---|---|
| Ephemeral ECDH P-256 | Establish a fresh shared secret for each session. |
| HMAC-SHA256 | Authenticate negotiation with the private pair credential. |
| HKDF-SHA256 | Derive separate AES keys and nonce prefixes for each direction. |
| AES-128-GCM | Encrypt application payloads and authenticate their headers and ciphertext. |
| SID and a 64-record sequence window | Bind records to the session and reject replay. |

![Protocol sequence](Project/docs/protocol-en.png)

1. **HELLO:** A generates a random 16-byte SID, an ephemeral P-256 key pair, and a 32-byte random value. Its HMAC covers the header and payload with the protocol's HELLO label.
2. **RESPONSE:** B verifies HELLO, generates its own key pair and random value, and authenticates the complete handshake transcript. A verifies the response and its pending SID.
3. **Derivation:** Both boards validate the peer's public point and calculate the ECDH secret. HKDF takes this secret, the transcript hash as salt, and the context string `ESP-NOW-v2 keys`. Its 40 output bytes contain two 16-byte AES keys and two four-byte nonce prefixes.
4. **READY:** Each board verifies an encrypted READY record before accepting application texts.
5. **TEXT and ACK:** The receiver accepts a text only after its origin, session, nonce, GCM tag, and replay checks succeed. It returns an encrypted ACK containing the accepted TEXT sequence.

The private ECDH material and shared secret are cleared after derivation. Reset clears the session keys. The pair credential remains available for future authenticated negotiations and is never transmitted over ESP-NOW.

The handshake retransmits its existing serialized records once per second for up to 15 seconds. Duplicate control records can recover lost responses without new encryption. A normal TEXT is not retransmitted automatically.

The receive callback copies frames into an eight-entry queue. The main loop performs cryptographic checks and console output. ESP-NOW peer encryption is disabled in this implementation, so application-level protection covers the secure records.

## Packet format

Offsets start at zero. The header occupies 45 bytes and forms the authenticated associated data for GCM records.

| Field | Bytes | Offset |
|---|---:|---:|
| ASCII magic `SM` | 2 | 0 |
| Protocol version, `2` | 1 | 2 |
| Message type | 1 | 3 |
| Sender role, `1` or `2` | 1 | 4 |
| Sender MAC address | 6 | 5 |
| Session identifier, SID | 16 | 11 |
| Sequence number, big-endian | 4 | 27 |
| Payload length, big-endian | 2 | 31 |
| Nonce | 12 | 33 |
| Payload | `L` | 45 |
| Handshake HMAC or GCM tag | 32 or 16 | `45 + L` |

| Type | Name | Payload | Total application bytes |
|---:|---|---|---:|
| 1 | HELLO | Public point, 65 bytes, plus random value, 32 bytes | 174 |
| 2 | RESPONSE | Public point, 65 bytes, plus random value, 32 bytes | 174 |
| 3 | READY | Five-byte key-confirmation value | 66 |
| 4 | TEXT | Zero to 128 UTF-8 bytes | `L + 61` |
| 5 | PING | Eight-byte token | 69 |
| 6 | PONG | Returned eight-byte token | 69 |
| 7 | ACK | Accepted TEXT sequence, four bytes | 65 |

The largest datagram is a 189-byte TEXT. Each datagram fits within the 250-byte application-data limit of the selected ESP-NOW interface.

The nonce combines the directional four-byte prefix and SEQ expanded to eight big-endian bytes. READY takes sequence zero. Later records start at one, and counter exhaustion requires a new session. SEQ counts protected records in each direction, including ACK, PING, and PONG.

The receiver commits its replay-window update only after successful GCM authentication. A forged high counter cannot advance the window. The parser also rejects unsupported types or versions, inconsistent lengths, truncated input, and trailing bytes.

## Security experiments

Run the following from A after both boards show `[SESSION OK]` and no text is pending. Keep both monitor logs. Send a normal text after each rejected packet to verify continued operation in the same session.

| Experiment | Serial input on A | Expected receiver result |
|---|---|---|
| Ciphertext modification | `/attack ciphertext ATTACK_C` | `[REJECT]`, invalid GCM tag, no plaintext delivery. |
| Tag modification | `/attack tag ATTACK_TAG` | `[REJECT]`, invalid GCM tag, no plaintext delivery. |
| Forged record | `/attack forged ATTACK_FALSE` | `[REJECT]`, invalid GCM tag, no forged plaintext delivery. |
| Sender modification | `/attack sender ATTACK_MAC` | `[REJECT]`, invalid origin or role. |
| Session modification | `/attack sid ATTACK_SID` | `[REJECT]`, origin or SID belongs to another session. |
| Counter modification | `/attack seq ATTACK_SEQ` | `[REJECT]`, invalid GCM tag. |

For example, after the ciphertext experiment, send:

```text
NORMAL_AFTER_C
```

Check `[SUCCESS]` at B and `[CONFIRMADO]` at A. A rejected text must not create an ACK or a `RTT_TEXT` sample.

### Replay

1. Send `CAPTURED_1` as a normal text.
2. Wait for `[SUCCESS]` at B and `[CONFIRMADO]` at A.
3. Enter `/attack replay` on A.
4. Check B's replay rejection. The original text must have only one successful delivery.
5. Send another normal text and verify its confirmation.

The command reuses the exact stored datagram. It does not encrypt a new copy. Reset clears the capture, so another confirmed text is needed after reconnection.

### Unauthorized participant with two boards

1. Enter `/reset` on B and check `/stats` for an idle session.
2. Close A's monitor with `Ctrl+C`.
3. Upload the unauthorized configuration on A's computer:

   ```powershell
   pio run -e intruso -t upload
   pio device monitor -e intruso
   ```

4. Check `[INTRUSO]`, then enter `connect` in that monitor.
5. Check B for HMAC rejection and no established session. B must be idle so this tests the credential rather than an occupied session.
6. Close the intruder monitor and restore A:

   ```powershell
   pio run -e esp_a -t upload
   pio device monitor -e esp_a
   ```

7. Reset both sessions, enter `connect` on A, and verify a normal confirmed exchange.

The unauthorized configuration excludes the pair credential and generates a false one. The attack commands provide controlled fault injection from the firmware. They are separate from an independent radio capture or attacker implementation.

## Metrics and repeated measurements

### CSV columns

```text
METRIC,direction,plaintext_bytes,packet_bytes,encrypt_us,verify_decrypt_us,rtt_us
```

The rows start with `METRIC`. Subsequent fields follow the order shown above. The firmware's printed header names the direction column `direccion`.

| Direction | Meaning |
|---|---|
| `TX` | TEXT encryption and serialization time, before radio enqueueing. |
| `RX` | TEXT parsing, origin/session/nonce checks, GCM verification and decryption, and replay validation. Excludes ACK generation. |
| `RTT_TEXT` | From the start of TEXT encryption until the sender finishes verifying its corresponding encrypted ACK. |
| `ACK_TX`, `ACK_RX` | Separate operations for the four-byte text confirmation. |
| `PING_TX`, `PING_RX`, `PONG_TX`, `PONG_RX` | Separate ping/pong operations. |
| `RTT` | Ping round-trip time. |
| `ATTACK_TX` | Deliberately altered record transmission. |
| `REJECT` | Processing time until rejection. No plaintext delivery. |

For example, this illustrative row:

```text
METRIC,TX,5,66,658,0,0
```

means a five-byte text, a 66-byte application packet, and 658 microseconds for encryption and preparation. The remaining time columns do not apply to TX. Their zeros are placeholders, not measured decryption or round-trip times. Divide microseconds by 1000 to obtain milliseconds.

`RTT_TEXT` includes both endpoints, cryptographic operations, queues, radio transport, and scheduling. It is not a one-way delay or a measure of human reading time. A missing ACK produces a timeout after five seconds without an invented RTT. The text might have arrived while its ACK was lost.

### Three repetitions of the same text

1. Close and reopen both monitors to obtain fresh logs, then reset both sessions.
2. Enter `/demo off` on both boards. Establish the session with `connect` on A.
3. From A, send `TEST0123456789AB`, a 16-byte ASCII text.
4. Wait for `[CONFIRMADO]` or the timeout before the next attempt. Make three attempts in total. Keep B receiving during this trial and do not run `/ping` or attacks.
5. A fully successful trial produces three TEXT TX rows on A, three TEXT RX rows on B, and three `RTT_TEXT` rows on A. If an attempt fails, report attempted, accepted, and confirmed counts separately. Retain every attempt rather than removing failures to force a three-sample result.
6. Close the monitors before processing their logs. Record distance, obstacles, firmware revision, and the demo setting.

In each computer's PowerShell terminal, select the newest log:

```powershell
$trialLog = Get-ChildItem -LiteralPath .\logs -Filter 'device-monitor-*.log' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$trialLog.Name
```

Check the displayed filename, then summarize it. On A:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\resumir_metricas.ps1 -Log $trialLog.FullName -Destino .\measurements\trial_A
```

On B, run the same command with `trial_B` as the destination prefix.

The script produces:

| Output suffix | Contents |
|---|---|
| `.csv` | Extracted TEXT TX/RX and RTT records. |
| `_resumen.csv` | Local operation means and TEXT overhead, grouped by direction and length. |
| `_rtt_texto.csv` | Confirmed text RTT count, mean, minimum, and maximum. Created when TEXT RTT records exist. |
| `_rtt.csv` | Ping RTT summary. Created when ping RTT records exist. |

For an A-to-B trial, take TX from A's summary, RX from B's summary, and text RTT from A's `_rtt_texto.csv`. Keep those means separate. Fresh logs prevent earlier messages of the same length from entering the three-sample summary.

### Application overhead

```text
TEXT bytes = plaintext bytes + 45-byte header + 16-byte tag
           = L + 61

TEXT plus ACK bytes = L + 61 + 65
                    = L + 126
```

A 16-byte text occupies 77 application bytes. Its acknowledgment adds 65 bytes in the opposite direction, for 142 bytes per confirmed exchange. These totals exclude radio framing, negotiation, and link retransmissions. The confirmation cost belongs to the protocol as well as the measurement procedure.

## Native C++ tests

The Windows build script compiles the shared protocol with mbedTLS 2.28.10. After the provisioning/build step, run:

```powershell
.\build\pruebas.exe
```

The recorded suite passes **41 tests**, covering:

- ECDH agreement, invalid public points, and authenticated negotiation.
- HKDF and AES-GCM reference vectors.
- Altered ciphertext, tags, headers, and forged records.
- Replay, session isolation, out-of-order records, and forged high counters.
- Handshake retry behavior, payload boundaries, UTF-8, and strict parsing.
- Protected ping/pong, ACK validation, RTT deadlines, and timer wraparound.

The tests transfer datagrams in memory. They do not validate the wireless link. The final test-program message makes this distinction explicit.

To collect a new PC benchmark without replacing the committed reference measurements:

```powershell
.\build\mediciones.exe measurements\pc_local.csv
```

The benchmark records 30 samples for each plaintext size, 1, 16, 64, and 128 bytes. Its echo time concerns local protected operations in both directions, not ESP-NOW latency or the hardware TEXT acknowledgment trial.

To compile all firmware configurations without uploading:

```powershell
pio run -e esp_a -e esp_b -e intruso
```

## Recorded results

The retained radio trial from October 4, 2026 contains four confirmed A-to-B transmissions of the same 16-byte text. Each TEXT occupies 77 bytes and each ACK 65 bytes.

| TEXT sequence | Encrypt/prepare, microseconds | Text RTT, milliseconds |
|---:|---:|---:|
| 1 | 680 | 24.567 |
| 3 | 870 | 24.550 |
| 4 | 726 | 24.417 |
| 5 | 702 | 24.431 |
| Mean | 744.5 | 24.49125 |

The boards were side by side, with demo output enabled. Exact distance and obstacle details were not recorded. All four samples are retained. Their RTT reflects these conditions, including console output.

Five separate 16-byte texts received by A from B have a mean verification/decryption time of 700.4 microseconds. Those RX samples concern B-to-A traffic. They are not receiver timings for the four A-to-B transmissions above.

The validation records show 41 passing C++ tests and successful builds for `esp_a`, `esp_b`, and `intruso`. Build status concerns the revised source. The radio log does not identify an installed firmware hash.

The following hardware evidence is still pending:

- B's console log with receiver timings for the same A-to-B texts.
- Recorded execution of the five required attacks: ciphertext, tag, replay, forged packet, and unauthorized participant.
- A performance trial with demo output disabled and documented physical conditions.

The expected rejections in the experiment guide describe test criteria, not completed radio observations. The available measurements and their provenance are in [the confirmed-text CSV](Project/measurements/esp32_A_textos_confirmados.csv) and [the evidence summary](Project/measurements/evidencia_esp32.json).

## Troubleshooting

| Symptom | Check |
|---|---|
| `pio` is not recognized | Start a terminal through **PlatformIO: New Terminal**. |
| `pair_secret.h` is missing | Complete credential provisioning, or copy the existing pair header before building authorized firmware. |
| HMAC rejection between authorized boards | Check that both builds contain the same pair credential and that both sessions were reset. |
| Both boards wait without establishing a session | Check roles A/B, enter `connect` only on A, and confirm both boards run the same version on channel 1. |
| A message reports a missing confirmed session | Wait for `[SESSION OK]` on both boards before sending text. |
| Upload cannot access the serial port | Close the monitor and other programs holding that port. Check the cable, driver, and selected device. |
| `[TX]` appears without confirmation | Check the receiver's console. Enqueueing alone does not establish delivery. Wait for the timeout before another text. |
| ACK is rejected as an invalid format | Load this protocol version on both boards. An older firmware can lack ACK type 7. |
| Replay says a confirmed text is required | Send a normal text and wait for its valid ACK. Reset clears the stored replay capture. |
| Intruder test reports an occupied session | Reset B to idle before testing the false credential. |
| Summary contains more than three samples | Select the fresh trial log and check for earlier texts of the same length. |

## Repository layout

```text
Project/
  platformio.ini              Firmware environments and serial configuration
  compilar.ps1                Windows native build and initial provisioning
  resumir_metricas.ps1        Serial-log extraction and measurement summaries
  src/                       Commands, application loop, and ESP-NOW driver
  include/                   Driver declarations and private pair credential
  lib/SecureNow/src/          Crypto, session, parser, replay, and RTT classes
  tests/                     Native tests, benchmarks, and credential generator
  vendor/mbedtls/             Native cryptographic library source and license
  docs/                      Diagrams, protocol description, and experiment guides
  measurements/              Test/build records and measurement CSV files
  output/pdf/                Technical report
```

PlatformIO creates `.pio/` locally. The native build creates `build/`, and the monitor creates `logs/`. These directories and `include/pair_secret.h` are excluded from Git. The firmware includes C library code from mbedTLS. The project's application and protocol classes are C++.

## Documentation and references

| File | Contents |
|---|---|
| [Protocol specification](Project/docs/PROTOCOLO.md) | Packet fields, negotiation, acceptance checks, and replay behavior. Spanish. |
| [Hardware test guide](Project/docs/PRUEBAS.md) | Two-board setup, attack procedures, and measurements. Spanish. |
| [Design notes](Project/docs/EXPLICACION.md) | Cryptographic roles and code organization. Spanish. |
| [Requirements and evidence](Project/docs/RUBRICA.md) | Assessment criteria and current validation status. Spanish. |
| [Native test results](Project/measurements/pruebas.txt) | Recorded C++ test output. |
| [Firmware build results](Project/measurements/firmware.txt) | Build status and static memory figures. |
| [PC reference samples](Project/measurements/pc.csv) | In-memory benchmark measurements, without radio. |
| [Hardware attack worksheet](Project/measurements/ataques_pendientes.csv) | Required attack cases and fields for observed evidence. |

The protocol follows established cryptographic primitives documented in:

- [NIST SP 800-56A Revision 3: Pair-Wise Key Establishment](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final).
- [RFC 2104: HMAC](https://www.rfc-editor.org/rfc/rfc2104.html).
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html).
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final).
- [Espressif ESP-NOW documentation, ESP-IDF 4.4.7](https://docs.espressif.com/projects/esp-idf/en/v4.4.7/esp32/api-reference/network/esp_now.html).
- [Mbed TLS 2.28 authenticated GCM API](https://mbed-tls.readthedocs.io/projects/api/en/mbedtls-2.28/api/file/gcm_8h/).

The handshake, packet layout, replay window, and acknowledgment exchange are project-level design choices. The repository does not claim certification or a complete production security audit. Authorization depends on possession of the pair credential, so copying that credential permits impersonation. Radio interference and denial of service fall outside the demonstrated protections.

Third-party mbedTLS code retains the [license included with its source](Project/vendor/mbedtls/LICENSE).

## Authors

Mateo Oñate and Damian Viteri.

Cryptography, Yachay Tech University, School of Mathematical and Computational Sciences.
