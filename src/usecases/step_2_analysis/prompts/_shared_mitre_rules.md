- MITRE ATT&CK SUB-TECHNIQUE RESOLUTION:
  When CVE signals clearly identify a specific sub-technique primitive
  (e.g. CVE describes bash command injection → T1059.004 Unix Shell,
  PowerShell post-exploitation → T1059.001, Windows cmd shell → T1059.003),
  prefer the most specific sub-technique over the parent. Do not stop at
  parent techniques if the description, attack flow, or PoC provides
  enough signal to pick a specific sub-technique.

  When you DO select a sub-technique, populate BOTH:
    1. "techniques": [parent_id, ...]      # parent goes here for backward compat
    2. "subtechniques": [sub_id, ...]      # specific sub-technique goes here
  Example: For a Unix shell RCE → techniques=["T1059"], subtechniques=["T1059.004"].

  When you do NOT select a sub-technique (parent-only is correct), populate:
    1. "techniques": [parent_id, ...]      # parent only
    2. "subtechniques": []                 # empty is VALID here, see "SUBTECHNIQUE DECISION" below
  This is NOT a failure — it is honest reporting when no real sub-primitive
  signal exists in the CVE (e.g. T1190 has no sub-techniques in MITRE; an
  SMB compression bug maps to T1210 with no sub-tech available).

  OS-AWARE SUB-TECHNIQUE CONSTRAINT:
  Before selecting a specific sub-technique, you MUST verify the target OS context:
    - If the vulnerability strictly affects Microsoft Windows, NEVER select Unix-only or
      macOS-only sub-techniques (e.g., T1059.004 Unix Shell, T1059.002 AppleScript).
    - If the vulnerability affects Linux/Unix only, NEVER select Windows-only sub-techniques
      (e.g., T1059.001 PowerShell, T1059.003 Windows cmd).
    - Memory-corruption exploits (Use-After-Free, Buffer Overflow) executing directly via
      kernel memory manipulation do NOT map to T1059 unless a command interpreter
      (cmd.exe, PowerShell, bash, sh) is explicitly invoked post-exploitation.

  WHEN TO SELECT SUB-TECHNIQUES (5 soft principles — not a fixed decision tree):
    Use these as analytical lenses, not lookup rules. The goal is to derive
    sub-techniques from CVE-specific signals, not to pattern-match against
    pre-listed CVE categories. Different CVEs may satisfy multiple principles
    or none — use your judgment, justify in `mapping_reasons`.

    Principle 1 — OS/SERVICE SIGNAL:
      If the CVE description, CVSS vector, or CPEs indicate a specific
      operating system or service, prefer OS-/service-specific sub-techniques.
      Examples: "Windows Server 2019" → avoid Unix-only sub-techniques (T1059.004);
      "Linux kernel" → T1068 with kernel-exploit context. This is the OS-aware
      constraint from above.

    Principle 2 — PROTOCOL SIGNAL:
      If the CVE mentions a specific network protocol (SMB, RDP, SSH, HTTP,
      FTP, DNS, etc.), classify it as either a remote-service primitive or a
      web-application primitive based on what the protocol IS, not what
      similar CVEs have been. SMB/RDP/SSH wormable RCE = T1210 (exploitation
      of remote service). HTTP endpoint RCE = T1190 (exploit public-facing
      application). Do not assume one implies the other.

    Principle 3 — TOOL/INTERPRETER SIGNAL:
      If the CVE description or PoC references mention a specific shell,
      script engine, or interpreter (bash, sh, cmd.exe, PowerShell, Python,
      Perl, Ruby, JavaScript, VBScript, AppleScript, PHP, sql/mysql, docker,
      kubectl, etc.), map to the matching T1059.xxx sub-technique. Only emit
      the sub-technique if the tool/interpreter is invoked POST-exploitation
      (memory corruption that does NOT spawn a shell = NO T1059).

    Principle 4 — AUTH/EXPLOITABILITY CONTEXT:
      Use CVSS vector as a constraint, not a template. If PR:N + AV:N +
      impact C:H, the CVE is pre-auth network RCE — the sub-technique choice
      should derive from which protocol/service is on the wire, not from
      a hardcoded "always emit T1210+T1068" rule. For local privesc (AV:L),
      prefer T1068 / T1548.xxx over network primitives.

    Principle 5 — NO-SIGNAL RULE:
      If the CVE description, CVSS vector, CPEs, references, and CWE do NOT
      mention any specific tool, interpreter, protocol, OS service, or
      execution environment that would let you pick a sub-technique, emit
      parent-only with an explicit `mapping_reason` explaining what signals
      you looked for. This is NOT a failure — it is honest reporting that
      the public information is insufficient for sub-technique granularity.

  SUBTECHNIQUE DECISION (principle — never a hard mandate):
    Selecting a sub-technique is ALWAYS a judgment call based on whether
    the CVE actually exposes a specific sub-technique primitive.
    The presence of a keyword (e.g. "Apache", "Windows") in the CVE
    description does NOT by itself require emitting a sub-technique.

    Empty `subtechniques: []` IS ALWAYS VALID when:
      1. The parent technique has no sub-techniques in current MITRE ATT&CK
         (e.g., T1190 Exploit Public-Facing Application, T1210 Exploitation
         of Remote Services, T1566.002 — these are inherently parent-only
         or have no granular sub-primitive). For these parents, emitting
         a sub-technique is technically impossible OR would require
         fabricating a sub-technique ID like "T1190.001" that does not
         exist in MITRE — DO NOT do this.
      2. The parent technique has sub-techniques in MITRE, but the CVE
         signals do NOT distinguish between them. For example:
           - A generic HTTP RCE in Apache → T1190 (no sub-technique needed
             unless a specific shell/interpreter is named)
           - An SMB compression bug → T1210 (no sub-technique available)
           - A cross-platform auth bypass → T1078 (no OS-specific signal)
      3. Choosing an OS-specific or tool-specific sub-technique would be
         guess-work, not analysis.

    WHEN sub-techniques ARE appropriate (emit only if you have real signal):
      - A specific shell/interpreter is invoked post-exploitation → T1059.001
        (PowerShell), T1059.003 (Windows cmd), T1059.004 (Unix Shell),
        T1059.006 (Python), T1059.007 (JavaScript), etc.
      - A specific OS-only primitive is the actual attack surface and the
        parent technique has OS-specific sub-techniques:
          - Linux kernel exploit → T1068 with kernel context (no sub-tech)
          - macOS-specific Office macro → T1059.002 (AppleScript)
      - A specific payload type / file format is the delivery mechanism:
          - .ps1 → T1059.001
          - .jar / .war / Java deserialization → T1190 stays parent
      - A specific execution primitive is named in description:
          - "command injection" + bash → T1059.004
          - "DLL injection" → T1059.001 / T1218.011
          - "lateral movement via WMI" → T1047 (no sub-tech needed)

    CRITICAL ANTI-HALLUCINATION GUARD (overrides any keyword match):
      NEVER emit a sub-technique ID that is NOT in the current MITRE
      ATT&CK matrix. You will not be penalized for emitting
      `subtechniques: []` when no real signal exists. You WILL be
      penalized (and the output rejected by the coverage engine) for
      emitting a fabricated ID like "T1190.001" or repeating the
      parent ID as its own sub-technique ("T1190" inside
      `subtechniques: ["T1190"]`).

    Format: when `subtechniques: []` is appropriate, write a
    `mapping_reason` that documents what you checked (e.g. "T1190 has no
    sub-techniques in MITRE ATT&CK; CVE describes HTTP endpoint RCE in
    a web framework with no specific shell/interpreter invocation").
    This is GOOD output, not a failure mode.
- EVASIVE INDICATORS ENFORCEMENT (CRITICAL):
  Do NOT default to "none" for evasive_indicators. The field MUST NOT BE EMPTY unless the CVE
  is a pure hardware/physical bug with no software telemetry path. For all software CVEs, you
  MUST populate evasive_indicators with at least 1-3 concrete evasion techniques that a real
  attacker would use to bypass detection.
    - Injection (CMDi, SQLi, JNDI): string obfuscation (e.g. ${lower:l}, ${upper:j} to bypass
      WAFs), encoding (base64, URL, Unicode), nested expansion, comment insertion.
    - Deserialization: polymorphic gadget chains, type confusion payloads, encryption.
    - Memory corruption: ROP chains, ASLR bypass, stack pivoting, heap spraying.
    - Path traversal: alternate encodings (%2e%2e%2f), double encoding, null bytes.
    - File upload: double extensions, null byte injection, polyglot files.
    - Authentication bypass: alternate auth paths, direct object reference, parameter tampering.
    - XSS: HTML entity encoding, JavaScript obfuscation, polyglot payloads.
  ONLY use ["none"] when there is genuinely no obfuscation/evasion vector (e.g. hardware fault
  injection, side-channel attack on silicon). For 95%+ of CVEs, evasive_indicators MUST have
  concrete items. Your answer will be rejected by the coverage engine if this field is empty
  without justification.
- MEMORY CORRUPTION → execution-aware discriminator (not a hard mandate):
 Memory-corruption CVEs (CWE-787/125/416/119/190) có nhiều cách map Execution
 tactic. T1203 (Exploitation for Client Execution) named for CLIENT-SIDE
 exploits where attacker code runs on victim's machine. CHO T1203 khi
 `execution_surface == "server_side"` chỉ khi affirmative answer cho CẢ 3 câu hỏi:

 (a) Does the vulnerable component run as a USERLAND PARSER PROCESS on the
 target server (vd Apache mod_fcgid FCGI worker, nginx handler process,
 REST framework parser)? If kernel-mode (srv.sys driver, network stack)
 → T1203 DOES NOT FIT. Use T1068 for SYSTEM escalation.

 (b) Is the vulnerability exploited FROM a network protocol that reaches
 this server (HTTP/HTTPS/SMB/RDP)? If no protocol — vd local kernel
 driver exploit → T1203 DOES NOT FIT.

 (c) Does the exploit CHAIN require user interaction on the target
 (e.g. user opens document, clicks link)? For pure server-side RCE
 → T1203 DOES NOT FIT (no user action on target).

 If CẢ 3 → "yes" → consider T1203 as SECONDARY Execution tactic (after
 initial-access technique). Document decision in mapping_reasons: "T1203
 applies because [vulnerable parser process] runs in userland on [target],
 exploit chain [parses attacker input from network], no user interaction
 required on target."

 Nếu bất kỳ câu nào → "no" hoặc "unclear" → SKIP T1203, use initial-access
 technique (T1190 for HTTP, T1210 for SMB/RDP/SSH) alone — these already
 cover Execution tactic for remote exploitation.

 Concrete examples:
 - EternalBlue CVE-2017-0144 (SMBv1 buffer overflow in srv.sys kernel):
 Câu (a) NO (kernel driver, not userland parser), (b) YES (SMB port 445),
 (c) NO (no user action on target). Skip T1203 → emit T1210 + T1068
 (kernel-mode code execution yields SYSTEM via token stealing).
 - Apache mod_fcgid CVE-2013-4365 (heap overflow in FCGI parser process):
 Câu (a) YES (mod_fcgid is a userland parser worker), (b) YES (HTTP),
 (c) NO (pre-auth HTTP request). Both answers → MAYBE include T1203
 as secondary Execution technique (in addition to T1190). Document
 deviation in mapping_reasons.
 - MSHTML CVE-2021-40444 (.docx ActiveX in Word on victim's machine):
 Câu (a) N/A (client-side), (b) YES (email attachment delivery),
 (c) YES (user must open document). T1203 IS the right Execution
 technique — this is the classic "Client Execution" semantic.

 Default mapping (when in doubt):
 - HTTP memory corruption → T1190 (no T1203 unless parser-process rationale).
 - SMB/RDP/SSH memory corruption → T1210 (+ T1068 IF SYSTEM).
 - Kernel driver memory corruption → T1068.
 - Client-side document/browser → T1203.

 Document T1203 inclusion OR exclusion in `mapping_reasons` (NOT `reasoning`):
 The `reasoning` field belongs to Phase 1 (canonical facts about the CVE).
 Phase 2 writes technique justification into `mapping_reasons` — these
 are two separate fields in two separate JSON outputs. Mixing them up
 risks overwriting Phase 1's `reasoning` array or producing malformed JSON.
