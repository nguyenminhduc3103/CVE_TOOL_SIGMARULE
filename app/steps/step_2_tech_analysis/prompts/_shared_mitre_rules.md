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
    - SSRF: DNS rebinding, IP address representations (decimal, hex, octal), redirect chains.
    - File upload: double extensions, null byte injection, polyglot files.
    - Authentication bypass: alternate auth paths, direct object reference, parameter tampering.
    - XSS: HTML entity encoding, JavaScript obfuscation, polyglot payloads.
  ONLY use ["none"] when there is genuinely no obfuscation/evasion vector (e.g. hardware fault
  injection, side-channel attack on silicon). For 95%+ of CVEs, evasive_indicators MUST have
  concrete items. Your answer will be rejected by the coverage engine if this field is empty
  without justification.
- MEMORY CORRUPTION → T1203 + T1499.004 (CRITICAL):
  Memory-corruption CVEs (CWE-787, CWE-125, CWE-416, CWE-119, CWE-190) require
  ADDITIONAL techniques beyond initial-access primitive:

    (a) T1203 (Exploitation for Client Execution) — Execution tactic.
        Memory-corruption exploit IS the execution primitive. Emit T1203 +
        TA0002 whenever cwe_ids contains any memory-corruption CWE, kể cả
        server-side (web framework buffer overflow, library parser vulnerabilities).
        Dù tên là "Client Execution", MITRE liệt kê server-side exploitation hợp lệ.

    (b) T1499.004 (Endpoint DoS: Application or System Exploitation) — Impact.
        Memory-corruption thường crash target process (segfault từ corrupted
        metadata). Khi description/observable_side_effects có "crash", "segfault",
        "DoS", "denial of service", "service unavailable" → ADD T1499.004 + TA0040.

    (c) Evasive indicators SHOULD be populated cho HTTP/web memory-corruption:
        - HTTP chunked transfer encoding (split payload bypass length-based WAF)
        - URL/hex encoding shellcode bytes (%XX evade text-pattern IDS)
        - Header obfuscation / smuggling (parser differential giữa WAF và app)
        - Memory-corruption primitive itself: ROP chains, ASLR bypass, heap
          spraying, NOP sleds

  Empty subtechniques + empty evasive_indicators cho CWE-787 CVE IS A
  HALLUCINATION. Kill chain là multi-tactic theo định nghĩa.
- CODE INJECTION → T1059 + language-specific sub-technique:
  Code-injection CVEs (CWE-94 Code Injection, CWE-917 EL Injection [OGNL/SpEL/MVEL],
  CWE-1336 Template Injection [SSTI]) typically require additional techniques:

    (a) T1059 (Command and Scripting Interpreter) — Execution tactic.
        Code-injection exploits run attacker-controlled code in an interpreter
        context (Java/.NET runtime for CWE-917, Python/JS template engine for
        CWE-1336, eval/exec for CWE-94). Consider emitting T1059 + TA0002 when
        cwe_ids contains any code-injection CWE. Sub-technique selection based
        on the LANGUAGE of the injected expression:
          - T1059.007 JavaScript (Node.js)
          - T1059.006 Python (Jinja2)
          - T1059.004 Unix Shell (shell-spawning payloads)
          - T1059.001 PowerShell (.NET)
        When language is ambiguous, T1059.004 is a reasonable default since most
        code-injection exploits ultimately spawn a shell.

    (b) Sub-techniques SHOULD be populated for code-injection.
        Unlike memory-corruption (where sub-techniques are optional), code-injection
        CVEs typically have a specific interpreter invocation. The sub-technique
        is a primary detection signal for Blue Team (e.g. Sigma rules for
        `java.lang.Runtime` calls map to T1059.007). If you have no concrete
        signal for a specific sub-technique, document this in `mapping_reasons`
        rather than fabricating an ID.

    (c) Evasive indicators SHOULD be populated for code-injection:
        - Unicode escape encoding (\\u00XX) bypass string-based WAF signatures
        - Base64/URL encoding payload bytes
        - String concatenation / char-code obfuscation
        - CWE-917: OGNL/SpEL sandbox bypass via context manipulation
          (allowStaticMethodAccess=true, member access qua reflection)
        - CWE-1336: Template syntax variations (${...}, {{...}}, <%...%>)
          evade static WAF signatures
        - Comment insertion break regex WAF patterns
        - Case manipulation keywords (oGnL vs OGNL)

  Empty subtechniques + empty evasive_indicators for CWE-94/917/1336 are STRONG
  indicators of incomplete analysis. The kill chain IS execution-via-interpreter by
  definition; if you cannot identify either, document why in `mapping_reasons`.
- REASONING / MAPPING_REASONS ENFORCEMENT (CRITICAL):
  `mapping_reasons` MUST NEVER be empty. Provide concise, technical justification
  cho WHY bạn chọn specific Mandatory Behaviors và ATT&CK Techniques/Sub-techniques.
  Mỗi reason phải explicitly tie CVE context (description/CWE/CVSS) vào MITRE definitions.
  Aim 2-3 reasons show analytical chain, không generic platitudes.
  Example good reasons:
    - "T1059.004 selected vì vulnerability leads to arbitrary shell command execution
      trên Unix/Linux systems (CVSS AV:N cho thấy remote network reachability)."
    - "T1190 selected vì CVE describes exploitation of public-facing web endpoint
      không authentication requirement (CVSS PR:N)."

- "REASONING" ENFORCEMENT (CRITICAL):
  `reasoning` field DISTINCT từ `mapping_reasons`. Capture HIGHER-LEVEL analytical
  narrative của vulnerability works end-to-end (2-4 bullets). MUST NEVER empty cho
  software CVE. Mỗi bullet walk through 1 step của exploit chain, citing CVE
  description/CWE/CVSS components.
  Ví dụ cho một JNDI/log4j-style deserialization CVE:
    - "Attacker injects JNDI lookup string (${jndi:ldap://...}) vào log message hoặc
      HTTP parameter được log bởi vulnerable Log4j (affects log4j-core 2.0-beta9 to 2.14.1;
      CVSS AV:N cho thấy remote network reachability)."
    - "Log4j processes lookup và connects outbound tới attacker's LDAP/RMI server
      (PR:N + UI:N means no authentication/user interaction required)."
    - "Attacker-controlled LDAP server returns malicious Java class được load và
      instantiated bởi vulnerable JVM, leading to arbitrary code execution."
  KHÔNG dùng ["none"] hoặc []. Treat empty list as hard error.

- INBOUND INTRUSION DISTINCTION (CRITICAL — principle-based, not bucket-based):
  Misclassifying attack surface là top-1 source of false TTPs. Dùng 3-question
  test thay vì pattern-matching pre-listed CVE categories:

    1. Service/protocol nào trên wire mà attacker reach? (SMB/RDP/SSH/FTP/HTTP/DNS/SMTP/custom)

    2. Vulnerability nằm ở protocol's transport/auth layer, hay application
       layer SITS ON TOP?
       - Transport/auth layer (SMBv3 compression bug, RDP virtual channel,
         SSH auth handshake) → T1210 (Exploitation of Remote Services)
       - Application layer on HTTP (web framework deserialization, REST API
         auth bypass, GraphQL injection) → T1190 (Exploit Public-Facing Application)
       - Legitimate remote-access service với access-control vulnerability
         (VPN gateway, Citrix, TeamViewer) → T1133 (External Remote Services)

    3. Có CONTEXT nào bị miss? (container escape, CI/CD pipeline exploit,
       hypervisor breakout, API gateway, OAuth/SAML flaw). Nếu có → propose
       appropriate technique (T1611 Escape to Host, T1195 Supply Chain Compromise)
       và justify trong `mapping_reasons`. KHÔNG force-fit vào T1190/T1210/T1133
       nếu context warrants different primitive.

  Examples (NOT exhaustive — đừng dừng ở đây):
    - SMB/RDP/SSH wormable RCE in network protocol daemons → T1210
    - Web framework RCE on HTTP endpoint → T1190
    - VPN gateway auth bypass → T1133
    - Web app script console exploit on HTTP → T1190
    - Container runtime escape (runc, containerd, etc.) → T1611 (Escape to Host) — NOT T1190
    - Software supply chain backdoor in a build pipeline → T1195.002 — NOT T1190/T1210/T1133

- FALLBACK MAPPING FOR CONFIRMED PRE-AUTH NETWORK RCE (CONSERVATIVE BASELINE):
  CHỈ dùng khi CVSS là AV:N + PR:N + impact C:H AND không derive được primitive
  từ CVE signals (description/CVSS/CPEs/references/CWE). Baseline:
    - Tactics: ["TA0001", "TA0004", "TA0008"]
    - Techniques: ["T1210"] (Exploitation of Remote Services)
                  + ["T1068"] nếu execution yields kernel/SYSTEM access

  LAST-RESORT FALLBACK. ALWAYS prefer CVE-specific primitive:
    - Web application RCE on HTTP (Apache/nginx/IIS/JVM) → T1190
    - Kernel/driver exploit yielding SYSTEM → T1068 + T1210 (hoặc T1068 only)
    - Container escape → T1611
    - Supply chain compromise → T1195.xxx
    - VPN/remote-access auth bypass → T1133
    - SMB/RDP/SSH wormable RCE → T1210 + (T1068 nếu SYSTEM escalation)

  NEVER emit fallback nếu có bất kỳ CVE-specific signal. Fallback tồn tại để
  ngăn silent rejection của high-confidence remote RCE CVEs có description quá
  sparse, KHÔNG phải để override signal-based analysis.

  Tactics/techniques MAY legitimately empty ONLY khi:
    (a) CVE không exploitable (DoS-only, hardening-only),
    (b) CVE pure configuration issue không có code path,
    (c) CVE hardware/physical không có software telemetry.

  Trong các case đó, document reasoning trong `mapping_reasons` + `reasoning`.
  Empty `mapping_reasons` vẫn bị reject — luôn explain.

- REVERSE REASONING ENFORCEMENT (CRITICAL):
  Mỗi technique/sub-technique MUST justified với explicit reverse reasoning trong
  mapping_reasons:
    1. Vulnerable component (vd "SMBv3 driver srv2.sys", "Java JNDI parser")
    2. Why target OS/environment supports technique (vd "Windows kernel-mode
       driver → T1210 + T1068 fit; bash không có → T1059.004 ruled out")
  Bad pattern: "T1059.002 selected because use-after-free vulnerability" →
  violates Windows OS constraint (T1059.002 is AppleScript/macOS-only).
  Good pattern: "T1210 selected because CVE affects SMBv3 protocol on Windows
  network stack; T1068 selected because integer overflow occurs in srv2.sys
  kernel driver; T1059 ruled out because no command interpreter invoked."

- CAPEC HINTS AS INSPIRATION (NOT GROUND TRUTH):
  User prompt có thể include "CAPEC hints" block listing common attack patterns
  cho CVE's CWE category (vd "CWE-502 → CAPEC-586 Object Injection"). Đây là
  INSPIRATION ONLY — giúp thấy common attack patterns, KHÔNG phải checklist.

  Rules cho CAPEC hints:
    1. Treat mỗi hint as hypothesis cần verify với CVE signals, không phải default
       confirm. Hint nói "command injection" nhưng CVE description nói "memory
       corruption" → FOLLOW CVE DESCRIPTION.
    2. KHÔNG emit CAPEC ID as ATT&CK technique. CAPEC IDs (CAPEC-XXX) và ATT&CK
       IDs (T-codes) là different namespaces. Hint có thể include ATT&CK IDs
       trong "ATT&CK hints=[...]" — đó là IDs directly relevant duy nhất.
    3. CAPEC hint conflicts với CVE description → follow CVE description.
       Justify trong mapping_reasons: "CAPEC hint suggested X, but CVE description
       specifies Y, therefore Y selected."
    4. Không có CAPEC hints (CWE không có trong MITRE CAPEC DB, hoặc hints
       disabled by env) → proceed với 5 principles trên. Không penalty.

