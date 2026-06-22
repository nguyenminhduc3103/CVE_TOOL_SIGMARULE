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
    Apache mod_fcgid with no specific shell/interpreter invocation").
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
  Memory-corruption CVEs (CWE-787 Out-of-bounds Write, CWE-125 Out-of-bounds
  Read, CWE-416 Use-After-Free, CWE-119 Improper Buffer Restriction, CWE-190
  Integer Overflow) require ADDITIONAL techniques beyond the initial-access
  primitive. Three required additions:

    (a) T1203 (Exploitation for Client Execution) — Execution tactic:
        The memory-corruption exploit IS the execution primitive. Emit
        T1203 + TA0002 whenever cwe_ids contains any memory-corruption CWE.
        This applies even for server-side exploits (Apache mod_fcgid,
        OpenSSL heartbleed, IIS buffer overflow). Despite the "Client
        Execution" name, MITRE ATT&CK lists server-side exploitation as
        a valid use case.

    (b) T1499.004 (Endpoint DoS: Application or System Exploitation) —
        Impact tactic: Memory-corruption exploits frequently crash the
        target process (segfault from corrupted metadata). When description
        OR observable_side_effects mentions "crash", "segfault", "DoS",
        "denial of service", "service unavailable", ADD T1499.004 to
        subtechniques and TA0040 to tactics.

    (c) Evasive indicators MUST be populated for HTTP/web memory-corruption:
        - HTTP chunked transfer encoding (split payload to bypass length-based
          WAF signatures)
        - URL/hex encoding of shellcode bytes (%XX form to evade text-pattern IDS)
        - Header obfuscation / smuggling (parser differential attack between
          WAF and mod_fcgid)
        - For the memory-corruption primitive itself: ROP chains, ASLR bypass,
          heap spraying, NOP sleds

  Empty subtechniques + empty evasive_indicators for a CWE-787 CVE IS A
  HALLUCINATION. The kill chain is multi-tactic by definition.
- CODE INJECTION → T1059 + language-specific sub-technique (CRITICAL):
  Code-injection CVEs (CWE-94 Code Injection, CWE-917 Expression Language
  Injection [OGNL, SpEL, MVEL], CWE-1336 Template Injection [SSTI]) require
  ADDITIONAL techniques beyond the initial-access primitive. Three required
  additions:

    (a) T1059 (Command and Scripting Interpreter) — Execution tactic:
        Code-injection exploits execute attacker-controlled code in an
        interpreter context (Java/.NET runtime for CWE-917, Python/JS template
        engine for CWE-1336, eval/exec for CWE-94). Emit T1059 + TA0002
        whenever cwe_ids contains any code-injection CWE. Sub-technique
        selection: pick based on the LANGUAGE of the injected expression
        (T1059.007 JavaScript for Node.js, T1059.006 Python for Jinja2,
        T1059.004 Unix Shell for shell-spawning payloads, T1059.001
        PowerShell for .NET). If language is ambiguous, default to
        T1059.004 (most code-injection exploits ultimately spawn a shell).

    (b) Sub-technique MUST be populated (not empty) for code-injection:
        Unlike memory-corruption (where sub-techniques are optional),
        code-injection CVEs ALWAYS have a specific interpreter
        invocation. The sub-technique is the primary detection signal
        for Blue Team (e.g. Sigma rule for `java.lang.Runtime` calls
        → T1059.007). Empty subtechniques for CWE-94/917/1336 IS A
        HALLUCINATION.

    (c) Evasive indicators MUST be populated for code-injection:
        - Unicode escape encoding (\\u00XX) to bypass string-based WAF
          signatures
        - Base64/URL encoding of payload bytes
        - String concatenation / char-code obfuscation
        - For CWE-917: OGNL/SpEL sandbox bypass via context manipulation
          (e.g. allowStaticMethodAccess=true, member access through
          reflection)
        - For CWE-1336: Template syntax variations (${...}, {{...}},
          <%...%>) to evade static WAF signatures
        - Comment insertion to break regex WAF patterns
        - Case manipulation of keywords (e.g. oGnL vs OGNL)

  Empty subtechniques + empty evasive_indicators for a CWE-94/917/1336
  CVE IS A HALLUCINATION. The kill chain is execution-via-interpreter
  by definition.
- REASONING / MAPPING_REASONS ENFORCEMENT (CRITICAL):
  The "mapping_reasons" field MUST NEVER be empty. You must provide a concise, technical
  justification for WHY you selected the specific Mandatory Behaviors and ATT&CK
  Techniques/Sub-techniques. Each reason must explicitly tie the CVE's context (description,
  CWE, CVSS vector) to the MITRE definitions.
  Example good reasons:
    - "T1059.004 was selected because the vulnerability leads to arbitrary shell command
      execution on Unix/Linux systems (CVSS AV:N indicates remote network reachability)."
    - "T1190 was selected because the CVE describes exploitation of a public-facing web
      endpoint without authentication requirement (CVSS PR:N)."
    - "mandatory_behavior 'network_callback' derived from CVE description mentioning
      outbound LDAP connection to attacker-controlled server."
  Aim for at least 2-3 mapping_reasons that show analytical chain, not generic platitudes.

- "REASONING" ENFORCEMENT (CRITICAL):
  The "reasoning" field is DISTINCT from "mapping_reasons". It captures the HIGHER-LEVEL
  analytical narrative of how this vulnerability works end-to-end (2-4 bullet points).
  This field MUST NEVER be empty for any software CVE. Each bullet should walk through
  one step of the exploit chain, citing the relevant CVE description, CWE, and CVSS
  vector components. Example for CVE-2021-44228 (Log4Shell):
    - "Attacker injects JNDI lookup string (${jndi:ldap://...}) into a log message or HTTP
      parameter that gets logged by vulnerable Log4j (CVE-2021-44228 affects log4j-core
      2.0-beta9 to 2.14.1; CVSS AV:N indicates remote network reachability)."
    - "Log4j processes the lookup and connects outbound to the attacker's LDAP/RMI server
      (PR:N + UI:N means no authentication or user interaction required)."
    - "Attacker-controlled LDAP server returns a malicious Java class which is loaded
      and instantiated by the vulnerable JVM, leading to arbitrary code execution
      (S:C scope - impact crosses the logging component boundary)."
  DO NOT use ["none"] or [] for this field. Treat the empty list as a hard error.

- INBOUND INTRUSION DISTINCTION (CRITICAL — principle-based, not bucket-based):
  Misclassifying the attack surface is a top-1 source of false TTPs. Use
  this 3-question test instead of pattern-matching against pre-listed
  CVE categories:

    1. What service / protocol is on the wire that the attacker reaches?
       (SMB / RDP / SSH / FTP / HTTP / DNS / SMTP / custom protocol / etc.)

    2. Is the vulnerability in the protocol's transport/auth layer, or in
       an application layer that SITS ON TOP of that protocol?
       - Transport/auth layer (e.g. SMBv3 compression bug, RDP virtual
         channel, SSH auth handshake) → T1210 (Exploitation of Remote Services)
       - Application layer on HTTP (e.g. web framework deserialization,
         REST API auth bypass, GraphQL injection) → T1190 (Exploit Public-
         Facing Application)
       - Legitimate remote-access service with access-control vulnerability
         (VPN gateway, Citrix, TeamViewer) → T1133 (External Remote Services)

    3. Is there a CONTEXT you may have missed? (container escape, CI/CD
       pipeline exploit, hypervisor breakout, API gateway, OAuth/SAML flaw,
       etc.) If yes, propose the appropriate technique (T1611 Escape to
       Host, T1195 Supply Chain Compromise, etc.) and justify in
       `mapping_reasons`. Do NOT force-fit into T1190/T1210/T1133 if the
       context warrants a different primitive.

  Examples to illustrate (NOT exhaustive — do not stop at these):
    - SMB/RDP/SSH wormable RCE (BlueKeep, EternalBlue, SMBGhost) → T1210
    - Web framework RCE (Log4Shell, Spring4Shell, Confluence OGNL) → T1190
    - VPN gateway auth bypass → T1133
    - Jenkins Script Console exploit → T1190 (web app on HTTP)
    - runc container escape → T1611 (Escape to Host) — NOT T1190
    - XZ Utils supply chain backdoor → T1195.002 (Compromise Software
      Supply Chain) — NOT T1190/T1210/T1133

- FALLBACK MAPPING FOR CONFIRMED PRE-AUTH NETWORK RCE (CONSERVATIVE BASELINE):
  Use ONLY when CVSS is AV:N + PR:N + impact C:H AND you cannot derive any
  primitive from the CVE signals (description, CVSS, CPEs, references, CWE).
  In that narrow situation, emit this baseline:
    - Tactics: ["TA0001", "TA0004", "TA0008"]
    - Techniques: ["T1210"] (Exploitation of Remote Services)
                  + ["T1068"] if execution yields kernel/SYSTEM access

  This is a LAST-RESORT FALLBACK. ALWAYS prefer the CVE-specific primitive:
    - Web application RCE on HTTP (Apache/nginx/IIS/JVM) → T1190
    - Kernel / driver exploit yielding SYSTEM → T1068 + T1210 (or T1068 only)
    - Container escape → T1611
    - Supply chain compromise → T1195.xxx
    - VPN / remote-access auth bypass → T1133
    - SMB/RDP/SSH wormable RCE → T1210 + (T1068 if SYSTEM escalation)

  NEVER emit the fallback if any CVE-specific signal is present. The fallback
  exists to prevent silent rejection of high-confidence remote RCE CVEs
  where the description is too sparse to analyze, NOT to override signal-
  based analysis.

  Tactics and techniques MAY legitimately be empty in the output ONLY when:
    (a) the CVE is not exploitable (denial-of-service only, hardening-only),
    (b) the CVE is a pure configuration issue with no code path, or
    (c) the CVE is hardware/physical with no software telemetry.

  In those cases, document the reasoning in `mapping_reasons` and
  `reasoning` (e.g. "CVE is DoS-only via resource exhaustion; no code
  execution primitive available"). Empty `mapping_reasons` is still
  rejected — always explain.

- REVERSE REASONING ENFORCEMENT (CRITICAL):
  Every technique/sub-technique you select MUST be justified with explicit reverse reasoning
  in mapping_reasons. For each technique/sub-technique, your reason must explicitly state:
    1. The vulnerable component (e.g., "SMBv3 driver srv2.sys", "Java JNDI parser")
    2. Why the target OS/environment supports this technique (e.g., "Windows kernel-mode
       driver, so T1210 + T1068 fit; bash not present, so T1059.004 ruled out")
  Bad reasoning pattern to AVOID: "T1059.002 selected because use-after-free vulnerability"
  → This violates Windows OS constraint (T1059.002 is AppleScript/macOS-only).
  Good reasoning pattern: "T1210 selected because CVE affects SMBv3 protocol on Windows
  network stack; T1068 selected because integer overflow occurs in srv2.sys kernel driver;
  T1059 ruled out because no command interpreter is invoked post-exploitation."

- CAPEC HINTS AS INSPIRATION (NOT GROUND TRUTH):
  The user prompt may include a "CAPEC hints" block listing common attack
  patterns for the CVE's CWE category (e.g. "CWE-502 → CAPEC-586 Object Injection").
  These are INSPIRATION ONLY — they help you see common attack patterns
  associated with the CWE category, but they are NOT a checklist to satisfy.

  Rules for using CAPEC hints:
    1. Treat each hint as a hypothesis to verify against CVE signals, not a
       default to confirm. If the hint suggests "command injection" but the
       CVE description says "memory corruption", FOLLOW THE CVE DESCRIPTION.
    2. Do NOT emit a CAPEC ID as an ATT&CK technique. CAPEC IDs (CAPEC-XXX)
       and ATT&CK IDs (T-codes) are different namespaces. The hint may
       include ATT&CK IDs in "ATT&CK hints=[...]" — those are the only
       directly relevant IDs to consider.
    3. If the CAPEC hint conflicts with the CVE description, follow the CVE
       description. Justify in mapping_reasons: "CAPEC hint suggested X, but
       CVE description specifies Y, therefore Y is selected."
    4. If no CAPEC hints are provided (CWE not in MITRE CAPEC database, or
       hints disabled by env), proceed with the 5 principles above as usual.
       No penalty for missing hints.

