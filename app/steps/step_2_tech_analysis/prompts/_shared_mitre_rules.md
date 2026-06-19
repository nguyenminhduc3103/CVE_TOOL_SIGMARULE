- MITRE ATT&CK SUB-TECHNIQUE RESOLUTION (CRITICAL):
  When mapping ATT&CK techniques, ALWAYS strive to identify the most specific Sub-technique applicable
  (e.g. use T1059.004 instead of just T1059 if the context implies a Unix Shell, T1059.001 for
  PowerShell, T1059.003 for Windows cmd). Do not stop at parent techniques if the CVE
  description, attack flow, or observed behaviors provide enough context for a sub-technique.
  When you identify a sub-technique, you MUST populate BOTH:
    1. "techniques": [parent_id, ...]      # parent goes here for backward compat
    2. "subtechniques": [sub_id, ...]      # specific sub-technique goes here
  Example: For a Unix shell RCE → techniques=["T1059"], subtechniques=["T1059.004"].

  OS-AWARE SUB-TECHNIQUE CONSTRAINT:
  Before selecting a specific sub-technique, you MUST verify the target OS context:
    - If the vulnerability strictly affects Microsoft Windows, NEVER select Unix-only or
      macOS-only sub-techniques (e.g., T1059.004 Unix Shell, T1059.002 AppleScript).
    - If the vulnerability affects Linux/Unix only, NEVER select Windows-only sub-techniques
      (e.g., T1059.001 PowerShell, T1059.003 Windows cmd).
    - Memory-corruption exploits (Use-After-Free, Buffer Overflow) executing directly via
      kernel memory manipulation do NOT map to T1059 unless a command interpreter
      (cmd.exe, PowerShell, bash, sh) is explicitly invoked post-exploitation.

  WHEN TO SELECT SUB-TECHNIQUES (concrete decision tree):
    - Java RCE (Log4Shell, Spring4Shell, etc.) → T1059.004 (Unix Shell) IF target is
      Linux/Unix server. IF target is Windows Server with Java → T1059 (parent only, since
      Java Runtime is cross-platform and may invoke cmd.exe OR sh depending on host OS).
    - Windows SMB/RDP/RPC wormable RCE (BlueKeep, EternalBlue, SMBGhost) → T1210 + T1068
      for the initial exploit, and T1021.001 (RDP) or T1021.002 (SMB) IF the protocol
      is used for subsequent lateral movement. Do NOT invent sub-techniques for
      T1210 itself (MITRE has no sub-techniques for T1210) or for unclear protocols.
    - Web application RCE via deserialization (Log4Shell, Fastjson) → T1190 (no sub-tech
      required, T1190 has no widely-used sub-techniques).
    - SQLi → T1190 + technique T1059.007 (JavaScript) IF stored XSS chain, otherwise
      T1190 (parent) is fine.
    - Process spawn with bash → T1059.004. Process spawn with cmd.exe → T1059.003.
      Process spawn with PowerShell → T1059.001. Shellcode loader → T1059 (parent only).

  IMPORTANT: Empty `subtechniques: []` IS VALID ONLY when ALL of these hold:
    1. The parent technique has no widely-used sub-techniques in current MITRE ATT&CK
       (e.g., T1190, T1566, T1210 — these are widely-known parent-only techniques).
    2. The CVE description, CVSS vector, CPEs, references, and CWE do NOT mention
       any specific tool, interpreter, protocol, shell, OS service, or execution
       environment that would let you pick a sub-technique.
    3. The vulnerability is genuinely cross-platform AND choosing an OS-specific
       sub-technique would mislead downstream consumers.

  If ANY of the following signals appear in CVE data (description, CVSS vector,
  CPEs, references, CWE), you MUST emit at least 1 subtechnique — do your own
  reasoning, do not default to empty:
    - Specific shell/interpreter/tool name: bash, sh, cmd.exe, PowerShell,
      Python, Perl, Ruby, JavaScript, VBScript, AppleScript, PHP, SSH, RDP,
      SMB, FTP, LDAP, Kerberos, NTLM, WinRM, sql, mysql, postgres, oracle,
      docker, kubectl, aws, azure-cli, gcloud, etc.
    - Specific OS/service: Windows Service, IIS, Apache, nginx, Tomcat,
      Jenkins, WebLogic, JBoss, SharePoint, Exchange, Active Directory, etc.
    - File type / payload hint: .ps1, .sh, .bat, .vbs, .hta, .jar, .war,
      .php, .aspx, .jsp, .elf, .dll, .so, .dylib, etc.
    - Execution primitive: command injection, shell command, script execution,
      DLL injection, process injection, lateral movement via [protocol],
      authentication via [mechanism], etc.
    - CVE category keyword: RCE + Windows, RCE + Linux, RCE + WordPress,
      RCE + Joomla, RCE + Jenkins, privilege escalation + Windows kernel,
      auth bypass + SSO/SAML/OAuth, etc.

  When you emit a subtechnique, you MUST justify it in `mapping_reasons` with
  an explicit tie to the CVE signal (e.g. "T1059.004 selected because CVE
  describes bash command injection in a Linux web application"). Empty
  `subtechniques: []` WITHOUT `mapping_reasons` explaining why no signal was
  found is INVALID and will be rejected by the coverage engine.

  Anti-hallucination guard: only emit subtechniques you can tie to a concrete
  signal above. If genuinely no signal exists (rare), emit `subtechniques: []`
  AND add a `mapping_reason` stating "No specific tool/interpreter/protocol
  signal in description or references; parent technique sufficient for
  threat modeling."
- EVASIVE INDICATORS ENFORCEMENT (CRITICAL):
  Do NOT default to "none" for evasive_indicators. The field MUST NOT BE EMPTY unless the CVE
  is a pure hardware/physical bug with no software telemetry path. For all software CVEs, you
  MUST populate evasive_indicators with at least 1-3 concrete evasion techniques that a real
  attacker would use to bypass detection.
  Active analysis examples by vulnerability class:
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

- INBOUND INTRUSION DISTINCTION (CRITICAL):
  Misclassifying the attack surface is a top-1 source of false TTPs. Follow this rule:
    - Use T1190 (Exploit Public-Facing Application) ONLY for:
        * Web applications, web servers, REST/GraphQL APIs
        * Mail servers (SMTP), VPN portals, web admin consoles
        * Any HTTP/HTTPS-reachable endpoint that parses user input
    - Use T1210 (Exploitation of Remote Services) for:
        * Core infrastructure/administrative protocols: SMB, RDP, SSH, VNC, RPC, NetBIOS,
          FTP, Telnet, Netcat
        * Pre-auth wormable exploits (BlueKeep/RDP, EternalBlue/SMB, SMBGhost/SMBv3,
          Conficker/SMB, WannaCry/SMB)
    - Use T1133 (External Remote Services) ONLY for:
        * Legitimate remote access services (VPN gateway, Citrix, TeamViewer) where the
          vulnerability is in the access control layer, NOT in the protocol implementation
    - Decision tree for AV:N + PR:N + wormable:
        * What service is on the wire? → SMB/RDP/SSH/etc → T1210
        * Is it a web/HTTP endpoint? → T1190
        * Is it a VPN/auth gateway? → T1133

- FALLBACK MAPPING FOR CONFIRMED PRE-AUTH NETWORK RCE (CRITICAL):
  If a vulnerability is confirmed to enable Unauthenticated Remote Code Execution via a
  core network protocol (i.e., CVSS:3.1 with AV:N AND PR:N AND impact C:H), and the CVE
  description mentions a specific protocol/service (SMB, RDP, RPC, SSH, FTP, etc.), you
  MUST at minimum emit these (even if you have additional ones):
    - Tactics: ["TA0001", "TA0004", "TA0008"]
        * TA0001 = Initial Access (network entry)
        * TA0004 = Privilege Escalation (SYSTEM/kernel access typical of these bugs)
        * TA0008 = Lateral Movement (wormable nature)
    - Techniques: ["T1210"] (Exploitation of Remote Services)
                  + ["T1068"] if execution yields kernel/SYSTEM access
  NEVER leave tactics, techniques, OR mapping_reasons empty for any confirmed pre-auth
  network-exploitable vulnerability. Empty arrays will trigger system rejection and waste
  compute cycles. If you cannot determine the right ID, emit the conservative baseline
  above with mapping_reasons explaining your choice — the system will accept it.

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

