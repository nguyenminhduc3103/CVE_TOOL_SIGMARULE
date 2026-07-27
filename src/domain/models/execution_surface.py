"""ExecutionSurface + DeliveryVector enums — canonical facts cho ATT&CK mapping.

Van de goc: AI doc CVSS AV:N + PR:N → auto-chon T1190 (Exploit Public-Facing
Application) cho MOI CVE, ke ca CVE client-side nhu MSHTML (CVE-2021-40444).
Nguyen nhan: CVSS AV:N co the gan cho ca client-side (email attachment) lan
server-side (HTTP endpoint). AI thieu canonical fact de biet code chay o
DAU post-exploitation.

Giai phap: 2 enum dinh nghia FACTS (khong phai ATT&CK). Phase 1 AI classify
CVE vao 1 trong cac value, Phase 2 AI su dung value do lam anchor de chon
ATT&CK technique chinh xac:
  - execution_surface=client_side → T1204 (User Execution) / T1566 (Phishing)
  - execution_surface=server_side → T1190 / T1210
  - execution_surface=local        → T1068 / T1548
  - execution_surface=multi_hop    → T1195 (Supply Chain) / T1611 (Container)

API contract: enum string-compatible (str, Enum) → Pydantic / JSON serialize
thang, khong can custom encoder.
"""
from __future__ import annotations

from enum import Enum


class ExecutionSurface(str, Enum):
    """WHERE code chay post-exploitation (FACTS, khong phai CVSS classification).

    Classification dua tren co che khai thac thuc te (mo ta CVE, CWE, PoC),
    KHONG dua tren CVSS vector. CVSS AV:N co the la:
      - client-side (email attachment qua mang)
      - server-side (HTTP endpoint truc tiep)

    Vi vay phai phan biet bang noi dung CVE, khong tin CVSS.
    """

    CLIENT_SIDE = "client_side"
    """Code chay tren may victim khi user tuong tac.
    Vi du: MSHTML ActiveX trong .docx, Office macro, PDF reader exploit,
    browser drive-by (Chrome CVE), media parser bug. Dac trung:
    - Can user mo file / click link
    - Payload den qua email, web download, hoac physical media
    - CVSS thuong UI:R (Required), UI:N neu auto-launched
    """

    SERVER_SIDE = "server_side"
    """Code chay tren may chu dich vu dang public/accessible.
    Vi du: Apache/IIS/nginx RCE, web framework deserialization (Log4Shell,
    Spring4Shell), database RCE, REST API auth bypass. Dac trung:
    - Tan cong truc tiep qua network protocol (HTTP, SMB, RDP)
    - CVSS AV:N + UI:N (khong can user tuong tac)
    - Tan cong vao may chu, khong phai may tram
    """

    LOCAL = "local"
    """Code chay local tren may, khong qua network. Vi du: kernel driver
    exploit, local privilege escalation, file parser local bug. Dac trung:
    - CVSS AV:L (Local), AV:P (Physical)
    - Can attacker co shell truoc do (post-exploitation step)
    - Memory corruption trong kernel/driver
    """

    MULTI_HOP = "multi_hop"
    """Khai thac lien hop nhieu surface (supply chain, container escape).
    Vi du: XZ Utils backdoor (supply chain), runc container escape (escape
    to host), CI/CD pipeline exploit. Dac trung:
    - Qua nhieu layer (build artifact → deployment → runtime)
    - Thuong CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
    - CVSS AV:N nhung primitive la injection vao build/deploy pipeline
    """

    UNKNOWN = "unknown"
    """Khong du thong tin de classify. Caller nen fallback rule-based classifier."""


class DeliveryVector(str, Enum):
    """Cach attacker dua payload den victim.

    Phase 1 AI se chon 1 trong cac value nay dua tren mo ta CVE. Phase 2
    su dung ket hop voi execution_surface de chon ATT&CK technique chinh xac.
    """

    EMAIL_ATTACHMENT = "email_attachment"
    """Payload la file dinh kem email. Vi du: CVE-2021-40444 (.docx + ActiveX),
    CVE-2017-11882 (.doc + Equation Editor). Dac trung: delivery_vector
    email_attachment + execution_surface client_side → T1566.001 + T1204.002.
    """

    EMAIL_LINK = "email_link"
    """Payload la URL trong email body. Vi du: phishing link → credential
    harvesting, OAuth consent phishing. → T1566.002 (Spearphishing Link).
    """

    WEB_DOWNLOAD = "web_download"
    """Payload download tu website (drive-by, malicious ad). Vi du: browser
    exploit, fake software update. → T1189 (Drive-by Compromise).
    """

    NETWORK_PROTOCOL = "network_protocol"
    """Tan cong truc tiep qua protocol (HTTP, SMB, RDP, SSH, FTP, DNS).
    Vi du: Apache RCE qua HTTP request, SMBGhost qua SMB, EternalBlue qua SMB.
    → T1190 (HTTP) hoac T1210 (SMB/RDP/SSH).
    """

    PHYSICAL = "physical"
    """Can physical access (USB, console). Vi du: BadUSB, hardware implant.
    → T1200 (Hardware Additions) + AV:P CVSS.
    """

    LOCAL_EXECUTION = "local_execution"
    """Da co shell local (post-exploitation step). Vi du: privesc exploit,
    lateral movement tool. → T1068 / T1548 / T1078.002.
    """

    UNKNOWN = "unknown"
    """Khong ro vector. Caller nen fallback rule-based classifier."""