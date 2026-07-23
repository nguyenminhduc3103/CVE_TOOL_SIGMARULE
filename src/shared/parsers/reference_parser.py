from urllib.parse import urlparse

def classify_reference(url: str, tags: list[str] | None = None) -> dict:
    """Phân loại và làm giàu thông tin cho một liên kết tham chiếu (URL) của CVE.

    Phân chia thành các nhóm chính: Exploit/PoC, Vendor Advisory, Third-Party Advisory, v.v.
    """
    if not url:
        return {
            "url": "",
            "category": "Unknown",
            "source": "Unknown",
            "is_exploit": False
        }

    url_lower = url.lower()
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # Loại bỏ phần 'www.' để so khớp tên miền chính xác
    if domain.startswith("www."):
        domain = domain[4:]

    category = "General Reference (Tài liệu chung)"
    source = domain.capitalize()
    is_exploit = False

    # 1. Các nguồn Exploit / PoC nổi tiếng
    exploit_domains = {
        "exploit-db.com": "Exploit Database",
        "packetstormsecurity.com": "Packet Storm Security",
        "0day.today": "0day Today",
        "cxsecurity.com": "CXSecurity",
        "seclists.org": "Security Mailing List",
        "securityfocus.com": "SecurityFocus",
        "metasploit.com": "Metasploit",
        "vulncode-db.com": "Vulncode-DB",
    }

    # 2. Các nguồn Vendor / Advisory / Patch chính thức
    vendor_domains = {
        "microsoft.com": "Microsoft MSRC",
        "msrc.microsoft.com": "Microsoft MSRC",
        "portal.msrc.microsoft.com": "Microsoft MSRC",
        "support.microsoft.com": "Microsoft Support",
        "oracle.com": "Oracle Security Alerts",
        "redhat.com": "Red Hat Security",
        "cisco.com": "Cisco Security Advisory",
        "apache.org": "Apache Software Foundation",
        "gentoo.org": "Gentoo Security",
        "debian.org": "Debian Security",
        "ubuntu.com": "Ubuntu Security Advisory",
        "vmware.com": "VMware Security Advisory",
        "apple.com": "Apple Security Updates",
        "google.com": "Google Security",
        "github.com/advisories": "GitHub Security Advisory",
        "gitlab.com/advisories": "GitLab Security Advisory"
    }

    # 3. Các hãng Bảo mật bên thứ ba (Third-Party Security Advisory)
    third_party_domains = {
        "tenable.com": "Tenable Security",
        "rapid7.com": "Rapid7 ZDI",
        "qualys.com": "Qualys",
        "trendmicro.com": "Trend Micro",
        "zerodayinitiative.com": "Zero Day Initiative (ZDI)",
        "fortiguard.com": "Fortiguard Labs",
        "snyk.io": "Snyk Advisor",
        "veracode.com": "Veracode",
        "mcafee.com": "McAfee Security",
        "talosintelligence.com": "Cisco Talos",
        "checkpoint.com": "Check Point Security",
        "kaspersky.com": "Kaspersky Labs",
        "f-secure.com": "WithSecure (F-Secure)",
        "security-help.cz": "Cybersecurity Help",
        "vicarius.io": "Vicarius vsociety"
    }

    # 4. Cơ sở dữ liệu Quốc gia / Chính phủ
    gov_domains = {
        "nvd.nist.gov": "NIST NVD",
        "cisa.gov": "CISA (US-CERT)",
        "kb.cert.org": "CERT Coordination Center",
        "jvn.jp": "Japan Vulnerability Notes",
        "cnvd.org.cn": "China National Vulnerability Database",
        "us-cert.gov": "US-CERT"
    }

    # Thực hiện khớp dữ liệu
    if domain in exploit_domains:
        category = "Exploit / PoC (Mã khai thác)"
        source = exploit_domains[domain]
        is_exploit = True
    elif any(d in url_lower for d in vendor_domains):
        matched_pattern = next(d for d in vendor_domains if d in url_lower)
        category = "Vendor Advisory (Cảnh báo từ hãng)"
        source = vendor_domains[matched_pattern]
    elif any(d in url_lower for d in third_party_domains):
        matched_pattern = next(d for d in third_party_domains if d in url_lower)
        category = "Third-Party Advisory (Cảnh báo từ bên thứ 3)"
        source = third_party_domains[matched_pattern]
    elif any(d in url_lower for d in gov_domains):
        matched_pattern = next(d for d in gov_domains if d in url_lower)
        category = "National Database (Cơ sở dữ liệu quốc gia)"
        source = gov_domains[matched_pattern]
    # Trường hợp đặc biệt: github.com hoặc gitlab.com chứa mã PoC/khai thác
    elif "github.com" in domain or "gitlab.com" in domain:
        source = "GitHub" if "github.com" in domain else "GitLab"
        if any(kw in url_lower for kw in ["poc", "exploit", "payload", "rce", "bypass", "writeup", "attack"]):
            category = "Exploit / PoC (Mã khai thác)"
            is_exploit = True
        elif "/security/advisories" in url_lower:
            category = "Vendor Advisory (Cảnh báo từ hãng)"
        else:
            category = "Code Repository (Kho lưu trữ mã nguồn)"
    # Các blog viết về kỹ thuật
    elif "blog" in domain or "medium.com" in domain or "dev.to" in domain or "writeup" in url_lower:
        category = "Technical Write-up / Blog (Phân tích kỹ thuật)"
        source = domain.split(".")[0].capitalize() if "blog" in domain else domain.capitalize()

    # Ghi đè phân loại bằng NVD tags nếu có (ưu tiên tuyệt đối độ chính xác từ NVD Analyst)
    if tags:
        tags_lower = [t.lower() for t in tags]
        
        # 1. Xác định cờ is_exploit dựa trên tags trước hết
        is_exploit = "exploit" in tags_lower

        # 2. Phân loại nhóm category dựa trên tags
        if "exploit" in tags_lower:
            category = "Exploit / PoC (Mã khai thác)"
        elif "patch" in tags_lower:
            category = "Vendor Advisory (Cảnh báo từ hãng)"
            if not source or source == domain.capitalize():
                source = "Vendor Patch"
        elif "vendor advisory" in tags_lower:
            category = "Vendor Advisory (Cảnh báo từ hãng)"
            if not source or source == domain.capitalize():
                source = "Vendor Advisory"
        elif "third party advisory" in tags_lower:
            category = "Third-Party Advisory (Cảnh báo từ bên thứ 3)"
        elif "mitigation" in tags_lower:
            category = "Mitigation (Biện pháp giảm thiểu)"
        elif "technical description" in tags_lower:
            category = "Technical Description (Mô tả kỹ thuật)"
        elif "vdb entry" in tags_lower:
            category = "VDB Entry (Cơ sở dữ liệu lỗ hổng)"
        elif "mailing list" in tags_lower:
            category = "Mailing List (Danh sách thư điện tử)"
        elif "broken link" in tags_lower:
            category = "Broken Link (Liên kết hỏng)"
        elif "release notes" in tags_lower:
            category = "Release Notes (Thông tin phát hành)"
        elif "issue tracking" in tags_lower:
            category = "Issue Tracking (Theo dõi lỗi)"
        elif "permissions required" in tags_lower:
            category = "Permissions Required (Yêu cầu quyền)"
        else:
            category = "General Reference (Tài liệu chung)"

    return {
        "url": url,
        "category": category,
        "source": source,
        "is_exploit": is_exploit
    }


def extract_urls(references: list) -> list:
    """Phân tích và làm giàu danh sách liên kết tham chiếu thành danh sách đối tượng có cấu trúc phân loại."""
    if not references:
        return []
    results = []
    for item in references:
        item_str = str(item)
        if "|" in item_str:
            parts = item_str.split("|", 1)
            url_str = parts[0]
            tags = [t.strip() for t in parts[1].split(",") if t.strip()]
        else:
            url_str = item_str
            tags = []

        results.append(classify_reference(url_str, tags))
    return results


def resolve_poc_context(references: list[str] | None, poc_stage_raw: dict | None) -> tuple[bool, list[str]]:
    """Gộp PoC từ cả references (NVD) và cơ sở dữ liệu (nomi-sec)."""
    public_poc = False
    poc_references = []
    
    # 1. Quét tìm PoC trong các references (NVD)
    if references:
        try:
            enriched_refs = extract_urls(references)
            for ref in enriched_refs:
                if ref.get("is_exploit"):
                    public_poc = True
                    poc_references.append(ref.get("url"))
        except Exception:
            pass
                
    # 2. Trộn thêm PoC từ nomi-sec/PoC-in-GitHub
    if poc_stage_raw and isinstance(poc_stage_raw, dict):
        _poc_refs = poc_stage_raw.get("poc_references")
        if _poc_refs:
            public_poc = True
            existing_set = set(poc_references)
            for ref in _poc_refs:
                if ref not in existing_set:
                    poc_references.append(ref)
                    
    return public_poc, poc_references
