import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.shared.models.attack import TechnicalAnalysis, AttackMapping
from app.steps.step_2_tech_analysis.validation.validate_stage import run_validate_stage

async def test_with_json(cve_id: str, json_file: str):
    print(f"=== TEST VALIDATION BẰNG JSON CHO: {cve_id} ===")
    
    # 1. Đọc file JSON giả lập AI
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] Lỗi đọc file JSON: {e}")
        return

    # 2. Ép kiểu dữ liệu JSON vào Pydantic Models (Mô phỏng y hệt AI)
    try:
        tech_analysis = TechnicalAnalysis(**data.get("technical_analysis", {}))
        attack_mapping = AttackMapping(**data.get("attack_mapping", {}))
    except Exception as e:
        print(f"[-] Lỗi JSON sai định dạng Pydantic: {e}")
        return

    print(f"[+] Đã load thành công dữ liệu AI từ {json_file}")
    print("[*] Đang đẩy vào Validation Stage để chấm điểm...")
    
    # 3. Đẩy vào Validator (Giả lập NVD cung cấp cwe_ids cho cve_id này)
    # Tự động lấy CWE-502 nếu là Log4Shell, hoặc mảng rỗng để tự tra cứu.
    cwe_ids = ["CWE-502"] if cve_id == "CVE-2021-44228" else []
    
    result = await run_validate_stage(
        tech_analysis=tech_analysis,
        attack_mapping=attack_mapping,
        cve_id=cve_id,
        cwe_ids=cwe_ids,
        cvss_vector=None,
        description=None
    )
    
    # 4. In kết quả Validation (Tương tự script thật)
    print("\n" + "="*50)
    print(f" BÁO CÁO VALIDATION: {cve_id} (DÙNG JSON GIẢ LẬP)")
    print("="*50)
    
    print("\n[ĐÁNH GIÁ CHUNG]")
    print(f"Verdict (Kết luận):      {result.verdict}")
    print(f"Lý do (Reason):          {result.verdict_reason}")
    if result.overall_confidence_score is not None:
        print(f"Confidence Score:        {result.overall_confidence_score * 100:.2f}%")
        
    print("\n[NGUỒN GROUND TRUTH]")
    print(f"Nguồn tham chiếu:        {result.ground_truth_source}")
    print(f"Chất lượng Ground Truth: {result.ground_truth_quality}")
    print(f"Mã CWE tham chiếu:       {cwe_ids if cwe_ids else 'Tự động tra cứu'}")
    
    print("\n[ĐỐI CHIẾU KỸ THUẬT ATT&CK (TECHNIQUES)]")
    if result.technique_match_rate is not None:
        print(f"Tỷ lệ khớp (Match Rate): {result.technique_match_rate * 100:.0f}%")
    else:
        print(f"Tỷ lệ khớp (Match Rate): N/A (Không có Ground Truth)")
    print(f"Kỹ thuật AI đoán ĐÚNG:   {result.matched_techniques}")
    print(f"Kỹ thuật AI BỎ SÓT:      {result.missing_techniques}")
    print(f"Kỹ thuật AI DƯ (Extra):  {result.extra_techniques}")
    
    print("\n[ĐỐI CHIẾU HÀNH VI (BEHAVIORS) & FALSE POSITIVE]")
    ai_behaviors = tech_analysis.mandatory_behaviors or []
    print(f"Hành vi AI sinh ra:      {ai_behaviors}")
        
    if result.behavior_match_rate is not None:
        print(f"Tỷ lệ khớp Hành vi:      {result.behavior_match_rate * 100:.0f}%")
    else:
        print(f"Tỷ lệ khớp Hành vi:      N/A (Ground Truth không có behavior)")
    print(f"Các hành vi khớp CAPEC:  {result.matched_behaviors}")
    print(f"Mức rủi ro False Positive: {result.false_positive_risk}")
    if result.whitelist_hits:
        print(f"Cảnh báo Whitelist Hits: {result.whitelist_hits} (AI đoán nhầm vào tiến trình hệ thống!)")
    else:
        print("Cảnh báo Whitelist Hits: Không phát hiện (An toàn)")
        
    print("\n" + "="*50)

if __name__ == "__main__":
    cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    json_path = sys.argv[2] if len(sys.argv) > 2 else "scripts/mock_ai_output.json"
    asyncio.run(test_with_json(cve, json_path))
