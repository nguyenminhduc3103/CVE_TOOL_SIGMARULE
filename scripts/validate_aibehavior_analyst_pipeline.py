import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.usecases.step_1_triage.orchestrator import TriageOrchestrator


async def validate(cve_id: str):
    print(f"=== CHẠY KIỂM ĐỊNH AI BEHAVIOR CHO: {cve_id} ===")

    # 1. Chạy pipeline thực tế (Triage + AI Behavior Analysis + Validation)
    print(f"[*] Đang chạy TriageOrchestrator để gọi phân tích {cve_id}...")
    orchestrator = TriageOrchestrator()
    enriched = await orchestrator.orchestrate(cve_id)

    tech_analysis = enriched.analysis
    attack_mapping = enriched.attack

    if not tech_analysis and not attack_mapping:
        print("[-] Phân tích thất bại hoặc không có kết quả TechnicalAnalysis/AttackMapping.")
        print(f"    Triage decision: {enriched.triage.decision} — {enriched.triage.decision_reason}")
        sys.exit(1)

    print("[+] Đã nhận kết quả phân tích. Bắt đầu đối chiếu Ground Truth...")

    print("\n[MÃ JSON KẾT QUẢ]")
    if tech_analysis:
        print(tech_analysis.model_dump_json(indent=2))
    if attack_mapping:
        print(attack_mapping.model_dump_json(indent=2))
    print("-" * 50)

    # 2. Lấy kết quả Validation từ pipeline (đã được orchestrator chạy sẵn)
    result = enriched.validation
    if result is None:
        print("[-] Validation stage không chạy được hoặc không có kết quả.")
        sys.exit(1)

    # 3. In kết quả Validation
    print("\n" + "="*50)
    print(f" BÁO CÁO VALIDATION: {cve_id}")
    print("="*50)

    print("\n[THÔNG TIN PIPELINE]")
    print(f"Triage Decision:         {enriched.triage.decision}")
    print(f"In KEV:                  {enriched.triage.in_kev}")
    print(f"Public PoC:              {enriched.triage.public_poc}")
    print(f"EPSS Percentile:         {f'{enriched.triage.epss_percentile*100:.3f}%' if enriched.triage.epss_percentile is not None else 'N/A'}")
    print(f"Pipeline Duration:       {enriched.metadata.enrichment_duration_ms} ms")

    print("\n[ĐÁNH GIÁ CHUNG]")
    print(f"Verdict (Kết luận):      {result.verdict}")
    print(f"Lý do (Reason):          {result.verdict_reason}")
    if result.overall_confidence_score is not None:
        print(f"Confidence Score:        {result.overall_confidence_score * 100:.2f}%")

    print("\n[NGUỒN GROUND TRUTH]")
    print(f"Nguồn tham chiếu:        {result.ground_truth_source}")
    print(f"Chất lượng Ground Truth: {result.ground_truth_quality}")
    print(f"Mã CWE tham chiếu:       {enriched.core.cwe_ids}")

    # Determine if AI was actually used based on metadata
    is_ai = bool(getattr(enriched.metadata, "ai_steps_used", []))
    engine_name = "AI" if is_ai else "Rule-based"

    print("\n[ĐỐI CHIẾU KỸ THUẬT ATT&CK (TECHNIQUES)]")
    if result.technique_match_rate is not None:
        print(f"Tỷ lệ khớp (Match Rate): {result.technique_match_rate * 100:.0f}%")
    else:
        print(f"Tỷ lệ khớp (Match Rate): N/A (Không có Ground Truth)")
    print(f"Kỹ thuật {engine_name} đoán ĐÚNG:   {result.matched_techniques}")
    print(f"Kỹ thuật {engine_name} BỎ SÓT:      {result.missing_techniques}")
    print(f"Kỹ thuật {engine_name} DƯ (Extra):  {result.extra_techniques}")

    print("\n[ĐỐI CHIẾU HÀNH VI (BEHAVIORS) & FALSE POSITIVE]")
    ai_behaviors = (tech_analysis.mandatory_behaviors or []) if tech_analysis else []
    if len(ai_behaviors) > 5:
        print(f"Hành vi {engine_name} sinh ra:      {ai_behaviors[:5]}... (+{len(ai_behaviors) - 5} hành vi nữa)")
    else:
        print(f"Hành vi {engine_name} sinh ra:      {ai_behaviors}")

    if result.behavior_match_rate is not None:
        print(f"Tỷ lệ khớp Hành vi:      {result.behavior_match_rate * 100:.0f}%")
    else:
        print(f"Tỷ lệ khớp Hành vi:      N/A (Ground Truth không có behavior)")
    print(f"Các hành vi khớp CAPEC:  {result.matched_behaviors}")
    print(f"Mức rủi ro False Positive: {result.false_positive_risk}")
    if result.whitelist_hits:
        print(f"Cảnh báo Whitelist Hits: {result.whitelist_hits} ({engine_name} đoán nhầm vào tiến trình hệ thống!)")
    else:
        print("Cảnh báo Whitelist Hits: Không phát hiện (An toàn)")

    print("\n" + "="*50)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    asyncio.run(validate(target))
