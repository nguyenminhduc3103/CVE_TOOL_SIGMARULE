import json
import faiss
from sentence_transformers import SentenceTransformer

# 1. Duong dan toi 2 file cua ban
FILE_MITRE = ".cache/ontology/ATT_CK_TTPs/TTPs_mapping.json"
FILE_BEHAVIOR = ".cache/ontology/CAPEC_BEHAVIORs/mandatory_behavior_ontology.json"
FILE_OUTPUT = "final_mapped_results.json" # File xuat ra

print("Dang tai mo hinh AI...")
model = SentenceTransformer('all-mpnet-base-v2')

# 2. Doc du lieu
print("Dang doc du lieu tu 2 file...")
with open(FILE_MITRE, 'r', encoding='utf-8') as f:
    mitre_data = json.load(f)

with open(FILE_BEHAVIOR, 'r', encoding='utf-8') as f:
    behavior_data = json.load(f)
    entries = behavior_data.get("entries", [])

# 3. Chuyen File 1 (MITRE) thanh Database AI
print("Dang nap ma MITRE vao Vector Database...")
mitre_ids = list(mitre_data.keys())
mitre_texts = []

for t_id, info in mitre_data.items():
    # Gop Ten va Mo ta de AI hieu sau
    name = info.get("name", "")
    desc = info.get("description", "")
    mitre_texts.append(f"{name}. {desc}")

mitre_embeddings = model.encode(mitre_texts, show_progress_bar=True)
index = faiss.IndexFlatL2(mitre_embeddings.shape[1])
faiss.normalize_L2(mitre_embeddings)
index.add(mitre_embeddings)

# 4. Tim kiem va Map File 2 (Behavior) vao Database
print("Dang tien hanh ghep doi (Mapping)...")
behavior_queries = []
for item in entries:
    prim = item.get("primitive", "").replace("_", " ")
    desc = item.get("description", "")
    behavior_queries.append(f"{prim}: {desc}")

query_embeddings = model.encode(behavior_queries)
faiss.normalize_L2(query_embeddings)

# ĐÃ ĐỔI THÀNH k=3 ĐỂ LẤY TOP 3
distances, indices = index.search(query_embeddings, k=3)

# 5. Xuat ket qua
THRESHOLD = 0.40
final_results = {}

for i, item in enumerate(entries):
    primitive_key = item.get("primitive")
    
    # Tạo mảng để lưu danh sách các kết quả vượt qua Threshold
    top_matches = []
    
    # Duyệt qua 3 kết quả vừa tìm được
    for j in range(3):
        best_match_idx = indices[i][j]
        score = float(1 - (distances[i][j] / 2))
        matched_id = mitre_ids[best_match_idx]
        
        # Nếu điểm số cao hơn hoặc bằng ngưỡng thì đưa vào danh sách
        if score >= THRESHOLD:
            top_matches.append({
                "mapped_t_code": matched_id,
                "t_name": mitre_data[matched_id]["name"],
                "tactics": mitre_data[matched_id]["tactics"],
                "confidence": round(score, 2)
            })
    
    # Ghi vào JSON (Nếu có ít nhất 1 kết quả đạt yêu cầu)
    if len(top_matches) > 0:
        final_results[primitive_key] = {
            "status": "SUCCESS",
            "matches": top_matches # Xuất mảng chứa Top kết quả
        }
    else:
        final_results[primitive_key] = {
            "status": "LOW_CONFIDENCE",
            "matches": [] # Rỗng nếu không có mã nào qua ngưỡng
        }

with open(FILE_OUTPUT, 'w', encoding='utf-8') as f:
    json.dump(final_results, f, ensure_ascii=False, indent=2)

print(f"Xong! Mo file '{FILE_OUTPUT}' de xem AI da map ra sao nhe.")