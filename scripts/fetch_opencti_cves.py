from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx

# Thêm thư mục gốc của dự án vào Python Path để nhận diện các module
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.config import settings
from app.core.logging import get_logger
from app.shared.providers.opencti import OpenCTIProvider

logger = get_logger(__name__)


def mask_string(val: str | None) -> str:
    """Ẩn các chuỗi nhạy cảm (như cookie hay mật khẩu) khi ghi log hoặc hiển thị console."""
    if not val:
        return "None"
    if len(val) <= 12:
        return "*" * len(val)
    return f"{val[:6]}...{val[-6:]}"


def wait_for_user(step_description: str) -> None:
    """Yêu cầu người dùng nhấn phím Enter để tiếp tục thực hiện bước tiếp theo."""
    print(f"\n👉 [BẤM ENTER] để thực hiện: {step_description}")
    input()


async def main() -> None:
    """Hàm chạy chính của công cụ thu thập và chuẩn hóa dữ liệu CVE từ OpenCTI."""
    print("==========================================================")
    print(" HỆ THỐNG PHÂN TÍCH CVE & XÂY DỰNG SIGMA RULE - OPENCTI")
    print("==========================================================\n")

    # Kiểm tra cấu hình kết nối từ file cấu hình/env
    print("----------------------------------------------------------")
    print("KIỂM TRA CẤU HÌNH KẾT NỐI")
    print("----------------------------------------------------------")
    print(f"  - OpenCTI URL:               {settings.opencti_url}")
    print(f"  - TAXII Collection ID:       {settings.opencti_taxii_collection_id or 'CHƯA CẤU HÌNH'}")
    print(f"  - WAF Session Cookie:        {mask_string(settings.opencti_cookie)}")
    print(f"  - OpenCTI Bearer Token:      {mask_string(settings.opencti_token)}")
    print(f"  - Basic Auth Username:       {settings.opencti_username or 'None'}")
    print(f"  - Basic Auth Password:       {mask_string(settings.opencti_password)}")
    print()

    # Kiểm tra sơ bộ trước khi chạy (Pre-flight check)
    if not settings.opencti_taxii_collection_id:
        print("[!] LỖI: OPENCTI_TAXII_COLLECTION_ID chưa được thiết lập trong file .env!")
        print("    Vui lòng cấu hình đầy đủ thông tin trước khi tiếp tục.")
        sys.exit(1)

    print("✅ Cấu hình hợp lệ.")

    # Khởi tạo OpenCTI Client 
    wait_for_user("Bắt đầu quá trình thu thập và chuẩn hóa CVE từ OpenCTI")
    print("\n[2] Khởi tạo OpenCTI Threat Intelligence Provider...")
    provider = OpenCTIProvider()
    print("    -> Khởi tạo thành công.")
 
    # Kết nối TAXII Collection và tải dữ liệu thô tự động
    print("\n[3] Kết nối hệ thống và tải dữ liệu từ TAXII Collection...")
    
    raw_bundle = None
    try:
        raw_bundle = await provider.client.fetch_raw_collection(limit=5)
        print(f"    -> Đã kết nối và tải thành công STIX Bundle chứa {len(raw_bundle.get('objects', []))} đối tượng.")
        print("    [!] Dữ liệu thô tải về (STIX JSON thô):")
        objects_preview = raw_bundle.get("objects", [])[:3]
        for obj in objects_preview:
            print(f"       + ID thô: {obj.get('id')} | Loại: {obj.get('type')} | Tên: {obj.get('name')}")
        if len(raw_bundle.get("objects", [])) > 3:
            print(f"       + ... và {len(raw_bundle.get('objects', [])) - 3} đối tượng khác.")
    except httpx.HTTPStatusError as exc:
        print(f"\n[!] LỖI HTTP KHI KẾT NỐI OPENCTI (Mã trạng thái: {exc.response.status_code}):")
        print(f"    Chi tiết: {exc}")
        print()
        if exc.response.status_code == 468:
            print("💡 PHÁT HIỆN YÊU CẦU XÁC THỰC NGƯỜI DÙNG (SafeLine WAF 468):")
            print("  SafeLine WAF đang yêu cầu xác thực người dùng (Human Verification / CAPTCHA).")
        else:
            print("💡 HƯỚNG DẪN KHI BỊ CHẶN WAF (403/401):")
            print("  Vui lòng kiểm tra xem Cookie trong file '.env' có bị hết hạn hay sai định dạng không.")
        print()
        sys.exit(1)
    except Exception as exc:
        print(f"\n[!] LỖI KẾT NỐI HOẶC TẢI DỮ LIỆU TỪ OPENCTI:")
        print(f"    Chi tiết: {exc}")
        print()
        sys.exit(1)
 
    # Chuẩn hóa dữ liệu CVE tự động
    print("\n[4] Tiến hành chuẩn hóa dữ liệu bằng OpenCTIParser...")
    cves = provider.parser.parse_bundle(raw_bundle)[:5]
    print(f"    -> Đã chuẩn hóa thành công {len(cves)} dữ liệu CVE:")
    for idx, cve in enumerate(cves, 1):
        print(f"  --------------------------------------------------------")
        print(f"  CVE #{idx}: {cve.cve_id}")
        print(f"  --------------------------------------------------------")
        print(f"    - Published At: {cve.published_at or 'N/A'}")
        print(f"    - Modified At:  {cve.modified_at or 'N/A'}")
    print(f"  --------------------------------------------------------")
 
    # Lưu dữ liệu vào biến cục bộ tự động
    print(f"\n[5] Lưu trữ dữ liệu vào biến cục bộ...")
    cves_list = cves  # Lưu danh sách CoreCVEData vào biến cục bộ
    print(f"    -> Đã lưu trữ thành công {len(cves_list)} đối tượng CoreCVEData vào biến cục bộ 'cves_list'.")
    print("       Biến này sẵn sàng để làm đầu vào cho bước tiếp theo (Làm giàu dữ liệu).")

    print("\n==========================================================")
    print(" HOÀN THÀNH QUÁ TRÌNH THU THẬP TỪNG BƯỚC")
    print("==========================================================")


if __name__ == "__main__":
    # Đảm bảo Windows xử lý vòng lặp bất đồng bộ và bảng mã UTF-8 chính xác
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(main())
