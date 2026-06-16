from __future__ import annotations

import asyncio
from typing import Any

import httpx

from app.shared.clients.base import BaseHTTPClient
from app.core.logging import get_logger

# Bỏ qua các cảnh báo xác thực chứng chỉ SSL cho các chứng chỉ tự ký nội bộ
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


class OpenCTIHTTPClient(BaseHTTPClient):
    """Client HTTP kết nối với API TAXII 2.1 của OpenCTI."""

    def __init__(
        self,
        base_url: str,
        cookie: str | None = None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 15.0,
        retries: int = 3,
        backoff_seconds: float = 0.5,
    ) -> None:
        """Khởi tạo OpenCTI HTTP Client."""
        super().__init__(base_url=base_url, timeout=int(timeout))
        self.cookie = cookie
        self.token = token
        self.username = username
        self.password = password
        self.retries = retries
        self.backoff_seconds = backoff_seconds
        self.logger = get_logger(__name__)

        self._client: httpx.AsyncClient | None = None


    # Kết nối OpenCTI
    def _get_client(self) -> httpx.AsyncClient:
        if not self._client:
            headers = {
                "Accept": "application/taxii+json;version=2.1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9,vi;q=0.8",
                "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
            }
            cookies = None
            if self.cookie:
                try:
                    from http.cookies import SimpleCookie
                    cookie_parser = SimpleCookie()
                    cookie_parser.load(self.cookie)
                    cookies = {k: v.value for k, v in cookie_parser.items()}
                    self.logger.info("[OpenCTI] Đã phân tích và tải session cookie thành công.")
                except Exception as exc:
                    self.logger.warning("[OpenCTI] Thất bại khi phân tích chuỗi cookie", error=str(exc))
                    headers["Cookie"] = self.cookie

            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
                self.logger.info("[OpenCTI] Đã cấu hình Bearer Token để xác thực.")

            auth = None
            if self.username and self.password and not self.cookie and not self.token:
                auth = httpx.BasicAuth(self.username, self.password)
                self.logger.info("[OpenCTI] Sử dụng xác thực HTTP Basic.")

            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                headers=headers,
                cookies=cookies,
                auth=auth,
                verify=False,
            )
        return self._client


    # Request xử lý lỗi và retry tự động 
    async def get(self, endpoint: str, **kwargs) -> httpx.Response:
        """Ghi đè phương thức get để đảm bảo AsyncClient được khởi tạo với headers/auth đúng cách."""
        client = self._get_client()
        return await client.get(endpoint, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Ghi đè phương thức request để đảm bảo AsyncClient được khởi tạo với headers/auth đúng cách."""
        client = self._get_client()
        return await client.request(method, url, **kwargs)


    # Xây dựng endpoint TAXII 2.1 động
    def _build_taxii_endpoint(self, collection_id: str) -> str:
        """Xây dựng URL endpoint objects của TAXII 2.1 động.

        Xử lý các trường hợp base_url có hoặc không chứa đường dẫn gốc '/taxii2'.
        """
        base = self.base_url.rstrip("/")
        if "/taxii2" in base:
            return f"{base}/collections/{collection_id}/objects"
        return f"{base}/taxii2/collections/{collection_id}/objects"


    # Tải dữ liệu vulnerability từ OpenCTI và xử lý lỗi WAF
    async def fetch_collection_objects(
        self, collection_id: str, limit: int | None = 5
    ) -> dict[str, Any]:
        """Tải các đối tượng từ một TAXII collection cụ thể.

        Args:
            collection_id: UUID của TAXII collection.
            limit: Số lượng đối tượng tối đa muốn lấy từ máy chủ.

        Returns:
            Dict chứa STIX bundle khớp với truy vấn của collection.
        """
        endpoint = self._build_taxii_endpoint(collection_id)
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        params["match[type]"] = "vulnerability"

        last_error: Exception | None = None

        for attempt in range(1, self.retries + 1):
            try:
                self.logger.info(
                    "[OpenCTI] Đang truy vấn TAXII collection",
                    collection_id=collection_id,
                    endpoint=endpoint,
                    limit=limit,
                    attempt=attempt,
                )
                
                response = await self.get(endpoint, params=params)
                
                if response.status_code == 403:
                    self.logger.error(
                        "[OpenCTI] Phát hiện chặn WAF/Auth (403 Forbidden). "
                        "Hãy đảm bảo header Cookie hợp lệ và chưa hết hạn.",
                        status_code=403
                    )
                elif response.status_code == 468:
                    self.logger.error(
                        "[OpenCTI] Bị chặn bởi WAF (468 Yêu cầu Xác thực Người dùng). "
                        "SafeLine WAF yêu cầu giải CAPTCHA xác minh con người. "
                        "Vui lòng truy cập URL bằng trình duyệt và hoàn thành thử thách xác thực.",
                        status_code=468
                    )
                
                response.raise_for_status()
                
                # Kiểm tra nếu SafeLine Gate trả về trang HTML giải CAPTCHA dưới mã trạng thái 200 OK
                content_type = response.headers.get("content-type") or ""
                if "text/html" in content_type or "<html" in response.text[:200].lower():
                    self.logger.error(
                        "[OpenCTI] Bị chặn bởi WAF (200 OK nhưng trả về trang HTML xác thực CAPTCHA). "
                        "SafeLine WAF yêu cầu giải xác thực con người."
                    )
                    # Gán lại mã trạng thái phản hồi về 468 để xử lý ở tầng trên
                    response.status_code = 468
                    raise httpx.HTTPStatusError(
                        "Phát hiện trang chờ xác thực SafeLine WAF (HTTP 200 chứa nội dung HTML)",
                        request=response.request,
                        response=response
                    )
                
                try:
                    payload = response.json()
                except ValueError as exc:
                    self.logger.error(
                        "[OpenCTI] Thất bại khi phân tích phản hồi dưới dạng JSON.",
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type"),
                        body_preview=response.text[:500]
                    )
                    raise ValueError(
                        f"Phản hồi không phải JSON hợp lệ (Mã: {response.status_code}, "
                        f"Content-Type: {response.headers.get('content-type')}). "
                        f"Nội dung phản hồi: {response.text[:200]}"
                    ) from exc
                
                self.logger.info("[OpenCTI] Yêu cầu tới collection thành công", status_code=response.status_code)
                return payload

            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                last_error = exc
                retryable = isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)) or (
                    isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code >= 500
                )
                self.logger.warning(
                    "[OpenCTI] Yêu cầu thất bại",
                    attempt=attempt,
                    retryable=retryable,
                    error=str(exc)
                )
                if not retryable or attempt >= self.retries:
                    break
                await asyncio.sleep(self.backoff_seconds * attempt)

        assert last_error is not None
        raise last_error
