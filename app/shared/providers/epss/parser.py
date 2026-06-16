"""EPSS parser."""
from typing import Any


class EPSSParser:
    def normalize(self, raw: Any, cve_id: str) -> dict:
        if not raw or 'data' not in raw:
            return {'epss_score': None, 'epss_percentile': None}
        for item in raw.get('data', []):
            if item.get('cve') == cve_id:
                return {
                    'epss_score': item.get('epss'),
                    'epss_percentile': item.get('percentile'),
                }
        return {'epss_score': None, 'epss_percentile': None}
