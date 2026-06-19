import asyncio
import httpx

async def get_raw_adversaries(cve_id: str):
    url = f"https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}/general"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.get(url, headers=headers, timeout=20.0)
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                raw_adversaries = set()
                for p in pulses:
                    adv = p.get("adversary")
                    if adv:
                        raw_adversaries.add(adv.strip())
                print(f"Raw adversaries for {cve_id}:", list(raw_adversaries))
            else:
                print(f"Failed to fetch {cve_id}: {response.status_code}")
        except Exception as e:
            print(f"Error fetching {cve_id}: {e}")

async def main():
    cves = ["CVE-2021-44228", "CVE-2019-11510", "CVE-2021-34527", "CVE-2023-38831"]
    for cve in cves:
        await get_raw_adversaries(cve)

if __name__ == "__main__":
    asyncio.run(main())
