import asyncio
import httpx

def extract_threat_actors(otx_data: dict) -> list[str]:
    actors = set()
    pulse_info = otx_data.get("pulse_info", {})
    pulses = pulse_info.get("pulses", [])
    for p in pulses:
        adv = p.get("adversary")
        if adv:
            adv = adv.strip()
            if not adv:
                continue
            # Split by comma or semicolon in case multiple actors are listed
            for delimiter in [",", ";"]:
                if delimiter in adv:
                    parts = adv.split(delimiter)
                    break
            else:
                parts = [adv]
                
            for part in parts:
                part_clean = part.strip()
                if not part_clean:
                    continue
                # Ignore generic words
                if part_clean.lower() in {"threat", "unknown", "none", "threat actor", "adversary"}:
                    continue
                # Let's filter out entries that look like malware if they contain "rat" or "agent" or "malware",
                # but keep specific APT names. Actually, we can keep them or clean them.
                actors.add(part_clean)
    return sorted(list(actors))

async def test_cve(cve_id: str):
    url = f"https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}/general"
    print(f"\n--- Testing CVE: {cve_id} ---")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            actors = extract_threat_actors(data)
            print("Extracted Threat Actors:", actors)
        else:
            print("Failed with status:", response.status_code)

async def main():
    cves = ["CVE-2021-44228", "CVE-2021-34527", "CVE-2019-0803", "CVE-2023-38831"]
    for cve in cves:
        await test_cve(cve)

if __name__ == "__main__":
    asyncio.run(main())
