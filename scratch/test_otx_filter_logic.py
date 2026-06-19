def clean_adversary(name: str) -> bool:
    name_lower = name.lower()
    
    # Common malware/tool keywords to reject
    malware_keywords = {
        "rat", "malware", "trojan", "backdoor", "botnet", "miner", "stealer", 
        "worm", "ransomware", "spyware", "keylogger", "rootkit", "adware",
        "webshell", "agent", "ransom"
    }
    
    # Common technique/generic keywords to reject
    technique_keywords = {
        "exploit", "exploitation", "vulnerability", "injection", "scan", 
        "scanning", "scanner", "bypass", "payload", "poc", "proof of concept",
        "threat", "adversary", "campaign", "actor"
    }
    
    # Split name into words to check precisely
    words = name_lower.replace("-", " ").replace("_", " ").replace(".", " ").split()
    for word in words:
        if word in malware_keywords or word in technique_keywords:
            return False
            
    return True

def test_filter():
    test_cases = {
        # Should be KEPT (True)
        "APT35": True,
        "APT29": True,
        "Lazarus Group": True,
        "Cozy Bear": True,
        "LockBit": True,
        "LockBit 3.0": True,
        "MuddyWater": True,
        "Fancy Bear": True,
        "UNC2452": True,
        "Payouts King": True,
        
        # Should be REJECTED (False)
        "Mirax RAT": False,
        "DesckVB RAT": False,
        "Marimo Exploitation": False,
        "SQL Injection": False,
        "Log4Shell exploit": False,
        "Threat Actor": False,
        "Unknown Campaign": False,
        "Lazarus Campaign": False,
        "webshell payload": False,
        "ransomware variant": False
    }
    
    passed = 0
    for name, expected in test_cases.items():
        result = clean_adversary(name)
        if result == expected:
            passed += 1
            print(f"✓ PASS: {repr(name)} -> {result}")
        else:
            print(f"✗ FAIL: {repr(name)} -> got {result}, expected {expected}")
            
    print(f"\nPassed: {passed}/{len(test_cases)}")

if __name__ == "__main__":
    test_filter()
