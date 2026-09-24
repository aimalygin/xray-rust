#!/usr/bin/env python3
"""Evidence integrity tests; never make failed/incomplete repetitions pass."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location("summary",Path(__file__).resolve().parents[1]/"summarize-v07-performance.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        case={"id":"test","path":"socks","traffic":"udp","connections":1,"iterations":10,"payload_size":1200}
        self.manifest={"cases":[case],"versions":{"candidate":{}},"repeats":5,"suite":"new","smoke":False,"runs":[]}
        for i in range(1,6):
            output=self.root/str(i);output.mkdir()
            result={**case,"status":"pass","bytes_sent":12000,"bytes_received":12000,
                "samples":[{},{}],"throughput_mib_s":10,"peak_rss_kib":4096,"cpu_millis":1,"latency_us":{"median":100}}
            (output/"result.json").write_text(json.dumps(result))
            self.manifest["runs"].append({"case":"test","version":"candidate","repeat":i,"output":str(output),"returncode":0})
        self.save()

    def tearDown(self):self.temp.cleanup()
    def save(self):(self.root/"manifest.json").write_text(json.dumps(self.manifest))

    def test_invalidated_campaign_is_rejected(self):
        (self.root/"quality.json").write_text(json.dumps({"usable_for_performance":False,"reason":"child leak"}))
        with self.assertRaises(ValueError):module.summarize(self.root)

    def test_complete_group(self):
        result=module.summarize(self.root)
        self.assertTrue(result["rows"][0]["versions"]["candidate"]["complete"])
        self.assertEqual(len(result["artifact_sha256"]),5)

    def test_missing_or_duplicate_run(self):
        self.manifest["runs"].pop();self.save()
        with self.assertRaises(ValueError):module.summarize(self.root)
        self.manifest["runs"].append(self.manifest["runs"][0]);self.save()
        with self.assertRaises(ValueError):module.summarize(self.root)

    def test_failure_does_not_receive_passing_median(self):
        self.manifest["runs"][1]["returncode"]=1;self.save()
        result=module.summarize(self.root)
        self.assertEqual(len(result["failures"]),1)
        group=result["rows"][0]["versions"]["candidate"]
        self.assertFalse(group["complete"])
        self.assertEqual(group["metrics"],{})

    def test_legacy_sub_millisecond_run_has_no_invented_throughput(self):
        self.manifest["suite"]="legacy"
        self.manifest["versions"]["candidate"]["engine_sha256"]="engine"
        self.manifest["cases"][0]["args"]=["--workload","stream-transport","--traffic","full-duplex","--connections","1","--iterations","10","--payload-size","1200"]
        for run in self.manifest["runs"]:
            path=Path(run["output"])/"result.json"
            result=json.loads(path.read_text())
            result.update(workload="stream-transport",throughput_mbps=None,provenance={"engine_binary_sha256":"engine"})
            path.write_text(json.dumps(result))
        self.save()
        metrics=module.summarize(self.root)["rows"][0]["versions"]["candidate"]["metrics"]
        self.assertNotIn("throughput_mib_s",metrics)
        result["bytes_received"]-=1
        path.write_text(json.dumps(result))
        with self.assertRaises(ValueError):module.summarize(self.root)

    def test_truncated_bytes_and_changed_axes_rejected(self):
        path=self.root/"1/result.json"
        result=json.loads(path.read_text());result["bytes_received"]-=1
        path.write_text(json.dumps(result))
        with self.assertRaises(ValueError):module.summarize(self.root)
        result["bytes_received"]+=1;result["connections"]=2
        path.write_text(json.dumps(result))
        with self.assertRaises(ValueError):module.summarize(self.root)


if __name__=="__main__":unittest.main()
