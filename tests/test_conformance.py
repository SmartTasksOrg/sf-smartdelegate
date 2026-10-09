"""The shared conformance vectors: the engine in-process, and through the REST daemon."""
import shutil
import tempfile
import unittest

from support import Daemon, cases, conformance_config, run_case

from sf_smartdelegate import DaemonClient, Engine


class InProcessConformance(unittest.TestCase):
    def test_vectors_in_process(self):
        n = 0
        for suite, case in cases():
            state = tempfile.mkdtemp(prefix="smartdelegate-conf-")
            try:
                with Engine(conformance_config(state, case['config'])) as engine:
                    failures = run_case(engine.call, case)
                self.assertEqual(failures, [], f"{suite}: {case['name']}")
            finally:
                shutil.rmtree(state, ignore_errors=True)
            n += 1
        self.assertGreaterEqual(n, 60)


class DaemonConformance(unittest.TestCase):
    def test_vectors_over_rest(self):
        n = 0
        for suite, case in cases():
            with Daemon(extra=case['config']) as d:
                client = DaemonClient(d.url, pep_key=d.PEP, admin_key=d.ADMIN)
                failures = run_case(client.call, case)
            self.assertEqual(failures, [], f"{suite}: {case['name']}")
            n += 1
        self.assertGreaterEqual(n, 60)


if __name__ == "__main__":
    unittest.main()
