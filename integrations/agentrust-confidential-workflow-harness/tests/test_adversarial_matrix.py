"""Reproducible, seeded adversarial checks for the deterministic adapter."""
import random
import unittest

from harness import HarnessRunner, Scenario


class AdversarialMatrix(unittest.TestCase):
    def test_no_unsafe_acceptance_in_seeded_control_matrix(self):
        rng = random.Random(199)
        runner = HarnessRunner()
        flags = ("dispatch", "timeout_after_dispatch", "revoked_before_use", "replay",
                 "missing_execution_evidence", "retry_lineage", "response_bound", "bypass_egress")
        for index in range(1000):
            inputs = {"workload": "workload-A", "key_id": "key-A", "policy_version": "p1"}
            for flag in flags:
                if rng.randrange(3) == 0:
                    inputs[flag] = rng.choice((True, False))
            inputs["recipient"] = rng.choice(("recipient-R", "recipient-X", "recipient-Y"))
            inputs["software_version"] = rng.choice(("1.0.0", "0.9.0", "1.0.0-rc.1", "2.0.0", "bad"))
            case = Scenario(scenario_id=f"adversarial-{index}", transaction_id=f"txn-{index}",
                            claim="synthetic boundary acceptance", protected_asset="asset-A",
                            workload_principal="workload-A", delegated_peer="peer-B",
                            permitted_recipients=("recipient-R",), forbidden_recipients=("recipient-X",),
                            policy_version="p1", trust_input_digest="sha256:" + "a" * 64,
                            inputs=inputs)
            result = runner.run(case)
            unsafe = (inputs["recipient"] != "recipient-R"
                      or inputs["software_version"] not in ("1.0.0", "2.0.0")
                      or inputs.get("revoked_before_use", False)
                      or inputs.get("replay", False)
                      or not inputs.get("response_bound", True)
                      or inputs.get("bypass_egress", False)
                      or not inputs.get("dispatch", True)
                      or inputs.get("timeout_after_dispatch", False)
                      or inputs.get("missing_execution_evidence", False))
            with self.subTest(index=index):
                if unsafe:
                    self.assertNotEqual(result.status, "passed")
                if result.status == "passed":
                    self.assertTrue(all(v == "established" for v in result.boundary_outcomes.values()))


if __name__ == "__main__":
    unittest.main()
