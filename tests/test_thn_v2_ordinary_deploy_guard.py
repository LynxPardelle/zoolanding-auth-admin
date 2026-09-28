import contextlib
import io
import json
import subprocess
import unittest

from tools import check_thn_v2_ordinary_deploy as guard


class RecordingRunner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), dict(kwargs)))
        if not self.responses:
            raise AssertionError("unexpected AWS CLI call")
        return self.responses.pop(0)


def _result(stdout="", *, returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=["aws"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


class ThnV2OrdinaryDeployGuardTests(unittest.TestCase):
    def test_missing_stack_is_the_only_aws_error_that_allows_first_deploy(self):
        runner = RecordingRunner(
            _result(
                returncode=255,
                stderr=(
                    "An error occurred (ValidationError) when calling the "
                    "DescribeStacks operation: Stack with id "
                    "zoolanding-auth-admin-test does not exist"
                ),
            )
        )

        guard.verify_ordinary_deploy_safe(runner=runner)

        self.assertEqual(len(runner.calls), 1)

    def test_inactive_stable_stack_without_thn_resources_allows_deploy(self):
        runner = RecordingRunner(
            _result(json.dumps(["UPDATE_COMPLETE", 0])),
            _result("0"),
        )

        guard.verify_ordinary_deploy_safe(runner=runner)

        self.assertEqual(len(runner.calls), 2)

    def test_active_named_parameter_blocks_before_resource_query(self):
        runner = RecordingRunner(_result(json.dumps(["UPDATE_COMPLETE", 1])))

        with self.assertRaises(guard.OrdinaryDeployBlocked):
            guard.verify_ordinary_deploy_safe(runner=runner)

        self.assertEqual(len(runner.calls), 1)

    def test_pre_parameter_stack_with_existing_thn_resource_blocks(self):
        runner = RecordingRunner(
            _result(json.dumps(["UPDATE_COMPLETE", 0])),
            _result("1"),
        )

        with self.assertRaises(guard.OrdinaryDeployBlocked):
            guard.verify_ordinary_deploy_safe(runner=runner)

    def test_unstable_or_malformed_stack_state_fails_closed(self):
        for response in (
            _result(json.dumps(["UPDATE_IN_PROGRESS", 0])),
            _result(json.dumps(["UPDATE_COMPLETE", "0"])),
            _result("not-json"),
        ):
            with self.subTest(stdout=response.stdout):
                runner = RecordingRunner(response)
                with self.assertRaises(guard.GuardVerificationError):
                    guard.verify_ordinary_deploy_safe(runner=runner)

    def test_aws_failure_and_main_output_do_not_disclose_cli_error(self):
        sensitive_error = "AccessDenied account=REDACTED secret=REDACTED"
        runner = RecordingRunner(_result(returncode=254, stderr=sensitive_error))

        with self.assertRaises(guard.GuardVerificationError) as caught:
            guard.verify_ordinary_deploy_safe(runner=runner)
        self.assertNotIn(sensitive_error, str(caught.exception))

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = guard.main(runner=RecordingRunner(_result(returncode=254, stderr=sensitive_error)))
        self.assertEqual(exit_code, 2)
        self.assertNotIn(sensitive_error, stderr.getvalue())
        self.assertNotIn("REDACTED", stderr.getvalue())

    def test_queries_project_only_status_and_counts_for_the_fixed_stack(self):
        runner = RecordingRunner(
            _result(json.dumps(["CREATE_COMPLETE", 0])),
            _result("0"),
        )

        guard.verify_ordinary_deploy_safe(runner=runner)

        describe, describe_options = runner.calls[0]
        resources, resource_options = runner.calls[1]
        self.assertEqual(describe[:3], ["aws", "cloudformation", "describe-stacks"])
        self.assertEqual(resources[:3], ["aws", "cloudformation", "list-stack-resources"])
        for command, options in runner.calls:
            self.assertIn("zoolanding-auth-admin-test", command)
            self.assertEqual(command[command.index("--region") + 1], "us-east-1")
            self.assertEqual(command[command.index("--output") + 1], "json")
            self.assertTrue(options["capture_output"])
            self.assertTrue(options["text"])
            self.assertFalse(options["check"])
        describe_query = describe[describe.index("--query") + 1]
        resource_query = resources[resources.index("--query") + 1]
        self.assertIn("StackStatus", describe_query)
        self.assertIn("EnableThnAuthAdminV2", describe_query)
        self.assertIn("ProvisionThnAuthAdminV2State", describe_query)
        self.assertIn("length(", describe_query)
        self.assertNotIn("StackId", describe_query)
        self.assertIn("ThnAuthAdminV2", resource_query)
        self.assertIn("length(", resource_query)
        self.assertNotIn("PhysicalResourceId", resource_query)
        self.assertEqual(describe_options, resource_options)


if __name__ == "__main__":
    unittest.main()
