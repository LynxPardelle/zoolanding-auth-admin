import unittest

from tools import check_auth_admin_readiness as readiness


class ReadinessCheckTests(unittest.TestCase):
    def test_collects_stack_table_pitr_status(self):
        calls = []

        def fake_aws(args):
            calls.append(args)
            if args[:2] == ["cloudformation", "describe-stacks"]:
                return {
                    "Stacks": [{
                        "Outputs": [
                            {"OutputKey": "SessionTableName", "OutputValue": "zoolanding-auth-admin-test-session"},
                            {"OutputKey": "UserStateTableName", "OutputValue": "zoolanding-auth-admin-test-users"},
                            {"OutputKey": "AuditTableName", "OutputValue": "zoolanding-auth-admin-test-audit"},
                        ],
                    }],
                }
            if args[:2] == ["dynamodb", "describe-continuous-backups"]:
                return {
                    "ContinuousBackupsDescription": {
                        "ContinuousBackupsStatus": "ENABLED",
                        "PointInTimeRecoveryDescription": {
                            "PointInTimeRecoveryStatus": "ENABLED",
                            "RecoveryPeriodInDays": 35,
                        },
                    },
                }
            raise AssertionError(args)

        result = readiness.check_stack("zoolanding-auth-admin-test", "us-east-1", aws=fake_aws)

        self.assertEqual(result["stackName"], "zoolanding-auth-admin-test")
        self.assertEqual([table["outputKey"] for table in result["tables"]], [
            "SessionTableName",
            "UserStateTableName",
            "AuditTableName",
        ])
        self.assertTrue(all(table["pitrEnabled"] for table in result["tables"]))
        self.assertIn(["dynamodb", "describe-continuous-backups", "--table-name", "zoolanding-auth-admin-test-audit"], calls)

    def test_marks_disabled_pitr_without_enabling_by_default(self):
        def fake_aws(args):
            if args[:2] == ["cloudformation", "describe-stacks"]:
                return {"Stacks": [{"Outputs": [{"OutputKey": "AuditTableName", "OutputValue": "zoolanding-auth-admin-prod-audit"}]}]}
            if args[:2] == ["dynamodb", "describe-continuous-backups"]:
                return {
                    "ContinuousBackupsDescription": {
                        "ContinuousBackupsStatus": "ENABLED",
                        "PointInTimeRecoveryDescription": {
                            "PointInTimeRecoveryStatus": "DISABLED",
                        },
                    },
                }
            if args[:2] == ["dynamodb", "update-continuous-backups"]:
                raise AssertionError("PITR should not be enabled without explicit apply")
            raise AssertionError(args)

        result = readiness.check_stack("zoolanding-auth-admin-prod", "us-east-1", aws=fake_aws)

        self.assertFalse(result["tables"][0]["pitrEnabled"])
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
