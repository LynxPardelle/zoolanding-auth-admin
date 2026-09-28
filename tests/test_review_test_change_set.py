import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.review_test_change_set import ChangeSetReviewError, review_change_set


ARN = "arn:aws:cloudformation:us-east-1:123456789012:changeSet/release-1/abc"


def payload(*, action="Modify", replacement="False"):
    return {"StackName": "example-test", "ChangeSetName": "release-1", "ChangeSetId": ARN, "ChangeSetType": "UPDATE", "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE", "Parameters": [{"ParameterKey": "EnvironmentName", "ParameterValue": "test"}, {"ParameterKey": "EnableFeature", "ParameterValue": "false"}], "Changes": [{"Type": "Resource", "ResourceChange": {"Action": action, "Replacement": replacement}}]}


class ReviewTestChangeSetTests(unittest.TestCase):
    def test_accepts_exact_nonreplacement_update(self):
        self.assertEqual(review_change_set(payload(), expected_stack_name="example-test", expected_change_set_name="release-1", expected_change_set_arn=ARN, expected_change_set_type="UPDATE", expected_parameters={"EnvironmentName": "test", "EnableFeature": "false"}, required_parameters=set()), "execute")

    def test_rejects_remove_and_replacement(self):
        for candidate in (payload(action="Remove"), payload(replacement="True")):
            with self.subTest(candidate=candidate), self.assertRaisesRegex(ChangeSetReviewError, "stateful_resource_change_forbidden"):
                review_change_set(candidate, expected_stack_name="example-test", expected_change_set_name="release-1", expected_change_set_arn=ARN, expected_change_set_type="UPDATE", expected_parameters={"EnvironmentName": "test"}, required_parameters=set())

    def test_rejects_parameter_drift(self):
        with self.assertRaises(ChangeSetReviewError):
            review_change_set(payload(), expected_stack_name="example-test", expected_change_set_name="release-1", expected_change_set_arn=ARN, expected_change_set_type="UPDATE", expected_parameters={"EnableFeature": "true"}, required_parameters=set())



class ChangeSetEnvelopeGuardTests(unittest.TestCase):
    def candidate(self):
        return {"StackName": "example-test", "StackId": "arn:aws:cloudformation:us-east-1:765932874577:stack/example-test/stack-id", "ChangeSetName": "release-1", "ChangeSetId": "arn:aws:cloudformation:us-east-1:765932874577:changeSet/release-1/change-id", "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE", "Parameters": [{"ParameterKey": "EnvironmentName", "ParameterValue": "test"}], "Changes": [{"Type": "Resource", "ResourceChange": {"LogicalResourceId": "Function", "ResourceType": "AWS::Lambda::Function", "Action": "Modify", "Replacement": "False"}}]}

    def review(self, candidate):
        return review_change_set(candidate, expected_stack_name="example-test", expected_change_set_name="release-1", expected_change_set_arn=self.candidate()["ChangeSetId"], expected_change_set_type="UPDATE", expected_parameters={"EnvironmentName": "test"}, required_parameters=set())

    def test_rejects_unreviewed_page_and_nested_preview(self):
        for field, value in (("NextToken", "another-page"), ("ParentChangeSetId", "parent"), ("RootChangeSetId", "root")):
            candidate = self.candidate()
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ChangeSetReviewError):
                self.review(candidate)

    def test_rejects_reported_stack_identity_conflict(self):
        for value in ("arn:aws:cloudformation:us-east-1:111111111111:stack/example-test/stack-id", "arn:aws:cloudformation:eu-west-1:765932874577:stack/example-test/stack-id", "arn:aws:cloudformation:us-east-1:765932874577:stack/other-test/stack-id", None):
            candidate = self.candidate()
            candidate["StackId"] = value
            with self.subTest(value=value), self.assertRaises(ChangeSetReviewError):
                self.review(candidate)

    def test_rejects_unreviewed_child_changes(self):
        for field, value in (("ChangeSetId", "child"), ("ResourceType", "AWS::CloudFormation::Stack")):
            candidate = self.candidate()
            candidate["Changes"][0]["ResourceChange"][field] = value
            with self.subTest(field=field), self.assertRaises(ChangeSetReviewError):
                self.review(candidate)

    def test_accepts_flat_cdk_preview_flag_without_child_changes(self):
        candidate = self.candidate()
        candidate["IncludeNestedStacks"] = True
        self.assertEqual(self.review(candidate), "execute")

if __name__ == "__main__":
    unittest.main()
