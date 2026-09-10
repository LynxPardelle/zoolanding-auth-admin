import unittest

class AuthAdminV2BootstrapTests(unittest.TestCase):
    def test_dedicated_v2_handler_and_cookie_namespace_are_additive(self):
        import auth_admin_session_v2 as auth_v2

        self.assertTrue(callable(auth_v2.lambda_handler))
        self.assertEqual("endefiz7dkk635k6di6k", auth_v2.COOKIE_NAMESPACE)
        self.assertEqual(
            "__Host-zlp_session_endefiz7dkk635k6di6k",
            auth_v2.SESSION_COOKIE_NAME,
        )
        self.assertEqual(1800, auth_v2.SESSION_IDLE_SECONDS)
        self.assertEqual(43200, auth_v2.SESSION_ABSOLUTE_SECONDS)
        self.assertEqual(300, auth_v2.STATE_SECONDS)
        self.assertEqual(900, auth_v2.FAILURE_WINDOW_SECONDS)

    def test_dynamo_number_deserialization_preserves_integer_session_contract(self):
        import auth_admin_session_v2 as auth_v2

        value = auth_v2.DynamoAuthV2Store._deserialize({"N": "3"})
        self.assertIs(type(value), int)
        self.assertEqual(3, value)

    def test_transaction_error_code_extraction_is_non_reflective(self):
        import auth_admin_session_v2 as auth_v2

        error = RuntimeError("private provider details")
        error.response = {"Error": {"Code": "TransactionCanceledException"}}
        self.assertEqual("TransactionCanceledException", auth_v2._aws_error_code(error))
        self.assertEqual("", auth_v2._aws_error_code(RuntimeError("private")))


if __name__ == "__main__":
    unittest.main()
