.PHONY: build-AuthAdminFunction build-ThnAuthAdminV2Function build-ThnAuthAdminV2OriginAuthorizerFunction build-ThnAuthAdminV2OwnerOperatorFunction

build-AuthAdminFunction:
	python tools/build_lambda_artifact.py AuthAdminFunction "$(ARTIFACTS_DIR)"

build-ThnAuthAdminV2Function:
	python tools/build_lambda_artifact.py ThnAuthAdminV2Function "$(ARTIFACTS_DIR)"

build-ThnAuthAdminV2OriginAuthorizerFunction:
	python tools/build_lambda_artifact.py ThnAuthAdminV2OriginAuthorizerFunction "$(ARTIFACTS_DIR)"

build-ThnAuthAdminV2OwnerOperatorFunction:
	python tools/build_lambda_artifact.py ThnAuthAdminV2OwnerOperatorFunction "$(ARTIFACTS_DIR)"
