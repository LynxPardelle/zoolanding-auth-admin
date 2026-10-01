# Isolate Auth Admin production recovery templates

The Image Upload production state review 36804498394 exposed a shared release-runner defect before any stack update. The private candidate reused existing public resource objects by reference; writing a sealed historical Lambda ZIP into the recovery template also changed the candidate and the baseline fingerprint. The state guard correctly blocked the resulting public-resource modification.

Auth Admin carries the same candidate selection and recovery-copy code. Copy existing resources and parameters into private candidates, and copy the historical original template before writing recovery code coordinates. This preserves public resource identities and a stable baseline for the subsequent exact-digest execution. Two new regression tests failed on the old code and pass with this change. No AWS deployment or repository setting changes are included.

The required pre-PR audit also found 13 known vulnerabilities in pinned PyJWT 2.13.0. Upgrade the runtime pin to PyJWT 2.15.0, matching API Proxy's validated runtime pin. This changes the next Auth Admin artifact when it is separately reviewed and deployed; source promotion alone does not update the production Lambda.
