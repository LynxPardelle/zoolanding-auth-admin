# Production OIDC compatibility correction

The protected release validates the exact production environment and its single main branch rule using GitHub Actions read access before credentials and during final authority checks. AWS trust accepts only exact standard aud/sub claims; unsupported ref and additional trust statements fail closed. The remote branch/protection evidence is sealed in the source fingerprint.

Offline regression coverage includes missing protection, widened rules, wrong repository/environment, duplicate rules, tag rules, unsupported claims, and subject/audience broadening. TEST contracts and mandatory CI remain intact. This source patch does not modify AWS or repository settings. Existing SHA-bound production permission selections must be separately reviewed for the resulting MAIN SHA.
