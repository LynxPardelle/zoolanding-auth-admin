# Production Registry prerequisite number hashing

The shared production prerequisite guard had the same DynamoDB `schemaVersion` number conversion defect observed in API review 36961102597. A regression test reproduced `production_registry_prerequisite_changed` through `capture` before the fix and passed afterward. The full suite passed (468 tests). This is a preventive code change; no AWS deployment or Registry mutation occurred.
