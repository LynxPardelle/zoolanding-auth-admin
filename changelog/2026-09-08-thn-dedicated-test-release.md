# 2026-09-08 — Dedicated THN Auth Admin TEST release

- Added an exact-ref/SHA manual TEST workflow with credential-free validation,
  immutable artifact transport and shared deployment concurrency.
- Added separate provision, enable and route-disable operations. Shared v1
  resources and parameters stay unchanged; retained state, functions, execution
  roles and the owner mediator guard survive disablement.
- Bound the owner operator to the reviewed TEST account digest without storing
  its raw identifier or accepting a caller-controlled account selector.
- Corrected change-set review to match AWS's actual response contract while
  retaining exact request/stack identity and destructive-change rejection.
- Added offline lifecycle, SDK response, artifact/workflow and negative tests.
  This entry records implementation, not deployment or client activation.
