# M-05 Retention and Legal Hold

Every evidence record has `retentionUntil` and an explicit
`EvidenceLegalHoldStatus` (`NONE`, `ACTIVE`, `RELEASED`). Legal holds have a
tenant-scoped history row, actor, reason, creation time, and release actor/time.

Normal application writes cannot delete or overwrite evidence. Deletion is
eligible only after retention expiry, with no active hold, and after a valid
integrity state. An active hold always blocks deletion. Hold create/release
requires `evidence.legal_hold` and is audited. Ownership/admin roles can
perform retention/legal-hold operations; MEMBER/VIEWER have read-only
evidence access.

The test adapter enforces retention on object deletion. The application does
not expose a force-delete or public sharing endpoint.
