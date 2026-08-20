# JOBEN Enterprise — Roadmap Gap Task List

**Tanggal analisis:** 19 Agustus 2026  
**Sumber analisis:** roadmap terlampir, `DOC/CAPABILITY-REGISTRY.md`,
`DOC/KNOWN-LIMITATIONS.md`, `DOC/GATE-A-PROOF.md`, `DOC/GATE-B-PROOF.md`,
dan completion dossiers M-03/M-05/M-06.

## Cara membaca dokumen ini

Dokumen ini hanya mencantumkan pekerjaan yang belum selesai secara nyata.
Implementasi, route, fixture, seed, dashboard render, HTTP 200, atau test fake
tidak dianggap sebagai `LIVE_VERIFIED`.

Status yang dipakai:

- **Sudah ada, belum live-verified:** kode dan test lokal/integrasi tersedia,
  tetapi bukti provider/operasional nyata belum ada.
- **Belum dibangun:** belum ada implementation boundary yang dapat dipakai
  end-to-end.
- **Gate:** pekerjaan harus selesai dan bukti penerimaannya lengkap sebelum
  capability boleh dipromosikan.

## Keputusan prioritas

### Jalur MVP live

Urutan minimum yang disarankan:

`S0 Foundation Truth → S1 Evidence Vertical Slice → S2 Decision System →
S3 Customer Operating Surface → S5 Commercial + Assistant`

Dalam istilah fase roadmap, ini kira-kira mencakup P0 → P1 → P1B. P2–P8
sebaiknya tidak dikerjakan lebih dahulu kecuali kontrak, owner, dan bukti gate
MVP sudah ditutup.

### Aturan yang tidak boleh dilanggar

1. Jangan mengubah `PLANNED`, `VERIFICATION_REQUIRED`, `DEGRADED`, atau
   `NOT_EVALUATED` menjadi sukses hanya karena UI, seed, fixture, AI, atau
   default value.
2. Provider error, permission denial, timeout, schema drift, stale data,
   partial coverage, dan missing evidence tidak boleh diproyeksikan sebagai
   pass/verified.
3. Setiap task harus memiliki actor, tenant scope, state machine, error
   taxonomy, idempotency, concurrency rule, retention, audit event, test
   evidence, metric/SLO, cost ceiling, rollback/recovery, dan runbook.
4. Data harus selalu dibedakan antara `LIVE CUSTOMER`, `PROVIDER SANDBOX`, dan
   `ISOLATED DEMO`. Data demo tidak boleh menjadi bukti live capability.
5. Setiap task berhenti setelah scope dan gate-nya selesai:
   **INSPECT FIRST → IMPLEMENT ONLY MISSING SCOPE → TEST → VERIFY →
   DOCUMENT → STOP.**

---

# A. Pekerjaan yang sudah ada tetapi belum 100% real

## TASK-01 — Tutup Gate A dengan bukti provider dan hosting nyata

**Status:** belum selesai; Gate A masih `NOT PASSED`.  
**Prioritas:** P0, blocker untuk klaim MVP live.  
**Dependency:** environment PostgreSQL yang terkontrol, identity provider,
AWS provider, dan target hosting.

### Catatan detail

Fondasi PostgreSQL, migration, tenant/RBAC, audit, CI definition, health
endpoint, dan HTTP boundary sudah memiliki bukti lokal/integrasi. Yang belum
lengkap adalah verifikasi eksternal: identity provider live, AWS identity,
live object storage/WORM, serta hosting/CI execution yang benar-benar dapat
direproduksi.

### Pekerjaan

- Jalankan clean install, typecheck, build, test, dan migration deploy pada
  environment target.
- Catat migration status sebelum dan sesudah deploy.
- Buktikan `/health/live` dan `/health/ready` pada runtime target.
- Buktikan boundary production config menolak konfigurasi yang tidak lengkap.
- Buktikan identity provider live dan session lifecycle.
- Buktikan AWS STS identity pada akun terkontrol.
- Buktikan live evidence storage dan retention boundary.
- Simpan bukti bertanggal, correlation ID, versi code, environment class,
  provider account identifier yang sudah direduksi, dan hasil negative test.

### Definition of Done

- Gate A proof record menyatakan PASS hanya untuk requirement yang benar-benar
  dieksekusi.
- Tidak ada claim `LIVE_VERIFIED` tanpa bukti provider.
- Capability registry, known limitations, runbook, dan customer limitations
  diperbarui.
- Ada rollback/recovery procedure yang berhasil dicoba, bukan hanya ditulis.

## TASK-02 — Aktifkan identity provider produksi dan verifikasi auth

**Status:** belum selesai; dev identity adapter ada, Clerk/provider belum live.  
**Prioritas:** P0/S0.  
**Dependency:** TASK-01; provider connection dan konfigurasi secret melalui
workspace secret flow.

### Catatan detail

Implementasi session, CSRF, revoke/rotate, membership, invitation, RBAC, dan
tenant boundary sudah ada sebagai code/test boundary. Ini belum menjadi
identity capability produksi sampai login provider, callback, email identity,
session revocation, dan failure modes diuji pada provider nyata.

### Pekerjaan

- Tetapkan provider produksi dan actor lifecycle: sign-in, callback, logout,
  expired session, revoked session, disabled membership, dan account recovery.
- Hubungkan provider tanpa menyimpan credential di source atau database.
- Pastikan external identity hanya dipetakan ke internal user melalui aturan
  yang immutable dan diaudit.
- Uji invitation accept, duplicate invitation, expiry, revoke, replay, dan
  ownership transfer dengan database PostgreSQL.
- Uji cross-tenant read/write denial melalui HTTP dan service boundary.
- Uji CSRF, cookie flags, session rotation, dan production disablement dev auth.

### Bukti wajib

Auth acceptance matrix, provider logs yang direduksi, integration/E2E/security
tests, audit events, failure taxonomy, dan runbook unlink/revoke/recovery.

## TASK-03 — Ganti adapter evidence lokal dengan object storage WORM nyata

**Status:** belum selesai; in-memory/versioned adapter hanya `TEST_VERIFIED`.  
**Prioritas:** P1/S1, blocker untuk Evidence Gate.  
**Dependency:** TASK-01; storage account/bucket terkontrol.

### Catatan detail

Pipeline redaction → schema validation → JCS-1 → SHA-256 → metadata
PostgreSQL → integrity verification sudah dibangun. Yang belum terbukti adalah
encryption, versioning, retention, dan Object Lock pada provider nyata.

### Pekerjaan

- Gunakan storage abstraction yang ada; jangan membuat bypass khusus production.
- Konfigurasikan encryption, bucket versioning, default retention, dan
  Object Lock governance/compliance sesuai kontrak.
- Uji write, read-back, overwrite rejection, retention expiry, legal hold,
  supersession, deletion eligibility, dan independent integrity check.
- Uji kehilangan object, object corruption, provider denial, timeout, dan
  storage schema/API drift.
- Pastikan objek evidence tidak dapat diubah/dihapus sebelum aturan lifecycle
  terpenuhi.

### Definition of Done

Live storage proof record berisi bucket policy class, version ID yang direduksi,
retention result, independent hash result, negative tests, dan recovery drill.
Registry tetap `VERIFICATION_REQUIRED` jika salah satu bukti belum tersedia.

## TASK-04 — Tutup Gate B dengan satu AWS control live

**Status:** belum selesai; root-MFA control sudah test-verified, live AWS belum.  
**Prioritas:** P1/S1, blocker untuk vertical slice.  
**Dependency:** TASK-01, TASK-02, TASK-03.

### Catatan detail

Control `AWS-IAM-ROOT-MFA` sudah mengalir dari `GetAccountSummary` sampai
dashboard. Belum ada STS proof, observation nyata, evidence live, controlled
account comparison, dan permission-negative run.

### Pekerjaan

- Gunakan disposable/controlled AWS account dengan policy read-only minimum.
- Jalankan STS identity verification dan pastikan account mismatch ditolak.
- Jalankan `iam:GetAccountSummary` pada account tersebut.
- Simpan observation, evidence hash, freshness, coverage, scan ID, control
  version, evaluator version, dan provenance.
- Jalankan account dengan permission dicabut dan pastikan hasilnya error/
  insufficient evidence, bukan PASS.
- Jalankan tenant-isolation negative test dan controlled-account manual
  comparison.
- Re-run untuk memastikan idempotency dan deterministic projection.

### Definition of Done

Gate B proof record memenuhi seluruh enam promotion conditions pada
`DOC/GATE-B-PROOF.md`; hanya setelah itu capability boleh naik ke
`LIVE_VERIFIED`.

---

# B. S1 — Evidence Vertical Slice yang masih kurang

## TASK-05 — Bangun provider contract registry dan capability truth service

**Status:** belum selesai sebagai product capability; registry dokumentasi ada.  
**Prioritas:** P1/S0–S1.  
**Dependency:** TASK-01 sampai TASK-04.

### Catatan detail

Roadmap membutuhkan CapabilityRecord, provider matrix, data classification,
source revision, freshness/coverage, dan proof reference yang konsisten.
Sebagian metadata sudah tersebar di code dan docs, tetapi belum ada lifecycle
operasional yang memaksa perubahan capability mengikuti bukti.

### Pekerjaan

- Definisikan schema CapabilityRecord: capability, module, version, state,
  source of truth, dependencies, proof, reviewer, verified/expires time.
- Definisikan provider matrix: operation, permission, region, data class,
  retention, error mapping, and live-verification status.
- Tambahkan state transition guard agar `LIVE_VERIFIED` memerlukan proof record.
- Tambahkan capability diff pada deploy/release checklist.
- Audit semua UI/API agar state tidak disimpulkan dari HTTP 200.

### Bukti selesai

Schema/migration, transition tests, registry API or operator command,
capability-diff output, and runbook promotion/revocation.

## TASK-06 — Lengkapi AWS security checks dan coverage matrix

**Status:** sebagian; rule engine empat rule dan root-MFA tersedia, tetapi
roadmap check set belum lengkap.  
**Prioritas:** P1/S2.  
**Dependency:** TASK-04, inventory yang live-verified.

### Catatan detail

Security rule engine hanya boleh mengevaluasi field inventory/evidence yang
benar-benar ada. Check tambahan tidak boleh dibuat sebagai scoring placeholder.

### Pekerjaan

- Kunci control catalog dari PRD: check ID/version, owner, source revision,
  required permission, resource scope, evidence schema, and remediation class.
- Implementasikan remaining AWS checks yang termasuk MVP hanya jika provider
  operation dan evidence contract sudah jelas.
- Tambahkan freshness, coverage, partial region/service, stale, schema drift,
  permission denial, and missing evidence semantics.
- Pastikan automatic resolve/reopen, dedupe, finding provenance, dan stable
  pagination tetap tenant-scoped.
- Tambahkan golden fixtures hanya untuk deterministic tests; beri label fixture
  dan jangan pakai sebagai live proof.

### Definition of Done

Setiap check punya contract, evaluator, evidence, failure behavior,
integration/security/regression test, runbook, dan proof record.

---

# C. S2 — Decision System

## TASK-07 — Bangun aggregation, posture, freshness, dan decision projection

**Status:** belum selesai; dashboard saat ini tidak menghitung compliance score.  
**Prioritas:** P1/S2.  
**Dependency:** TASK-06.

### Catatan detail

Roadmap meminta rebuild projection identik, freshness/coverage, dan error tidak
menjadi pass. Projection harus berasal dari persisted scan/control/evidence,
bukan state frontend.

### Pekerjaan

- Definisikan decision state: `PASS`, `FAIL`, `ERROR`, `INSUFFICIENT_EVIDENCE`,
  `STALE`, `PARTIAL`, `NOT_EVALUATED`, dan terminal semantics.
- Definisikan score/posture hanya jika coverage dan freshness memenuhi threshold.
- Simpan input version, evaluator version, calculation timestamp, and lineage.
- Implementasikan deterministic rebuild dari database dan equality test terhadap
  projection incremental.
- Tampilkan alasan, missing coverage, provider errors, dan freshness pada API
  maupun UI.
- Uji concurrent scan, replay, late event, duplicate event, dan schema drift.

### Definition of Done

Projection rebuild identik, no-error-as-pass test lulus, tenant/security
regression lulus, dan operator dapat menjelaskan setiap angka sampai evidence.

## TASK-08 — Bangun remediation workflow yang aman dan read-only-by-default

**Status:** belum dibangun; registry `REMEDIATION = PLANNED`.  
**Prioritas:** P1/S2, setelah decision projection stabil.  
**Dependency:** TASK-07.

### Catatan detail

Remediation bukan sekadar tombol “fix”. MVP harus membedakan guidance,
customer-approved action, execution, verification, dan failure. Default
AWS discovery tetap read-only.

### Pekerjaan

- Definisikan remediation contract per finding: prerequisites, affected scope,
  permission, rollback, expected observation, and risk.
- Implementasikan guidance/read-only plan terlebih dahulu.
- Jika execution diperlukan, gunakan explicit approval, idempotency key,
  confirmation, least privilege, audit, timeout, retry, and rollback.
- Re-scan setelah remediation dan hubungkan finding old/new state.
- Uji permission denial, partial execution, concurrent approval, cancellation,
  failed verification, and cross-tenant denial.

### Definition of Done

Tidak ada mutation tanpa approval yang dapat diaudit; hasil remediation hanya
dianggap sukses setelah verification provider dan rescan, bukan optimistic UI.

---

# D. S3 — Customer Operating Surface

## TASK-09 — Tutup dashboard/API parity dan operational UX

**Status:** dashboard v2 ada; product surface belum lengkap.  
**Prioritas:** P1/S3.  
**Dependency:** TASK-07 dan TASK-08.

### Pekerjaan

- Selaraskan semua route/API dengan projection server dan permission matrix.
- Lengkapi empty, loading, error, permission-denied, stale, partial,
  not-calculated, and degraded states.
- Tambahkan drill-down dari posture → control → finding → evidence → source.
- Tambahkan scan start/status/cancel/replay bila kontrak sudah live.
- Pastikan search/filter/pagination tenant-scoped dan tidak menampilkan
  demo/live data bercampur.
- Uji keyboard accessibility, responsive layouts, localization readiness,
  error recovery, and API/UI parity.

### Definition of Done

Tidak ada angka demo atau default score; setiap nilai UI dapat ditelusuri ke
API, database record, scan, dan evidence.

## TASK-10 — Bangun deterministic report dan signed access

**Status:** belum dibangun; registry `REPORT = PLANNED`.  
**Prioritas:** P1B/S3.  
**Dependency:** TASK-07, TASK-09, TASK-03.

### Pekerjaan

- Definisikan report snapshot: tenant, time window, controls, findings,
  evidence hashes, freshness, coverage, limitations, and source revisions.
- Generate output deterministik dari snapshot immutable; ulangi input yang sama
  harus menghasilkan isi dan hash yang sama.
- Sediakan access control, expiry, revoke, audit, and signed URL/token policy.
- Pastikan report menandai `DEMO`, `SANDBOX`, atau `LIVE` dengan jelas.
- Uji report terhadap stale/partial/error/missing evidence dan cross-tenant
  access.

### Definition of Done

Report dapat diverifikasi penerimanya, dapat dicabut, tidak memuat secret, dan
memiliki provenance lengkap sampai evidence.

## TASK-11 — Bangun notification inbox, delivery, dedupe, dan audit

**Status:** belum dibangun; registry `NOTIFICATION = PLANNED`.  
**Prioritas:** P1B/S3.  
**Dependency:** TASK-10 dan event boundary M-03.

### Pekerjaan

- Definisikan event envelope, recipient scope, preference, severity, and
  delivery policy.
- Buat durable inbox/outbox dengan idempotency, dedupe key, retry/backoff,
  dead-letter, and replay.
- Implementasikan minimal satu channel nyata setelah provider dipilih.
- Catat delivery status, latency, provider response category, and audit event.
- Jangan kirim notification untuk demo data atau unverified live claim tanpa
  label.

### Definition of Done

Dedupe, retry, provider failure, unsubscribe/preference, tenant isolation,
delivery latency SLO, and operator replay runbook terbukti.

---

# E. P1B — Provider kedua dan operasi komersial beta

## TASK-12 — Bangun GitHub App provider vertical slice

**Status:** belum dibangun; roadmap WP-09.  
**Prioritas:** P1B.  
**Dependency:** TASK-05, TASK-07, dan provider credential boundary.

### Pekerjaan

- Tetapkan installation/account/repository tenant mapping.
- Implementasikan webhook signature verification, replay protection, inbox,
  installation revoke, and permission-denied semantics.
- Normalisasi resource/evidence ke provider-neutral contract tanpa kehilangan
  provenance GitHub.
- Implementasikan satu check nyata dengan source revision dan evidence schema.
- Uji repository deletion, rename, private/public transition, stale webhook,
  duplicate webhook, rate limit, and API outage.

### Definition of Done

GitHub sandbox/controlled installation menghasilkan observation nyata, evidence
yang immutable, dan decision projection yang sama contract-nya dengan AWS.

## TASK-13 — Operational beta: scheduler, queue controls, SLO, and runbooks

**Status:** sebagian; durable queue/worker/retry ada, scheduler calendar dan
operational surface belum lengkap.  
**Prioritas:** P1B/S6.  
**Dependency:** TASK-06 sampai TASK-12.

### Pekerjaan

- Finalisasi timezone/calendar contract dan schedule lifecycle.
- Tambahkan queue depth, age, lease expiry, retry, dead-letter, cancellation,
  circuit breaker, and worker health metrics.
- Tetapkan SLO: scan start latency, completion latency, provider error rate,
  evidence commit latency, notification delivery latency.
- Tambahkan alert threshold, runbook, manual replay, pause/resume, and safe
  recovery drill.
- Uji worker crash, duplicate lease, database outage, provider outage, and
  poison job.

### Definition of Done

Operator dapat mengetahui job apa yang tertahan, mengapa, dampaknya pada
freshness, dan cara recovery tanpa mengubah data secara manual.

## TASK-14 — Billing sandbox dan entitlement enforcement

**Status:** belum dibangun; registry `BILLING = PLANNED`.  
**Prioritas:** P1B/S5.  
**Dependency:** TASK-02, TASK-09, provider billing yang dipilih.

### Pekerjaan

- Tetapkan product/price/plan, trial, limits, seats, provider/customer mapping,
  and entitlement model.
- Buat webhook inbox dengan signature verification, dedupe, replay,
  reconciliation, and out-of-order event handling.
- Enforce entitlement server-side pada route/service/worker; UI hanya
  menampilkan hasil server.
- Definisikan grace period, payment failure, cancellation, upgrade/downgrade,
  and refund behavior.
- Pisahkan billing sandbox dari live customer namespace.

### Definition of Done

Tidak ada akses berbayar yang diberikan dari frontend atau optimistic response;
entitlement denial, webhook replay, reconciliation, audit, and recovery
teruji.

---

# F. S4–S5 — Governance dan assistant

## TASK-15 — Governance, trust portal, auditor access, dan publication workflow

**Status:** belum dibangun; registry `GOVERNANCE = PLANNED`.  
**Prioritas:** P2/S4.  
**Dependency:** TASK-10, TASK-13, TASK-05.

### Pekerjaan

- Definisikan human approval, reviewer role, separation of duties, and
  approval expiry.
- Implementasikan official-source provenance, source revision, reviewer,
  effective date, and supersession.
- Buat auditor access yang scoped, time-bound, revocable, and tenant-specific.
- Tambahkan stale/demo exclusion pada published trust material.
- Implementasikan publish/unpublish/revoke dengan immutable audit trail.

### Definition of Done

Auditor hanya melihat scope yang disetujui; published material dapat dibuktikan
asal-usulnya, masa berlaku, approval, dan status revoke.

## TASK-16 — AI Gateway dengan citation, refusal, fallback, dan cost ceiling

**Status:** belum dibangun; registry `AI = PLANNED`.  
**Prioritas:** P1B/S5 atau setelah core S3 stabil.  
**Dependency:** TASK-05, TASK-07, TASK-10, billing/usage control.

### Pekerjaan

- Tetapkan retrieval boundary: hanya evidence/report/provider data yang
  authorized dan fresh sesuai policy.
- Buat citation contract: source ID, evidence hash, observation time,
  provider/source revision, and quoted support.
- Buat refusal rules untuk missing evidence, stale data, unsupported question,
  tenant mismatch, and provider error.
- Tambahkan provider fallback safety: no silent model/provider substitution,
  versioned prompt/model, timeout, retry, and outage behavior.
- Tambahkan usage metering, budget/cost ceiling, rate limit, and audit.
- Buat golden set untuk citation/refusal dan prompt injection/security tests.

### Definition of Done

AI tidak boleh mengarang pass/verified/paid/published status. Jawaban yang
tidak didukung evidence harus menolak atau menyatakan keterbatasan secara
eksplisit.

---

# G. P2–P8 expansion setelah MVP

## TASK-17 — Market pack dan public trust surface

**Status:** belum dibangun; roadmap WP-13.  
**Prioritas:** P2.  
**Dependency:** TASK-15.

**Catatan detail:** Buat paket trust/public yang versioned dan approved:
  security overview, limitations, control coverage, report verification,
  privacy/security contact, and revocation. Public surface tidak boleh
  menampilkan customer data, stale proof, demo proof, atau unapproved claim.

**DoD:** publish/revoke, approval, cache invalidation, signed artifact
  verification, accessibility, localization, and abuse/rate-limit tests lulus.

## TASK-18 — Global provider, routing, and data residency

**Status:** belum dibangun; roadmap WP-14.  
**Prioritas:** P3.  
**Dependency:** TASK-05, TASK-13, TASK-15.

**Catatan detail:** Tetapkan region routing, tenant residency, cross-region
  replication policy, failover, provider availability, timezone, localization,
  data transfer, and deletion behavior. Jangan mengklaim global availability
  tanpa failover drill dan jurisdiction proof.

**DoD:** residency matrix, routing test, failover/recovery drill, regional
  outage behavior, and data classification audit tersedia.

## TASK-19 — ISO 27001 control/evidence pack dan provider expansion

**Status:** belum dibangun; roadmap WP-15/WP-16.  
**Prioritas:** P4.  
**Dependency:** TASK-15, TASK-17, TASK-18.

**Catatan detail:** Implementasikan control catalog, statement of applicability,
  evidence mapping, owner/reviewer workflow, exception/risk acceptance,
  recurring review, and additional provider controls. Ini bukan claim
  certification; certification remains external.

**DoD:** setiap control memiliki source, evidence, freshness, owner, review
  expiry, exception, and auditor export; no unsupported compliance claim.

## TASK-20 — Privacy, GDPR/CCPA, and data subject workflows

**Status:** belum dibangun; roadmap WP-17.  
**Prioritas:** P5.  
**Dependency:** TASK-02, TASK-03, TASK-15, TASK-18.

**Catatan detail:** Definisikan data inventory/classification, purpose,
  retention, consent/legal basis, DSR export/delete/correct, restriction,
  processor/subprocessor record, breach workflow, and tenant isolation.
  Legal policy must be reviewed separately; code must enforce only explicit
  product rules.

**DoD:** DSR state machine, authorization, legal hold conflict, audit,
  deletion verification, export redaction, SLA timers, and runbook teruji.

## TASK-21 — PCI SAQ assistant

**Status:** belum dibangun; roadmap WP-19.  
**Prioritas:** P7.  
**Dependency:** TASK-16, TASK-19, TASK-20.

**Catatan detail:** Buat questionnaire contract, evidence-backed answers,
  uncertainty/refusal, reviewer approval, versioned export, scope
  segmentation, and no certification claim. Jawaban harus dapat ditelusuri
  ke evidence dan reviewer.

**DoD:** golden questionnaire set, unsupported-answer refusal, approval/
  revision history, export verification, and tenant/security tests lulus.

## TASK-22 — White-label dan auditor marketplace

**Status:** belum dibangun; roadmap WP-20/WP-21.  
**Prioritas:** P8.  
**Dependency:** TASK-15, TASK-17, TASK-18, TASK-19.

**Catatan detail:** Implementasikan tenant branding, domain/asset isolation,
  branding approval, marketplace publisher/listing/review/install/revoke,
  entitlement, auditor identity, fee/contract boundary, and supply-chain
  security. Jangan menjadikan white-label sebagai bypass authorization.

**DoD:** isolation tests, publish/revoke, uninstall cleanup, signed package
  verification, audit, abuse controls, and operational support runbook lulus.

---

# H. P9 — Hardening dan GA

## TASK-23 — Security hardening, resilience, and GA readiness

**Status:** belum selesai; roadmap WP-22.  
**Prioritas:** P9, hanya setelah capability MVP dan expansion yang dipilih
  selesai.

### Pekerjaan

- Threat model diperbarui untuk seluruh trust boundary dan provider.
- Jalankan dependency audit, SAST, secret scan, and authorization regression.
- Uji load/performance, concurrency, queue saturation, provider throttling,
  database failover, backup/restore, and disaster recovery.
- Finalisasi centralized logging/telemetry dengan redaction dan retention.
- Tetapkan SLO/SLI/error budget, incident exercise, on-call rotation, and
  escalation.
- Jalankan accessibility, localization, browser/device, and data migration
  regression suite.
- Audit capability diff antara release dan registry.

### Definition of Done

Semua live capability memiliki proof yang belum expired, rollback/recovery
berhasil dalam drill, limitation/customer disclosure diperbarui, dan GA gate
ditandatangani owner yang ditentukan.

---

# I. Cross-cutting acceptance package untuk setiap task

Setiap task di atas belum boleh ditutup hanya dengan code merge. Tambahkan
artefak berikut ke completion dossier task tersebut:

1. **Requirement dan non-goal** dari PRD/roadmap.
2. **Actor, role, tenant scope**, dan permission matrix.
3. **Provider contract**: operation, permission, source revision, schema,
   timeout, retry, and rate limit.
4. **State machine** lengkap, termasuk terminal, stale, partial, error, dan
   recovery states.
5. **Error taxonomy** dan pemetaan response yang aman.
6. **Idempotency/concurrency**: dedupe key, lock/lease, replay, conflict,
   and transaction boundary.
7. **Data/evidence schema**, classification, retention, legal hold, and
   deletion semantics.
8. **Audit events** dengan actor, tenant, target, result, reason, correlation
   ID, and redaction.
9. **Test matrix**: unit, integration, contract, E2E, security, regression,
   accessibility, localization, performance, and provider-negative tests
   yang relevan.
10. **Operational proof**: metric, SLO, cost ceiling, alert, runbook,
    backup/restore, incident or recovery drill.
11. **CapabilityRecord** dan proof reference yang diperbarui.
12. **Customer limitation** yang menjelaskan apa yang belum diverifikasi.

# J. Urutan eksekusi yang disarankan

| Urutan | Task | Gate/hasil |
|---:|---|---|
| 1 | TASK-01 | Gate A ditutup atau limitation tetap eksplisit |
| 2 | TASK-02 | Identity live dan tenant auth terverifikasi |
| 3 | TASK-03 | Evidence storage WORM live terverifikasi |
| 4 | TASK-04 | Gate B: satu AWS control live |
| 5 | TASK-05 | Capability/provider truth dapat dipromosikan dengan aman |
| 6 | TASK-06 | Control coverage MVP tersedia |
| 7 | TASK-07 | Decision projection deterministik |
| 8 | TASK-08 | Remediation dan rescan end-to-end |
| 9 | TASK-09 | Customer dashboard/API parity |
| 10 | TASK-10 | Report signed dan deterministic |
| 11 | TASK-11 | Notification durable dan auditable |
| 12 | TASK-12 | Provider kedua nyata |
| 13 | TASK-13 | Operational beta dan SLO |
| 14 | TASK-14 | Billing sandbox dan entitlement |
| 15 | TASK-15 | Trust/auditor governance |
| 16 | TASK-16 | AI evidence-grounded assistant |
| 17–22 | TASK-17–22 | Expansion P2–P8 sesuai keputusan bisnis |
| 23 | TASK-23 | Hardening dan GA |

## Kesimpulan status saat ini

Repository belum dapat disebut selesai 100% real/complete. Pekerjaan yang
paling mendesak bukan menambah halaman, melainkan menutup bukti eksternal
TASK-01 sampai TASK-04. Setelah itu, jalur MVP yang belum dibangun adalah
decision projection, remediation, report, notification, provider kedua,
operational beta, billing sandbox, dan assistant. ISO, privacy, PCI,
white-label, marketplace, dan GA adalah expansion/hardening berikutnya, bukan
pengganti vertical slice MVP.