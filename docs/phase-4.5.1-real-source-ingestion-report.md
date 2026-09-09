# Phase 4.5.1: Real Source Ingestion Report

A. **Source filename**: `الطب النبوي لابن القيم_260908_112010.docx`
B. **Source type**: DOCX
C. **SHA-256**: `b12597a1643b6761e0cb6bb4d520eb31ed51d99aa24a1a1f43a4d5944442beab`
D. **Title**: الطب النبوي
E. **Author**: ابن قيم الجوزية
F. **Available metadata**: Only Title and Author could be reliably detected without inventing data. (Publisher, Year, Edition are marked `NULL`).
G. **Extraction method**: Deterministic Node script utilizing `mammoth` (`extractRawText()`), splitting chunks safely on double-newlines and detecting headers via regex `/^(?:فصل|فَصْلٌ?|فصل:|فصل\s+)\s*(?:في|فِي)?\s*(.*)/i`.
H. **Number of sections**: 174
I. **Number of paragraphs**: 3773
J. **Number of chunks**: 3773
K. **Page/provenance coverage**: 0 printed page mappings. (While page markers exist in the document styling like `(371/7)`, deterministic parsing from plain-text output could not safely extract them without risking false citations, so they default to `NULL`.)
L. **Extraction anomalies**: The first metadata block appears slightly reversed due to the document's internal text-direction formatting, but the primary text body's Arabic was extracted with flawless encoding and sequencing.
M. **Verification status**: All chunks strictly ingested as `unverified`. `reviewed_arabic_text` remains exclusively `NULL`.
N. **Duplicate/idempotency result**: Passed. The pipeline hashes the artifact and accurately throws an idempotency `Duplicate source` exception if re-run.
O. **Migration execution result**: **FAILED**. (The `npx supabase db push` and `npx supabase start` commands failed because `docker` is not installed on the system, preventing the local Supabase container from running).
P. **RLS verification result**: Skipped on real DB (due to migration failure), but policies are rigidly defined in the SQL schema.
Q. **Database verification result**: Ingestion against the `MockSupabaseKnowledgeBase` transaction script passed perfectly with exact metrics. Real Supabase DB insertion skipped pending Docker availability.
R. **Test results**: Passed. `ingest.test.ts` successfully asserts DOCX parsing, duplicate blocking, Arabic integrity, sequence mapping, and correct defaults.
S. **Lint result**: Passed. 
T. **Typecheck result**: Passed.
U. **Build result**: Passed.
V. **Limitations**:
   1. The lack of a local Docker instance prevents end-to-end execution of the DB migration.
   2. Page number extraction was intentionally disabled to prefer `NULL` over generating false citations.
W. **Exact files changed**: 
   - `src/lib/knowledge/ingest.ts` (added DOCX parsing logic)
   - `src/lib/knowledge/ingest.test.ts` (updated to run against real DOCX)
   - `scripts/do-ingest.ts` (added to generate metrics)
   - `docs/phase-4.5.1-real-source-ingestion-report.md`
X. **Any unresolved issues**: The live Database remains unpopulated until it is run in an environment with Docker or linked to a remote Supabase project.

*Note: The secondary document `tibb-nabawi-disease-remedy-reference.docx` was identified but intentionally ignored per the Phase 4.5.1 constraint to only use the Arabic primary source.*
