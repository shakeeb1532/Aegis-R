# BOTS Dataset Readiness

Date: 2026-03-12

## Summary

Aman is **not yet ready for direct scored validation against BOTS v1/v3**, but the first prerequisite is now in place.

This is not a core reasoning failure. It is a dataset-ingest mismatch:

- `botsv3` is primarily distributed as a pre-indexed Splunk dataset, not a neutral raw-event corpus.
- `botsv1` exposes JSON/CSV by sourcetype. Aman now has an initial `sysmon_json` adapter, but it still needs to be proven against real BOTS exports before scored validation would be credible.
- Attempting direct BOTS file retrieval from the public S3 links currently returns `403 Forbidden` from this environment, so an immediate automated ingest path was not available.

## What this means

BOTS is still useful later for:

- realism / noise validation
- mixed-source load testing
- thread and ticket behavior
- queue reduction studies

But it should not be used yet as a scored external benchmark until Aman has:

1. real BOTS v1 Windows/Sysmon exports flowing through the new adapter
2. stronger Windows auth/process-tree normalization
3. scoped contradiction support for those sources

## Current best external validation sources

Until those adapters exist, the most defensible external validation path is:

1. `splunk/attack_data` for technique reasoning validation
2. Aman mixed-event load tests for stress and memory behavior
3. later, BOTS for realism/noise once ingestion is ready
