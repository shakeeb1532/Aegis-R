# BOTS Dataset Readiness

Date: 2026-03-11

## Summary

Aman is **not yet ready for direct scored validation against BOTS v1/v3**.

This is not a core reasoning failure. It is a dataset-ingest mismatch:

- `botsv3` is primarily distributed as a pre-indexed Splunk dataset, not a neutral raw-event corpus.
- `botsv1` exposes JSON/CSV by sourcetype, but Aman does not yet have a Windows/Sysmon/Splunk-export normalization path strong enough to score it honestly.
- Attempting direct BOTS file retrieval from the public S3 links currently returns `403 Forbidden` from this environment, so an immediate automated ingest path was not available.

## What this means

BOTS is still useful later for:

- realism / noise validation
- mixed-source load testing
- thread and ticket behavior
- queue reduction studies

But it should not be used yet as a scored external benchmark until Aman has:

1. a Windows/Sysmon adapter or a Splunk-export adapter
2. stronger auth/process-tree normalization
3. scoped contradiction support for those sources

## Current best external validation sources

Until those adapters exist, the most defensible external validation path is:

1. `splunk/attack_data` for technique reasoning validation
2. Aman mixed-event load tests for stress and memory behavior
3. later, BOTS for realism/noise once ingestion is ready
