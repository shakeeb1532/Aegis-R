# Demo Pack

This folder contains curated demo datasets and expected noise-reduction results.

## Datasets
- `demo/data/webapp.log` (plain text)
- `demo/data/kubernetes.jsonl` (JSONL)
- `demo/data/cloudtrail.jsonl` (JSONL)

Note: These datasets are regenerated on each demo run for fresh variation.

## Policy Example
- `demo/policy.example.yaml`

## Expected Results (default config)
These were generated with:
```bash
python3 scripts/eval_noise_reduction.py --input <file> --format <plain|jsonl> --max-lines 5000 -b 200
```

### Web App (5,000 lines)
- Noise reduction: **99.5%**
- Signal rate: **0.5%**

### Kubernetes (5,000 lines)
- Noise reduction: **96.9%**
- Signal rate: **3.1%**

### CloudTrail (5,000 lines)
- Noise reduction: **43.1%**
- Signal rate: **56.9%**

Notes:
- CloudTrail-like logs are inherently more novel and will have lower suppression.
- For infra logs (webapp/kube), suppression stays high due to repetition.
