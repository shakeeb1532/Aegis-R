.PHONY: demo reviewer-demo readiness demo-pack roi pilot-metrics

demo:
	./scripts/demo.sh

reviewer-demo:
	bash ./docs/reviewer_demo/run_demo.sh

readiness:
	go run ./cmd/aman system integration-readiness --strict --min-events 1 --min-feasible 0 -rules data/rules.json -out docs/integration_readiness.json

demo-pack:
	go run ./cmd/aman system demo-pack -outdir docs/demo_pack -rules data/rules.json

pilot-metrics:
	go run ./cmd/aman system pilot-metrics -report data/bench/report.json -history data/incident_history.json -format json -out docs/pilot_metrics_report.json

roi: readiness pilot-metrics
	go run ./cmd/aman system roi-scorecard -pilot docs/pilot_metrics_report.json -integration docs/integration_readiness.json -benchmark docs/production_benchmark_report.md -out docs/roi_scorecard.md
