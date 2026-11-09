# Development field/context experiment — measured results, 4 November 2026

**Status: exploratory development evidence. This is not an exact GTAE reproduction, a proven improvement, or an independent generalization test.**

Twenty-four independent reconstruction fits completed: raw/masked header × self/past context × p2/p8 × three seeds, fixed 20 epochs. Twelve simple Isolation Forest controls use the same identities and packet vectors. Each neural arm fits an Isolation Forest on its benign train2 embeddings. The declared 1%/5% settings are benign-validation quantiles, not guaranteed operational false-alert rates.

## Frozen population and causal input checks

Selected benign targets: 128 train1, 106 train2, 139 validation, 100 test. Test attacks: 100 DDoS, 100 Slowloris, 10 FTP; all targets have eight observed packets, so p2/p8 use identical IDs.

Masked-p2 feature groups do not cross target fitting, validation and test partitions. The Monday capture was split by chronological target-start quantiles; p8 completion had to remain in its stage window. Repeating masked-p2 groups were retained only in their earliest stage. Test attack classes were capped by fixed identity hash before scores. Each decision uses all observed sessions in its capture, without a label/split/final-length context filter.

Physical PCAP record indices and a running timestamp maximum over every raw record fix availability and recency. Every selected decision was rebuilt from its truncated visible history; all raw/masked and self/past graph tensors matched the full-history cutoff construction. Source IDs, code hashes, target IDs, graph receipts, histories and scores are saved beside this report.

| Population | Eligible before group filter | Retained | Selected | Selected masked-p2 groups |
|---|---:|---:|---:|---:|
| benign train1 | 832 | 832 | 128 | 56 |
| benign train2 | 409 | 106 | 106 | 32 |
| benign validation | 417 | 139 | 139 | 55 |
| benign test | 422 | 104 | 100 | 30 |
| DDoS | 2202 | — | 100 | 1 |
| DoS Slowloris | 276 | — | 100 | 2 |
| FTP-Patator | 10 | — | 10 | 1 |

## Conditional prefix results at nominal 1% validation budget

Values are mean [minimum, maximum] across the three fixed model seeds. Seed ranges are not confidence intervals. Attack TPR averages the declared 210 selected attacks; benign FPR uses 100 selected benign flows.

| p | Representation / context | Attack TPR % | Benign FPR % |
|---:|---|---:|---:|
| 2 | raw / self | 3.49 [0.00, 6.67] | 0.67 [0.00, 2.00] |
| 2 | raw / past | 8.41 [1.43, 19.52] | 1.33 [0.00, 3.00] |
| 2 | mask / self | 0.00 [0.00, 0.00] | 0.00 [0.00, 0.00] |
| 2 | mask / past | 0.00 [0.00, 0.00] | 0.00 [0.00, 0.00] |
| 2 | raw / tabular | 2.70 [0.00, 5.71] | 0.33 [0.00, 1.00] |
| 2 | mask / tabular | 0.00 [0.00, 0.00] | 0.00 [0.00, 0.00] |
| 8 | raw / self | 35.56 [0.95, 52.86] | 4.00 [3.00, 5.00] |
| 8 | raw / past | 42.06 [21.90, 53.33] | 5.33 [3.00, 9.00] |
| 8 | mask / self | 7.14 [0.00, 21.43] | 0.33 [0.00, 1.00] |
| 8 | mask / past | 17.46 [0.00, 52.38] | 2.67 [0.00, 7.00] |
| 8 | raw / tabular | 52.38 [52.38, 52.38] | 0.67 [0.00, 1.00] |
| 8 | mask / tabular | 0.00 [0.00, 0.00] | 0.00 [0.00, 0.00] |

## Conditional prefix results at nominal 5% validation budget

Values are mean [minimum, maximum] across the three fixed model seeds. Seed ranges are not confidence intervals. Attack TPR averages the declared 210 selected attacks; benign FPR uses 100 selected benign flows.

| p | Representation / context | Attack TPR % | Benign FPR % |
|---:|---|---:|---:|
| 2 | raw / self | 25.56 [24.29, 26.19] | 8.00 [8.00, 8.00] |
| 2 | raw / past | 24.29 [20.95, 26.19] | 6.67 [2.00, 10.00] |
| 2 | mask / self | 0.00 [0.00, 0.00] | 31.00 [3.00, 45.00] |
| 2 | mask / past | 0.00 [0.00, 0.00] | 32.00 [1.00, 50.00] |
| 2 | raw / tabular | 10.16 [0.00, 26.19] | 2.67 [0.00, 8.00] |
| 2 | mask / tabular | 0.00 [0.00, 0.00] | 0.00 [0.00, 0.00] |
| 8 | raw / self | 53.49 [52.86, 54.76] | 11.33 [9.00, 15.00] |
| 8 | raw / past | 53.49 [52.38, 55.24] | 16.00 [11.00, 24.00] |
| 8 | mask / self | 17.62 [0.00, 52.86] | 6.00 [0.00, 9.00] |
| 8 | mask / past | 31.11 [0.95, 52.86] | 10.67 [2.00, 20.00] |
| 8 | raw / tabular | 52.38 [52.38, 52.38] | 5.00 [2.00, 9.00] |
| 8 | mask / tabular | 36.51 [4.76, 52.38] | 0.67 [0.00, 2.00] |

## Interpretation limits

All benign rows are from a Monday prefix and all attack labels from bounded later-day samples. Labels are reused schedule/endpoint-derived development labels rather than independently joined provider CSV labels. Differences can reflect capture conditions. DDoS test flows represent only one masked-p2 signature; they are not 100 independent signatures. The validation set has 139 rows from 55 masked-p2 groups, so 1% is a coarse calibration target. Group filtering substantially changes cohort coverage.

The neural models are a target-edge reconstruction adaptation with one IF detector, not the source four-detector GTAE ensemble. Context and field arms have identical declared target IDs, architectures, fit budgets and seeds. The result supports local mechanism diagnostics only. Prefix metrics are conditional on matched p8 eligibility and a capped case-control sample; they are not all-flow opportunity recall, multi-prefix first-alert performance, calibrated deployment precision, or attack-onset detection.

No winner was selected or retuned after test scoring. Test labels/features defined the fixed class caps and input checks; only test scores were withheld until the manifest and invariants were fixed. The metadata phrase `test_opened_after_manifest_and_invariant_checks` refers to test scores, not previously unobserved labels. Full-source verification and independent transfer remain pending.

The original runner omitted validation-score export. `recover_calibration.py` recovered it through frozen neural checkpoints and deterministic IF reconstruction, with no neural refit or selection. All 11,160 test scores and 72 thresholds/counts match exactly. The archive now includes 5,004 validation scores, detectors and embeddings, with hashes in `calibration-recovery.json`.

## Reproduce

From FYP:

```sh
GTAE/.venv/bin/python GTAE-Improvement-Paper-2026-11-03/experiments/field_context.py extract
GTAE/.venv/bin/python GTAE-Improvement-Paper-2026-11-03/experiments/run_factorial.py prepare
GTAE/.venv/bin/python GTAE-Improvement-Paper-2026-11-03/experiments/run_factorial.py run
GTAE/.venv/bin/python GTAE-Improvement-Paper-2026-11-03/experiments/summarize_factorial.py
```

The saved completed output should be inspected before rerunning; source/capture hashes are enforced. Local timing describes this small CPU experiment and is not a packet-throughput claim.
