# CICIDS2017 Independent Evaluation Report

**Dataset:** CICIDS2017
**Model:** Random Forest (100 Trees, `class_weight='balanced_subsample'`, Random State 42)
**Partition:** Stratified 80/20 Holdout (80000 train, 57294 test)

## Summary Metrics

| Metric | Value |
|---|---:|
| **Overall Accuracy** | 0.9999 |
| **Binary Precision** | 1.0000 |
| **Binary Recall** | 0.9998 |
| **Binary F1 Score** | 0.9999 |
| **False Positive Rate (FPR)** | 0.0000 |
| **Binary ROC-AUC** | 1.0000 |
| **Binary PR-AUC** | 1.0000 |
| **Macro F1 Score** | 0.9999 |
| **Balanced Accuracy** | 0.9999 |
| **Inference Throughput** | 337023.5 samples/sec |

## Per-Class Performance

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| **Normal** | 0.9998 | 1.0000 | 0.9999 | 25508 |
| **Probe** | 1.0000 | 0.9998 | 0.9999 | 31786 |

## Confusion Matrix

Labels (rows=true, cols=pred): `['Normal', 'Probe']`

```text
[[25508,     0],
 [    6, 31780]]
```

## Duplicate and Data Quality Audit

- **Total CSV Rows:** 286,467
- **Exact Duplicate Rows:** 72,353 (25.26% of dataset)
- **Unique Flow Records:** 214,114

### Deduplicated Holdout Verification:
When the model is re-evaluated exclusively on deduplicated rows to eliminate identical record leakage:
- **Deduplicated Accuracy (with Port):** 0.999883 (FPR: 0.000000, ROC-AUC: 0.999945)
- **Deduplicated Accuracy (excluding Port):** 0.999883 (FPR: 0.000000, ROC-AUC: 0.999945)

### Why PortScan Scores Are Near-Perfect:
1. Automated port scan generators (e.g. Nmap SYN scans) generate single-packet forward probes with 0 backward packets, minimal flow duration, and uniform packet lengths.
2. In contrast, benign background traffic comprises rich bidirectional exchanges (HTTP/HTTPS/DNS) with substantial backward byte flows.
3. The near-perfect scores reflect the synthetic homogeneity of the test environment rather than a silver bullet for real-world stealthy scans.

## Reproduction Command

```powershell
python scripts/train_dataset_models.py --dataset cicids2017
```
