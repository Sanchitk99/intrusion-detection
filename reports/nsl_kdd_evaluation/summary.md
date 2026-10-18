# NSL_KDD Independent Evaluation Report

**Dataset:** NSL-KDD
**Model:** Random Forest (100 Trees, `class_weight='balanced_subsample'`, Random State 42)
**Partition:** Stratified 80/20 Holdout (80000 train, 29704 test)

## Summary Metrics

| Metric | Value |
|---|---:|
| **Overall Accuracy** | 0.9946 |
| **Binary Precision** | 0.9952 |
| **Binary Recall** | 0.9938 |
| **Binary F1 Score** | 0.9945 |
| **False Positive Rate (FPR)** | 0.0045 |
| **Binary ROC-AUC** | 0.9998 |
| **Binary PR-AUC** | 0.9998 |
| **Macro F1 Score** | 0.7539 |
| **Balanced Accuracy** | 0.8826 |
| **Inference Throughput** | 194143.8 samples/sec |

## Per-Class Performance

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| **DoS** | 0.9990 | 0.9994 | 0.9992 | 10677 |
| **Normal** | 0.9943 | 0.9955 | 0.9949 | 15411 |
| **Other** | 0.0000 | 0.0000 | 0.0000 | 0 |
| **Probe** | 0.9940 | 0.9954 | 0.9947 | 2816 |
| **R2L** | 0.9471 | 0.9227 | 0.9347 | 776 |
| **U2R** | 0.7500 | 0.5000 | 0.6000 | 24 |

## Confusion Matrix

Labels (rows=true, cols=pred): `['DoS', 'Normal', 'Other', 'Probe', 'R2L', 'U2R']`

```text
[[10671,     5,     0,     1,     0,     0],
 [   11, 15342,     0,    16,    40,     2],
 [    0,     0,     0,     0,     0,     0],
 [    0,    13,     0,  2803,     0,     0],
 [    0,    58,     0,     0,   716,     2],
 [    0,    12,     0,     0,     0,    12]]
```

## Reproduction Command

```powershell
python scripts/train_dataset_models.py --dataset nsl_kdd
```
