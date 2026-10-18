# Cross-Dataset Generalization & Transfer Analysis

## 1. Domain Incompatibility Audit

- **NSL-KDD:** 41 connection attributes derived from KDD Cup 99 simulated LAN topology.
- **UNSW-NB15:** 42 hybrid window metrics synthesized using IXIA PerfectStorm.
- **CICIDS2017:** 78 statistical flow distributions extracted via CICFlowMeter.
- **Exact Column Name Overlap:**
  - NSL-KDD vs UNSW-NB15: 1 direct column matches
  - NSL-KDD vs CICIDS2017: 0 direct column matches

## 2. Empirical Cross-Domain Transfer Experiment

A Random Forest classifier was trained on normalized common flow features (`duration`, `src_bytes`, `dst_bytes`, `count`) using NSL-KDD, then evaluated on both in-domain test data and cross-domain UNSW-NB15 traffic:

| Evaluation Environment | Accuracy | Binary F1 Score | Performance Delta |
|---|---:|---:|---:|
| **In-Domain (NSL-KDD Test)** | 0.9786 | 0.9768 | Baseline |
| **Cross-Domain Transfer (UNSW-NB15)** | 0.0215 | 0.0199 | **F1 Drop: -0.9568** |

## 3. Engineering Conclusion

The empirical transfer experiment demonstrates that direct cross-dataset feature transfer suffers from severe distribution shift and performance degradation. As required by high-assurance MLOps principles, Sentinel IDS enforces **dataset-specific feature pipelines** rather than naive feature concatenation.
