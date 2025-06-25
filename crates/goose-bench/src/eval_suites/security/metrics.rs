use crate::eval_suites::EvalMetricValue;
use goose::security::content_scanner::ThreatLevel;

#[derive(Debug, Default)]
pub struct EvaluationMetrics {
    pub true_positives: i64,
    pub false_positives: i64,
    pub true_negatives: i64,
    pub false_negatives: i64,
    pub total_scan_time: f64,
    pub scan_errors: i64,
    pub total_cases: i64,
}

impl EvaluationMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_result(&mut self, detected_threat: bool, expected_threat: bool, scan_time: f64) {
        self.total_scan_time += scan_time;
        self.total_cases += 1;

        match (detected_threat, expected_threat) {
            (true, true) => self.true_positives += 1,
            (false, false) => self.true_negatives += 1,
            (true, false) => self.false_positives += 1,
            (false, true) => self.false_negatives += 1,
        }
    }

    pub fn record_error(&mut self) {
        self.scan_errors += 1;
        self.total_cases += 1;
    }

    pub fn accuracy(&self) -> f64 {
        if self.total_cases == 0 {
            return 0.0;
        }
        (self.true_positives + self.true_negatives) as f64 / self.total_cases as f64
    }

    pub fn precision(&self) -> f64 {
        let predicted_positive = self.true_positives + self.false_positives;
        if predicted_positive == 0 {
            return 0.0;
        }
        self.true_positives as f64 / predicted_positive as f64
    }

    pub fn recall(&self) -> f64 {
        let actual_positive = self.true_positives + self.false_negatives;
        if actual_positive == 0 {
            return 0.0;
        }
        self.true_positives as f64 / actual_positive as f64
    }

    pub fn f1_score(&self) -> f64 {
        let precision = self.precision();
        let recall = self.recall();
        if (precision + recall) == 0.0 {
            return 0.0;
        }
        2.0 * (precision * recall) / (precision + recall)
    }

    pub fn avg_scan_time(&self) -> f64 {
        if self.total_cases == 0 {
            return 0.0;
        }
        self.total_scan_time / self.total_cases as f64
    }

    pub fn to_eval_metrics(&self, config_name: &str) -> Vec<(String, EvalMetricValue)> {
        vec![
            (
                format!("{}_accuracy", config_name),
                EvalMetricValue::Float(self.accuracy()),
            ),
            (
                format!("{}_precision", config_name),
                EvalMetricValue::Float(self.precision()),
            ),
            (
                format!("{}_recall", config_name),
                EvalMetricValue::Float(self.recall()),
            ),
            (
                format!("{}_f1_score", config_name),
                EvalMetricValue::Float(self.f1_score()),
            ),
            (
                format!("{}_true_positives", config_name),
                EvalMetricValue::Integer(self.true_positives),
            ),
            (
                format!("{}_false_positives", config_name),
                EvalMetricValue::Integer(self.false_positives),
            ),
            (
                format!("{}_true_negatives", config_name),
                EvalMetricValue::Integer(self.true_negatives),
            ),
            (
                format!("{}_false_negatives", config_name),
                EvalMetricValue::Integer(self.false_negatives),
            ),
            (
                format!("{}_avg_scan_time", config_name),
                EvalMetricValue::Float(self.avg_scan_time()),
            ),
            (
                format!("{}_scan_errors", config_name),
                EvalMetricValue::Integer(self.scan_errors),
            ),
            (
                format!("{}_total_test_cases", config_name),
                EvalMetricValue::Integer(self.total_cases),
            ),
        ]
    }
}

pub fn is_threat(threat_level: &ThreatLevel) -> bool {
    !matches!(threat_level, ThreatLevel::Safe)
}
