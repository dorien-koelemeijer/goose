use crate::bench_session::BenchAgent;
use crate::bench_work_dir::BenchmarkWorkDir;
use crate::eval_suites::security::{
    dataset_loader::PromptInjectionDatasetLoader,
    metrics::{EvaluationMetrics, is_threat},
    scanner_configs::ScannerConfig,
};
use crate::eval_suites::{EvalMetricValue, Evaluation, ExtensionRequirements};
use crate::register_evaluation;
use anyhow::Result;
use async_trait::async_trait;
use goose::security::SecurityManager;
use mcp_core::Content;
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::Instant;

#[derive(Debug, Deserialize, Serialize)]
pub struct PromptInjectionTestCase {
    pub id: String,
    pub input: String,
    pub expected_threat_level: goose::security::content_scanner::ThreatLevel,
    pub category: String,
    pub description: String,
    pub source: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PromptInjectionTestSuite {
    pub test_cases: Vec<PromptInjectionTestCase>,
}

pub struct PromptInjectionDetectionEval {
    test_suite: PromptInjectionTestSuite,
    scanner_configs: Vec<ScannerConfig>,
}

impl PromptInjectionDetectionEval {
    pub fn new() -> Self {
        let test_suite = Self::load_test_suite();
        let scanner_configs = ScannerConfig::get_all_configs();

        Self {
            test_suite,
            scanner_configs,
        }
    }

    fn load_test_suite() -> PromptInjectionTestSuite {
        match PromptInjectionDatasetLoader::load_comprehensive_dataset() {
            Ok(suite) => {
                println!("✅ Loaded {} test cases", suite.test_cases.len());
                suite
            }
            Err(e) => {
                eprintln!("⚠️  Failed to load test dataset: {}", e);
                eprintln!("   Using empty dataset for evaluation");
                PromptInjectionTestSuite { test_cases: vec![] }
            }
        }
    }

    async fn evaluate_scanner(&self, config: &ScannerConfig) -> Result<EvaluationMetrics> {
        println!("🔍 Testing: {}", config.name);
        
        let security_manager = SecurityManager::new(config.config.clone());
        let mut metrics = EvaluationMetrics::new();

        if !security_manager.is_enabled() {
            println!("❌ Scanner not enabled: {}", config.name);
            return Ok(metrics);
        }

        for (i, test_case) in self.test_suite.test_cases.iter().enumerate() {
            if i % 25 == 0 {
                println!("   Progress: {}/{}", i, self.test_suite.test_cases.len());
            }

            let start_time = Instant::now();
            let content = vec![Content::text(&test_case.input)];

            match security_manager.scan_content(&content).await {
                Ok(Some(scan_result)) => {
                    let scan_time = start_time.elapsed().as_secs_f64();
                    let detected_threat = is_threat(&scan_result.threat_level);
                    let expected_threat = is_threat(&test_case.expected_threat_level);
                    
                    metrics.record_result(detected_threat, expected_threat, scan_time);
                }
                Ok(None) => {
                    // Scanner disabled - treat as no threat detected
                    let scan_time = start_time.elapsed().as_secs_f64();
                    let expected_threat = is_threat(&test_case.expected_threat_level);
                    metrics.record_result(false, expected_threat, scan_time);
                }
                Err(e) => {
                    eprintln!("   Error on test {}: {}", test_case.id, e);
                    metrics.record_error();
                }
            }
        }

        self.print_summary(&config.name, &metrics);
        Ok(metrics)
    }

    fn print_summary(&self, config_name: &str, metrics: &EvaluationMetrics) {
        println!("📊 Results for {}:", config_name);
        println!("   Accuracy:  {:.1}%", metrics.accuracy() * 100.0);
        println!("   Precision: {:.1}%", metrics.precision() * 100.0);
        println!("   Recall:    {:.1}%", metrics.recall() * 100.0);
        println!("   F1 Score:  {:.3}", metrics.f1_score());
        println!("   Avg Time:  {:.3}s", metrics.avg_scan_time());
        println!("   Errors:    {}", metrics.scan_errors);
        println!();
        println!("   📈 Confusion Matrix:");
        println!("      True Positives:  {} (correctly detected threats)", metrics.true_positives);
        println!("      False Positives: {} (false alarms)", metrics.false_positives);
        println!("      True Negatives:  {} (correctly identified safe content)", metrics.true_negatives);
        println!("      False Negatives: {} (missed threats)", metrics.false_negatives);
        println!("      Total Cases:     {}", metrics.total_cases);
        println!();
    }

    fn save_detailed_results(
        &self,
        run_loc: &BenchmarkWorkDir,
        all_metrics: &[(String, EvalMetricValue)],
    ) -> Result<()> {
        let results_path = run_loc.base_path.join("prompt_injection_results.json");
        
        let detailed_results = serde_json::json!({
            "test_suite": self.test_suite,
            "scanner_configs": self.scanner_configs.iter().map(|c| &c.name).collect::<Vec<_>>(),
            "metrics": all_metrics
        });

        fs::write(&results_path, serde_json::to_string_pretty(&detailed_results)?)?;
        println!("💾 Detailed results saved to: {:?}", results_path);
        
        Ok(())
    }
}

#[async_trait]
impl Evaluation for PromptInjectionDetectionEval {
    async fn run(
        &self,
        _agent: &mut BenchAgent,
        run_loc: &mut BenchmarkWorkDir,
    ) -> Result<Vec<(String, EvalMetricValue)>> {
        println!("🚀 Starting Prompt Injection Detection Evaluation");
        println!("📋 Testing {} configurations on {} test cases", 
                 self.scanner_configs.len(), 
                 self.test_suite.test_cases.len());
        println!();

        let mut all_metrics = Vec::new();

        for config in &self.scanner_configs {
            match self.evaluate_scanner(config).await {
                Ok(metrics) => {
                    all_metrics.extend(metrics.to_eval_metrics(&config.name));
                }
                Err(e) => {
                    eprintln!("❌ Error evaluating {}: {}", config.name, e);
                    all_metrics.push((
                        format!("{}_config_error", config.name),
                        EvalMetricValue::String(e.to_string()),
                    ));
                }
            }
        }

        self.save_detailed_results(run_loc, &all_metrics)?;
        println!("✅ Prompt Injection Detection Evaluation completed");

        Ok(all_metrics)
    }

    fn name(&self) -> &str {
        "prompt_injection_detection"
    }

    fn required_extensions(&self) -> ExtensionRequirements {
        ExtensionRequirements::default()
    }
}

register_evaluation!(PromptInjectionDetectionEval);