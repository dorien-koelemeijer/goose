use crate::bench_session::BenchAgent;
use crate::bench_work_dir::BenchmarkWorkDir;
use crate::eval_suites::{EvalMetricValue, Evaluation, ExtensionRequirements};
use crate::register_evaluation;
use anyhow::Result;
use async_trait::async_trait;
use goose::security::{SecurityManager, config::{SecurityConfig, ScannerType, ActionPolicy, ThreatThreshold}};
use goose::security::content_scanner::ThreatLevel;
use mcp_core::Content;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use std::fs;

#[derive(Debug, Deserialize, Serialize)]
pub struct PromptInjectionTestCase {
    pub id: String,
    pub input: String,
    pub expected_threat_level: ThreatLevel,
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

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub name: String,
    pub config: SecurityConfig,
}

impl PromptInjectionDetectionEval {
    pub fn new() -> Self {
        // Load comprehensive test suite from multiple sources
        let test_suite = match super::dataset_loader::PromptInjectionDatasetLoader::load_comprehensive_dataset() {
            Ok(suite) => suite,
            Err(e) => {
                eprintln!("Warning: Failed to load comprehensive dataset: {}. Using empty dataset.", e);
                PromptInjectionTestSuite { test_cases: vec![] }
            }
        };
        
        // Define different scanner configurations to test
        let scanner_configs = vec![
            // // Mistral Nemo configurations
            // ScannerConfig {
            //     name: "mistral-nemo-block-medium".to_string(),
            //     config: SecurityConfig {
            //         enabled: true,
            //         scanner_type: ScannerType::MistralNemo,
            //         ollama_endpoint: "http://localhost:11434".to_string(),
            //         action_policy: ActionPolicy::Block,
            //         scan_threshold: ThreatThreshold::Medium,
            //     },
            // },
            // ScannerConfig {
            //     name: "mistral-nemo-block-low".to_string(),
            //     config: SecurityConfig {
            //         enabled: true,
            //         scanner_type: ScannerType::MistralNemo,
            //         ollama_endpoint: "http://localhost:11434".to_string(),
            //         action_policy: ActionPolicy::Block,
            //         scan_threshold: ThreatThreshold::Low,
            //     },
            // },
            // ScannerConfig {
            //     name: "mistral-nemo-sanitize-medium".to_string(),
            //     config: SecurityConfig {
            //         enabled: true,
            //         scanner_type: ScannerType::MistralNemo,
            //         ollama_endpoint: "http://localhost:11434".to_string(),
            //         action_policy: ActionPolicy::Sanitize,
            //         scan_threshold: ThreatThreshold::Medium,
            //     },
            // },
            
            // // Prompt Injection Detection Model configurations (working model)
            // ScannerConfig {
            //     name: "prompt-injection-model-block-medium".to_string(),
            //     config: SecurityConfig {
            //         enabled: true,
            //         scanner_type: ScannerType::LlamaPromptGuard,
            //         ollama_endpoint: "".to_string(), // Not used for this model
            //         action_policy: ActionPolicy::Block,
            //         scan_threshold: ThreatThreshold::Medium,
            //     },
            // },
            // ScannerConfig {
            //     name: "prompt-injection-model-block-low".to_string(),
            //     config: SecurityConfig {
            //         enabled: true,
            //         scanner_type: ScannerType::LlamaPromptGuard,
            //         ollama_endpoint: "".to_string(), // Not used for this model
            //         action_policy: ActionPolicy::Block,
            //         scan_threshold: ThreatThreshold::Low,
            //     },
            // },
            // ScannerConfig {
            //     name: "prompt-injection-model-sanitize-medium".to_string(),
            //     config: SecurityConfig {
            //         enabled: true,
            //         scanner_type: ScannerType::LlamaPromptGuard,
            //         ollama_endpoint: "".to_string(), // Not used for this model
            //         action_policy: ActionPolicy::Sanitize,
            //         scan_threshold: ThreatThreshold::Medium,
            //     },
            // },
            
            // Llama Prompt Guard 2 configurations - requires HF token
            ScannerConfig {
                name: "llama-prompt-guard2-block-medium".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::LlamaPromptGuard2,
                    ollama_endpoint: "".to_string(), // Not used for this model
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                },
            },
            ScannerConfig {
                name: "llama-prompt-guard2-block-low".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::LlamaPromptGuard2,
                    ollama_endpoint: "".to_string(), // Not used for this model
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Low,
                },
            },
            ScannerConfig {
                name: "llama-prompt-guard2-sanitize-medium".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::LlamaPromptGuard2,
                    ollama_endpoint: "".to_string(), // Not used for this model
                    action_policy: ActionPolicy::Sanitize,
                    scan_threshold: ThreatThreshold::Medium,
                },
            },
        ];

        Self {
            test_suite,
            scanner_configs,
        }
    }

    async fn test_scanner_config(
        &self,
        config: &ScannerConfig,
    ) -> Result<Vec<(String, EvalMetricValue)>> {
        let security_manager = SecurityManager::new(config.config.clone());
        
        if !security_manager.is_enabled() {
            return Ok(vec![
                (format!("{}_enabled", config.name), EvalMetricValue::Boolean(false)),
                (format!("{}_error", config.name), EvalMetricValue::String("Scanner not enabled".to_string())),
            ]);
        }

        let mut metrics = Vec::new();
        let mut true_positives = 0;
        let mut false_positives = 0;
        let mut true_negatives = 0;
        let mut false_negatives = 0;
        let mut total_scan_time = 0.0;
        let mut scan_errors = 0;

        for test_case in &self.test_suite.test_cases {
            let start_time = Instant::now();
            
            let content = vec![Content::text(&test_case.input)];
            
            match security_manager.scan_content(&content).await {
                Ok(Some(scan_result)) => {
                    let scan_time = start_time.elapsed().as_secs_f64();
                    total_scan_time += scan_time;

                    // Classify the result
                    let detected_as_threat = scan_result.threat_level != ThreatLevel::Safe;
                    let expected_as_threat = test_case.expected_threat_level != ThreatLevel::Safe;

                    match (detected_as_threat, expected_as_threat) {
                        (true, true) => true_positives += 1,
                        (false, false) => true_negatives += 1,
                        (true, false) => false_positives += 1,
                        (false, true) => false_negatives += 1,
                    }

                    // Log individual test case results
                    metrics.push((
                        format!("{}_{}_detected_level", config.name, test_case.id),
                        EvalMetricValue::String(format!("{:?}", scan_result.threat_level)),
                    ));
                    
                    metrics.push((
                        format!("{}_{}_scan_time", config.name, test_case.id),
                        EvalMetricValue::Float(scan_time),
                    ));
                }
                Ok(None) => {
                    // Scanner disabled
                    metrics.push((
                        format!("{}_{}_result", config.name, test_case.id),
                        EvalMetricValue::String("scanner_disabled".to_string()),
                    ));
                }
                Err(e) => {
                    scan_errors += 1;
                    metrics.push((
                        format!("{}_{}_error", config.name, test_case.id),
                        EvalMetricValue::String(e.to_string()),
                    ));
                }
            }
        }

        // Calculate aggregate metrics
        let total_cases = self.test_suite.test_cases.len() as f64;
        let accuracy = (true_positives + true_negatives) as f64 / total_cases;
        let precision = if (true_positives + false_positives) > 0 {
            true_positives as f64 / (true_positives + false_positives) as f64
        } else {
            0.0
        };
        let recall = if (true_positives + false_negatives) > 0 {
            true_positives as f64 / (true_positives + false_negatives) as f64
        } else {
            0.0
        };
        let f1_score = if (precision + recall) > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            0.0
        };

        // Add aggregate metrics
        metrics.extend(vec![
            (format!("{}_accuracy", config.name), EvalMetricValue::Float(accuracy)),
            (format!("{}_precision", config.name), EvalMetricValue::Float(precision)),
            (format!("{}_recall", config.name), EvalMetricValue::Float(recall)),
            (format!("{}_f1_score", config.name), EvalMetricValue::Float(f1_score)),
            (format!("{}_true_positives", config.name), EvalMetricValue::Integer(true_positives)),
            (format!("{}_false_positives", config.name), EvalMetricValue::Integer(false_positives)),
            (format!("{}_true_negatives", config.name), EvalMetricValue::Integer(true_negatives)),
            (format!("{}_false_negatives", config.name), EvalMetricValue::Integer(false_negatives)),
            (format!("{}_avg_scan_time", config.name), EvalMetricValue::Float(total_scan_time / total_cases)),
            (format!("{}_scan_errors", config.name), EvalMetricValue::Integer(scan_errors)),
            (format!("{}_total_test_cases", config.name), EvalMetricValue::Integer(total_cases as i64)),
        ]);

        Ok(metrics)
    }
}

#[async_trait]
impl Evaluation for PromptInjectionDetectionEval {
    async fn run(
        &self,
        _agent: &mut BenchAgent,
        run_loc: &mut BenchmarkWorkDir,
    ) -> Result<Vec<(String, EvalMetricValue)>> {
        println!("Running Prompt Injection Detection Evaluation");
        
        let mut all_metrics = Vec::new();

        // Test each scanner configuration
        for config in &self.scanner_configs {
            println!("Testing scanner configuration: {}", config.name);
            
            match self.test_scanner_config(config).await {
                Ok(mut metrics) => {
                    all_metrics.append(&mut metrics);
                }
                Err(e) => {
                    println!("Error testing config {}: {}", config.name, e);
                    all_metrics.push((
                        format!("{}_config_error", config.name),
                        EvalMetricValue::String(e.to_string()),
                    ));
                }
            }
        }

        // Save detailed results to file
        let results_path = run_loc.base_path.join("prompt_injection_results.json");
        let detailed_results = serde_json::json!({
            "test_suite": self.test_suite,
            "scanner_configs": self.scanner_configs.iter().map(|c| &c.name).collect::<Vec<_>>(),
            "metrics": all_metrics.iter().map(|(k, v)| (k, v)).collect::<Vec<_>>()
        });
        
        fs::write(&results_path, serde_json::to_string_pretty(&detailed_results)?)?;
        
        println!("Detailed results saved to: {:?}", results_path);
        println!("Prompt Injection Detection Evaluation completed");

        Ok(all_metrics)
    }

    fn name(&self) -> &str {
        "prompt_injection_detection"
    }

    fn required_extensions(&self) -> ExtensionRequirements {
        ExtensionRequirements::default() // No specific extensions required
    }
}

register_evaluation!(PromptInjectionDetectionEval);