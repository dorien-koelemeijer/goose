use goose::security::config::{ActionPolicy, ScannerType, SecurityConfig, ThreatThreshold};

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub name: String,
    pub config: SecurityConfig,
}

impl ScannerConfig {
    pub fn get_all_configs() -> Vec<ScannerConfig> {
        // Use fast config for now - just one model for speed
        Self::get_fast_configs()
    }

    /// Quick testing with just the fastest model
    pub fn get_fast_configs() -> Vec<ScannerConfig> {
        vec![
            ScannerConfig {
                name: "protectai-deberta-block-medium".to_string(),
                config: SecurityConfig {
                    enabled: true,
                    scanner_type: ScannerType::ProtectAiDeberta,
                    ollama_endpoint: "".to_string(),
                    action_policy: ActionPolicy::Block,
                    scan_threshold: ThreatThreshold::Medium,
                },
            },
        ]
    }
}