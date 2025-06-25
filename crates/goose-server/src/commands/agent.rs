use std::sync::Arc;

use crate::configuration;
use crate::state;
use anyhow::Result;
use etcetera::{choose_app_strategy, AppStrategy};
use goose::agents::Agent;
use goose::config::APP_STRATEGY;
use goose::scheduler_factory::SchedulerFactory;
use goose::security::config::{
    ActionPolicy, EnsembleConfig, EnsembleMember, SecurityConfig, ScannerType, ThreatThreshold,
    VotingStrategy,
};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

pub async fn run() -> Result<()> {
    // Initialize logging
    crate::logging::setup_logging(Some("goosed"))?;

    let settings = configuration::Settings::new()?;

    let secret_key =
        std::env::var("GOOSE_SERVER__SECRET_KEY").unwrap_or_else(|_| "test".to_string());

    let new_agent = Agent::new();
    let agent_ref = Arc::new(new_agent);

    // Configure security with ONNX ensemble using Deepset and ProtectAI DeBERTa models
    let security_config = SecurityConfig {
        enabled: true,
        scanner_type: ScannerType::ParallelEnsemble,
        ollama_endpoint: "http://localhost:11434".to_string(),
        action_policy: ActionPolicy::AskUser, // Ask user for confirmation on threats
        scan_threshold: ThreatThreshold::Medium, // Medium and above threats
        confidence_threshold: 0.7, // 70% confidence threshold
        ensemble_config: Some(EnsembleConfig {
            voting_strategy: VotingStrategy::AnyDetection, // Flag if any model detects threat
            member_configs: vec![
                EnsembleMember {
                    scanner_type: ScannerType::RustDeepsetDeberta,
                    confidence_threshold: 0.7,
                    weight: 1.0,
                },
                EnsembleMember {
                    scanner_type: ScannerType::RustProtectAiDeberta,
                    confidence_threshold: 0.7,
                    weight: 1.0,
                },
            ],
            max_scan_time_ms: Some(800),     // 800ms timeout
            min_models_required: Some(1),    // At least one model must respond
            early_exit_threshold: Some(0.9), // If one model is very confident, exit early
        }),
        hybrid_config: None, // No hybrid configuration
    };

    agent_ref.configure_security(security_config).await;
    info!("Security configured with ONNX ensemble (Deepset + ProtectAI DeBERTa models)");

    let app_state = state::AppState::new(agent_ref.clone(), secret_key.clone()).await;

    let schedule_file_path = choose_app_strategy(APP_STRATEGY.clone())?
        .data_dir()
        .join("schedules.json");

    let scheduler_instance = SchedulerFactory::create(schedule_file_path).await?;
    app_state.set_scheduler(scheduler_instance.clone()).await;

    // NEW: Provide scheduler access to the agent
    agent_ref.set_scheduler(scheduler_instance).await;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = crate::routes::configure(app_state).layer(cors);

    let listener = tokio::net::TcpListener::bind(settings.socket_addr()).await?;
    info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
