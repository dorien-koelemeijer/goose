use std::sync::Arc;

use crate::configuration;
use crate::state;
use anyhow::Result;
use etcetera::{choose_app_strategy, AppStrategy};
use goose::agents::Agent;
use goose::config::{APP_STRATEGY, Config, SecuritySettings};
use goose::scheduler_factory::SchedulerFactory;
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

    // Configure security based on user configuration
    let config = Config::global();
    if let Ok(security_settings) = config.get_param::<SecuritySettings>("security") {
        if security_settings.enabled {
            let security_config = security_settings.to_security_config();
            agent_ref.configure_security(security_config).await;
            info!("Security scanning enabled with ONNX ensemble (Deepset + ProtectAI DeBERTa models)");
        } else {
            info!("Security scanning is disabled in configuration");
        }
    } else {
        info!("No security configuration found, security scanning disabled");
    }

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
