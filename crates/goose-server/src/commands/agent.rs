use std::sync::Arc;

use crate::configuration;
use crate::state;
use anyhow::Result;
use etcetera::{choose_app_strategy, AppStrategy};
use goose::agents::Agent;
use goose::config::APP_STRATEGY;
use goose::scheduler_factory::SchedulerFactory;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use goose::providers::pricing::initialize_pricing_cache;

pub async fn run() -> Result<()> {
    // Initialize logging
    crate::logging::setup_logging(Some("goosed"))?;

    let settings = configuration::Settings::new()?;

    // Initialize pricing cache on startup
    tracing::info!("Initializing pricing cache...");
    if let Err(e) = initialize_pricing_cache().await {
        tracing::warn!(
            "Failed to initialize pricing cache: {}. Pricing data may not be available.",
            e
        );
    }

    let secret_key =
        std::env::var("GOOSE_SERVER__SECRET_KEY").unwrap_or_else(|_| "test".to_string());

    let mut new_agent = Agent::new();

    tracing::info!("🔧 About to configure security from config file");
    // Configure security from config file
    let config = goose::config::Config::global();
    tracing::info!("🔧 Got global config, about to get security config");
    match config.get_security_config() {
        Ok(security_config) => {
            tracing::info!(
                "🔍 Security config loaded: enabled={}, models={}",
                security_config.enabled,
                security_config.models.len()
            );

            if security_config.enabled {
                tracing::info!("🔒 Security scanning enabled from config");
                tracing::info!("🔧 Security mode: {:?}", security_config.mode);

                for (i, model) in security_config.models.iter().enumerate() {
                    tracing::info!(
                        "📦 Model {}: {} (threshold: {}, weight: {:?})",
                        i + 1,
                        model.model,
                        model.threshold,
                        model.weight
                    );
                }

                let security_manager = goose::security::SecurityManager::new(security_config);
                let security_integration = security_manager.create_integration();
                new_agent.configure_security(security_integration).await;

                tracing::info!("✅ Security system initialized successfully");
            } else {
                tracing::info!("🔓 Security scanning disabled in config");
            }
        }
        Err(e) => {
            tracing::error!(
                "❌ Failed to load security config: {}, using disabled security",
                e
            );
        }
    }

    let agent_ref = Arc::new(new_agent);

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
