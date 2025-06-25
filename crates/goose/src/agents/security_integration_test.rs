#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::message::Message;
    use crate::security::config::{ActionPolicy, ScannerType, SecurityConfig, ThreatThreshold};
    use tokio;

    #[tokio::test]
    async fn test_agent_security_integration() {
        // Create an agent with security configured
        let agent = Agent::new();

        // Configure security with a test-friendly setup
        let security_config = SecurityConfig {
            enabled: true,
            scanner_type: ScannerType::None, // Use None for testing to avoid model dependencies
            action_policy: ActionPolicy::AskUser,
            scan_threshold: ThreatThreshold::Low,
            confidence_threshold: 0.5,
            ..Default::default()
        };

        agent.configure_security(security_config).await;

        // Verify security manager is configured
        let security_manager = agent.security_manager.lock().await;
        assert!(security_manager.is_some());

        if let Some(ref manager) = *security_manager {
            assert!(manager.is_enabled());
        }

        println!("✅ Agent input security integration test passed");
    }

    #[tokio::test]
    async fn test_extension_security_scanning() {
        use crate::agents::extension::ExtensionConfig;

        let agent = Agent::new();

        // Configure security with blocking policy
        let security_config = SecurityConfig {
            enabled: true,
            scanner_type: ScannerType::None, // Use None for testing
            action_policy: ActionPolicy::Block,
            scan_threshold: ThreatThreshold::Any,
            confidence_threshold: 0.1, // Very low threshold for testing
            ..Default::default()
        };

        agent.configure_security(security_config).await;

        // Create a test extension config
        let test_extension = ExtensionConfig::Frontend {
            name: "test_extension".to_string(),
            tools: vec![],
            instructions: Some("Test extension for security scanning".to_string()),
            bundled: false,
        };

        // Try to add the extension - should work with None scanner
        let result = agent.add_extension(test_extension).await;
        assert!(
            result.is_ok(),
            "Extension installation should succeed with None scanner"
        );

        println!("✅ Extension security scanning test passed");
    }

    #[tokio::test]
    async fn test_security_confirmation_channels() {
        use crate::permission::{SecurityConfirmation, SecurityPermission};

        let agent = Agent::new();

        // Test security confirmation channel
        let test_id = "test_security_123".to_string();
        let test_confirmation = SecurityConfirmation {
            permission: SecurityPermission::AllowOnce,
            threat_level: "Medium".to_string(),
        };

        // Send confirmation
        agent
            .handle_security_confirmation(test_id.clone(), test_confirmation.clone())
            .await;

        // Receive confirmation
        let mut rx = agent.security_confirmation_rx.lock().await;
        if let Some((received_id, received_confirmation)) = rx.recv().await {
            assert_eq!(received_id, test_id);
            assert_eq!(
                received_confirmation.permission,
                SecurityPermission::AllowOnce
            );
            assert_eq!(received_confirmation.threat_level, "Medium");
        } else {
            panic!("Failed to receive security confirmation");
        }

        println!("✅ Security confirmation channels test passed");
    }
}
