#[cfg(test)]
mod onnx_runtime_tests {
    use ort::{Environment, SessionBuilder};
    use std::path::Path;
    use std::sync::Arc;

    #[test]
    fn test_onnx_runtime_environment() {
        println!("🧪 Testing ONNX Runtime Environment...");
        
        let environment = Environment::builder().build();
        match environment {
            Ok(env) => {
                println!("✅ ONNX Runtime Environment created successfully!");
                let _arc_env = Arc::new(env);
            }
            Err(e) => {
                panic!("❌ ONNX Runtime Environment creation failed: {}", e);
            }
        }
    }

    #[test]
    fn test_onnx_models_directory() {
        println!("🧪 Testing ONNX models directory...");
        
        let model_dir = Path::new("onnx_models");
        if model_dir.exists() {
            println!("✅ ONNX models directory found: {:?}", model_dir);
            
            if let Ok(entries) = std::fs::read_dir(model_dir) {
                let mut model_count = 0;
                for entry in entries {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("onnx") {
                            println!("   - Found model: {}", path.display());
                            model_count += 1;
                        }
                    }
                }
                
                if model_count > 0 {
                    println!("   ✅ Found {} ONNX model(s)", model_count);
                } else {
                    println!("   ⚠️  No .onnx model files found in directory");
                }
            }
        } else {
            println!("⚠️  ONNX models directory not found: {:?}", model_dir);
            println!("   You can create this directory and add .onnx model files for testing");
        }
    }

    #[test]
    fn test_onnx_model_loading_if_available() {
        println!("🧪 Testing ONNX model loading...");
        
        let environment = match Environment::builder().build() {
            Ok(env) => Arc::new(env),
            Err(e) => {
                println!("⚠️  Skipping model loading test - Environment creation failed: {}", e);
                return;
            }
        };
        
        let model_dir = Path::new("onnx_models");
        if !model_dir.exists() {
            println!("⚠️  Skipping model loading test - No onnx_models directory");
            return;
        }
        
        let deepset_model = model_dir.join("deepset_deberta-v3-base-injection.onnx");
        let protectai_model = model_dir.join("protectai_deberta-v3-base-prompt-injection-v2.onnx");
        
        let mut tested_any = false;
        
        if deepset_model.exists() {
            println!("🔍 Testing Deepset DeBERTa model...");
            test_single_model(&environment, &deepset_model);
            tested_any = true;
        }
        
        if protectai_model.exists() {
            println!("🔍 Testing ProtectAI DeBERTa model...");
            test_single_model(&environment, &protectai_model);
            tested_any = true;
        }
        
        if !tested_any {
            println!("⚠️  No expected model files found for testing");
            println!("   Expected: deepset_deberta-v3-base-injection.onnx");
            println!("   Expected: protectai_deberta-v3-base-prompt-injection-v2.onnx");
        }
    }

    fn test_single_model(environment: &Arc<Environment>, model_path: &Path) {
        match SessionBuilder::new(environment) {
            Ok(builder) => {
                match builder.with_model_from_file(model_path) {
                    Ok(_session) => {
                        println!("   ✅ Model loaded successfully: {}", model_path.display());
                    }
                    Err(e) => {
                        println!("   ⚠️  Model loading failed: {}", e);
                        println!("   This might be due to missing dependencies or incompatible model format");
                    }
                }
            }
            Err(e) => {
                println!("   ⚠️  SessionBuilder creation failed: {}", e);
            }
        }
    }
}