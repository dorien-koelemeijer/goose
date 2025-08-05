pub mod ensemble_scanner;
pub mod factory;
pub mod model_downloader;
pub mod model_scanner;
pub mod onnx;
pub mod scanner;
pub mod types;

#[cfg(feature = "onnx")]
pub mod onnx_model_scanner;

// Re-export main types and functions
pub use ensemble_scanner::EnsembleScanner;
pub use factory::create_scanner;
pub use model_scanner::ModelScanner;
pub use scanner::SecurityScanner;
pub use types::{
    ContentType, ContentTypeConfig, ModelBackend, ModelConfig, ResponseMode, ScanResult,
    ScannerType, SecurityConfig, ThreatLevel,
};

#[cfg(feature = "onnx")]
pub use onnx::{DualOnnxScanner, OnnxScanner};

#[cfg(feature = "onnx")]
pub use onnx_model_scanner::OnnxModelScanner;

#[cfg(feature = "onnx")]
pub use model_downloader::{get_global_downloader, ModelDownloader, ModelInfo};
