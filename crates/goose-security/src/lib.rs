pub mod types;
pub mod scanner;
pub mod factory;
pub mod model_scanner;
pub mod ensemble_scanner;
pub mod model_downloader;
pub mod onnx;

#[cfg(feature = "onnx")]
pub mod onnx_model_scanner;

// Re-export main types and functions
pub use types::{
    ScanResult, SecurityConfig, ThreatLevel, ContentType, ScannerType, ResponseMode,
    ModelConfig, ModelBackend, ContentTypeConfig
};
pub use scanner::SecurityScanner;
pub use model_scanner::ModelScanner;
pub use ensemble_scanner::EnsembleScanner;
pub use factory::create_scanner;

#[cfg(feature = "onnx")]
pub use onnx::{OnnxScanner, DualOnnxScanner};

#[cfg(feature = "onnx")]
pub use onnx_model_scanner::OnnxModelScanner;

#[cfg(feature = "onnx")]
pub use model_downloader::{ModelDownloader, ModelInfo, get_global_downloader};