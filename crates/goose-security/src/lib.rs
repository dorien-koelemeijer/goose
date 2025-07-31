pub mod types;
pub mod scanner;
pub mod factory;
pub mod model_downloader;
pub mod onnx;

// Re-export main types and functions
pub use types::{
    ScanResult, SecurityConfig, ThreatLevel, ContentType, ScannerType, ResponseMode,
    ModelConfig, ContentTypeConfig
};
pub use scanner::SecurityScanner;
pub use factory::create_scanner;

#[cfg(feature = "onnx")]
pub use onnx::{OnnxScanner, DualOnnxScanner};

#[cfg(feature = "onnx")]
pub use model_downloader::{ModelDownloader, ModelInfo, get_global_downloader};