use thiserror::Error;

#[derive(Error, Debug)]
pub enum SnifferError {
    #[error("Device '{0}' not found")]
    DeviceNotFound(String),
    #[error("Device lookup failed: {0}")]
    DeviceLookupFailed(String),
    #[error("Permission denied: {0} (needs CAP_NET_RAW or root)")]
    PermissionDenied(String),
    #[error("Pcap error: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("Decode error: {0}")]
    Decode(String),
    #[error("Capture stream closed: {0}")]
    CaptureClosed(String),
    #[error("Persistent capture error: {0}")]
    PersistentCapture(String),
    #[error("Capture error: {0}")]
    Capture(String),
}
