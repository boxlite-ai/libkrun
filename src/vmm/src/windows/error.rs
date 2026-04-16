//! Error types for the Windows WHPX backend.

/// Result type for WHPX operations.
pub type Result<T> = std::result::Result<T, WkrunError>;

/// Errors that can occur in the WHPX backend.
#[derive(Debug, thiserror::Error)]
pub enum WkrunError {
    /// WHPX API call failed with an HRESULT.
    #[error("WHPX API call failed: {function} returned 0x{hresult:08X}")]
    WhpxApi {
        function: &'static str,
        hresult: u32,
    },

    /// WHPX/Hyper-V is not available on this system.
    #[error("WHPX not available: {0}")]
    WhpxUnavailable(String),

    /// Invalid VM context ID.
    #[error("invalid context ID: {0}")]
    InvalidContext(u32),

    /// Context ID already in use.
    #[error("context ID {0} already exists")]
    ContextExists(u32),

    /// VM configuration error.
    #[error("VM configuration error: {0}")]
    Config(String),

    /// Guest memory error.
    #[error("guest memory error: {0}")]
    Memory(String),

    /// vCPU error.
    #[error("vCPU error: {0}")]
    Vcpu(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Boot/kernel loading error.
    #[error("boot error: {0}")]
    Boot(String),

    /// Device emulation error.
    #[error("device error: {0}")]
    Device(String),

    /// VM is not in the expected state for this operation.
    #[error("invalid VM state: expected {expected}, got {actual}")]
    InvalidState {
        expected: &'static str,
        actual: String,
    },
}

impl WkrunError {
    /// Create a WHPX API error from a function name and HRESULT.
    pub fn whpx(function: &'static str, hresult: u32) -> Self {
        WkrunError::WhpxApi { function, hresult }
    }
}

/// Checks an HRESULT and returns an error if it indicates failure.
/// HRESULT values with the high bit set indicate failure.
#[cfg(target_os = "windows")]
pub fn check_hresult(function: &'static str, hr: i32) -> Result<()> {
    if hr < 0 {
        Err(WkrunError::whpx(function, hr as u32))
    } else {
        Ok(())
    }
}

/// Return code for the C API: 0 = success, negative = error.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CApiResult {
    Success = 0,
    InvalidContext = -1,
    InvalidArgument = -2,
    WhpxError = -3,
    MemoryError = -4,
    BootError = -5,
    DeviceError = -6,
    StateError = -7,
    IoError = -8,
    Unknown = -99,
}

impl From<&WkrunError> for CApiResult {
    fn from(err: &WkrunError) -> Self {
        match err {
            WkrunError::InvalidContext(_) => CApiResult::InvalidContext,
            WkrunError::ContextExists(_) => CApiResult::InvalidContext,
            WkrunError::Config(_) => CApiResult::InvalidArgument,
            WkrunError::WhpxApi { .. } => CApiResult::WhpxError,
            WkrunError::WhpxUnavailable(_) => CApiResult::WhpxError,
            WkrunError::Memory(_) => CApiResult::MemoryError,
            WkrunError::Boot(_) => CApiResult::BootError,
            WkrunError::Device(_) => CApiResult::DeviceError,
            WkrunError::InvalidState { .. } => CApiResult::StateError,
            WkrunError::Vcpu(_) => CApiResult::DeviceError,
            WkrunError::Io(_) => CApiResult::IoError,
        }
    }
}

impl From<&WkrunError> for i32 {
    fn from(err: &WkrunError) -> Self {
        CApiResult::from(err) as i32
    }
}
