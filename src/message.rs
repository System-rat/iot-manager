use serde::{Deserialize, Serialize};


// Device messages

#[derive(Deserialize)]
pub(crate) struct Heartbeat {
    pub timestamp: u64,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DiagnosticLevel {
    DEBUG,
    INFO,
    ERROR,
    CRITICAL
}

#[derive(Deserialize)]
pub(crate) struct DiagnosticMessage {
    pub level: DiagnosticLevel,
    pub message: String,
    pub detailed: Option<String>
}

#[derive(Deserialize)]
pub(crate) struct RelayStatus {
    pub relay_name: String,
    pub active: bool,
}

#[derive(Deserialize)]
pub(crate) struct ButtonStatus {
    pub button_name: String,
    pub is_high: bool,
}

#[derive(Deserialize)]
pub(crate) struct DeviceData {
    pub humidity: f32,
    pub temperature: f32,
    pub relays: Vec<RelayStatus>,
    pub buttons: Vec<ButtonStatus>,
}

// Device commands

#[derive(Serialize, Deserialize)]
pub(crate) struct PingCommand {
    pub ping_message: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SetRelay {
    pub relay_name: String,
    pub active: bool,
}

