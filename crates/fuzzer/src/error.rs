use std::io;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid JSON in {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to encode JSON: {0}")]
    JsonEncode(#[from] serde_json::Error),

    #[error("invalid spec: {0}")]
    InvalidSpec(String),

    #[error("invalid address in {field}: {value:?}")]
    InvalidAddress { field: String, value: String },

    #[error("invalid base58 in {field}: {value:?}: {message}")]
    Base58 {
        field: String,
        value: String,
        message: String,
    },

    #[error("invalid hex in {field}: {source}")]
    Hex {
        field: String,
        #[source]
        source: hex::FromHexError,
    },

    #[error("invalid secret key in {field}: {message}")]
    SecretKey { field: String, message: String },

    #[error("liteSVM: {0}")]
    LiteSvm(#[from] litesvm::error::LiteSVMError),

    #[error("transaction failed to build: {0}")]
    Transaction(String),

    #[error("step {index}: {message}")]
    Step { index: usize, message: String },

    #[error("unknown invariant {name:?}; available: {available:?}")]
    UnknownInvariant {
        name: String,
        available: Vec<String>,
    },

    #[error("shrink failed: {0}")]
    Shrink(String),

    #[error("corpus error: {0}")]
    Corpus(String),
}

pub type Result<T> = std::result::Result<T, Error>;
