// Stub error module for starcoin-bridge-sdk

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Starcoin SDK error: {0}")]
    StarcoinError(String),

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Client error: {0}")]
    ClientError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, Error>;
