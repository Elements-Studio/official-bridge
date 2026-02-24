// Wrapper for Starcoin config - provides Starcoin-compatible Config API

use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

// Config trait compatible with Starcoin's interface
// Wraps Starcoin's config functionality
pub trait Config: Serialize + DeserializeOwned {
    fn persisted(self, path: &Path) -> PersistedConfig<Self>
    where
        Self: Sized,
    {
        PersistedConfig {
            inner: self,
            path: path.to_path_buf(),
        }
    }

    fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        // Support both YAML and JSON formats
        let config: Self = if path.extension().and_then(|s| s.to_str()) == Some("yaml")
            || path.extension().and_then(|s| s.to_str()) == Some("yml")
        {
            serde_yaml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        };
        Ok(config)
    }

    fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

pub struct PersistedConfig<C> {
    inner: C,
    path: std::path::PathBuf,
}

impl<C: Config> PersistedConfig<C> {
    pub fn read(&self) -> Result<C> {
        C::load(&self.path)
    }

    pub fn save(&self) -> Result<()> {
        self.inner.save(&self.path)
    }
}

// Implement available_port utilities
pub mod local_ip_utils {
    use std::net::{IpAddr, SocketAddr, TcpListener};

    // Get a random available port by binding to port 0 and letting OS assign
    pub fn get_available_port(host: &IpAddr) -> u16 {
        let socket_addr = SocketAddr::new(*host, 0);
        let listener = TcpListener::bind(socket_addr).expect("Failed to bind to random port");
        listener
            .local_addr()
            .expect("Failed to get local address")
            .port()
    }

    pub fn get_available_ports(host: &IpAddr, count: usize) -> Vec<u16> {
        (0..count).map(|_| get_available_port(host)).collect()
    }

    // Testing helper
    pub fn localhost_for_testing() -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
    }
}
