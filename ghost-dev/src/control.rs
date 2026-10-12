//! Requests to an app instance the launcher started, over the loopback port it named in
//! the instance's environment: one JSON line out, one JSON reply line back.

use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Ample on loopback, short enough that a stuck instance does not hang the page.
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Reply {
    Ok(Value),
    Error(String),
}

/// A free loopback port for an instance to listen on.
pub fn free_port() -> Result<u16, String> {
    std::net::TcpListener::bind(("127.0.0.1", 0)).and_then(|listener| listener.local_addr()).map(|addr| addr.port()).map_err(|e| e.to_string())
}

/// Send `request` to the instance listening on `port` and return its answer.
pub async fn request(port: u16, request: Value) -> Result<Value, String> {
    let exchange = async {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| format!("reach the instance: {e}"))?;
        let (read, mut write) = stream.into_split();
        let mut line = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        line.push(b'\n');
        write.write_all(&line).await.map_err(|e| e.to_string())?;
        let mut reply = String::new();
        BufReader::new(read).read_line(&mut reply).await.map_err(|e| e.to_string())?;
        match serde_json::from_str::<Reply>(&reply).map_err(|e| format!("instance reply: {e}"))? {
            Reply::Ok(value) => Ok(value),
            Reply::Error(e) => Err(e),
        }
    };
    tokio::time::timeout(TIMEOUT, exchange).await.map_err(|_| "the instance did not answer".to_string())?
}
