//! A plain connection to the sound server (PulseAudio, or PipeWire through
//! pipewire-pulse) for what cpal's PulseAudio host leaves out: which sources are
//! monitors, and the server's device events.

use std::collections::HashSet;
use std::ffi::CString;
use std::io::{BufReader, Read};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use pulseaudio::protocol::{self, Command};

/// How long the server gets to answer a request before it counts as hung.
const SERVER_TIMEOUT: Duration = Duration::from_secs(2);

/// A connection past authentication, with the protocol version agreed.
pub struct Connection {
    sock: BufReader<UnixStream>,
    version: u16,
    /// The sequence number of the next command.
    seq: u32,
}

impl Connection {
    /// Connect to the server the environment names, as the client `name`.
    pub fn open(name: &str) -> Result<Self, String> {
        let path = pulseaudio::socket_path_from_env().ok_or("no sound server socket")?;
        let sock = UnixStream::connect(&path).map_err(|e| format!("connect to {}: {e}", path.display()))?;
        sock.set_read_timeout(Some(SERVER_TIMEOUT)).map_err(|e| format!("socket timeout: {e}"))?;
        let mut connection = Self { sock: BufReader::new(sock), version: protocol::MAX_VERSION, seq: 0 };

        let cookie = pulseaudio::cookie_path_from_env().and_then(|path| std::fs::read(path).ok()).unwrap_or_default();
        connection.send(&Command::Auth(protocol::AuthParams { version: protocol::MAX_VERSION, supports_shm: false, supports_memfd: false, cookie }))?;
        let (_, auth) = protocol::read_reply_message::<protocol::AuthReply>(&mut connection.sock, protocol::MAX_VERSION)
            .map_err(|e| format!("authenticate: {e}"))?;
        connection.version = protocol::MAX_VERSION.min(auth.version);

        let mut props = protocol::Props::new();
        props.set(protocol::Prop::ApplicationName, CString::new(name).map_err(|e| format!("client name: {e}"))?);
        connection.send(&Command::SetClientName(props))?;
        protocol::read_reply_message::<protocol::SetClientNameReply>(&mut connection.sock, connection.version)
            .map_err(|e| format!("name the client: {e}"))?;
        Ok(connection)
    }

    fn send(&mut self, command: &Command) -> Result<(), String> {
        protocol::write_command_message(self.sock.get_mut(), self.seq, command, self.version).map_err(|e| format!("send to the sound server: {e}"))?;
        self.seq += 1;
        Ok(())
    }

    /// Ask for the server's events on `mask`, for `next_event` to wait on.
    pub fn subscribe(&mut self, mask: protocol::SubscriptionMask) -> Result<(), String> {
        self.send(&Command::Subscribe(mask))?;
        protocol::read_ack_message(&mut self.sock).map_err(|e| format!("subscribe: {e}"))?;
        // Events come when they happen, however long that takes.
        self.sock.get_ref().set_read_timeout(None).map_err(|e| format!("socket timeout: {e}"))
    }

    /// The next event subscribed to; other messages are passed over. Fails once the
    /// connection ends.
    pub fn next_event(&mut self) -> Result<protocol::SubscriptionEvent, String> {
        loop {
            // A whole message is read before it is parsed, so one this crate cannot parse
            // is passed over without losing the place in the stream.
            let descriptor = protocol::read_descriptor(&mut self.sock).map_err(|e| format!("read from the sound server: {e}"))?;
            let mut payload = vec![0; descriptor.length as usize];
            self.sock.read_exact(&mut payload).map_err(|e| format!("read from the sound server: {e}"))?;
            if let Ok((_, Command::SubscribeEvent(event))) = Command::read_tag_prefixed(&mut payload.as_slice(), self.version) {
                return Ok(event);
            }
        }
    }

    /// A handle that ends the connection, waking a read waiting on it.
    pub fn closer(&self) -> Result<UnixStream, String> {
        self.sock.get_ref().try_clone().map_err(|e| format!("socket handle: {e}"))
    }
}

/// The names of the sources that are monitors: what a sink plays, offered as an input.
pub fn monitor_sources() -> Result<HashSet<String>, String> {
    let mut connection = Connection::open("ghost-devices")?;
    connection.send(&Command::GetSourceInfoList)?;
    let (_, sources) = protocol::read_reply_message::<protocol::SourceInfoList>(&mut connection.sock, connection.version)
        .map_err(|e| format!("list sources: {e}"))?;
    Ok(sources
        .into_iter()
        .filter(|source| source.monitor_of_sink_index.is_some())
        .map(|source| source.name.to_string_lossy().into_owned())
        .collect())
}
