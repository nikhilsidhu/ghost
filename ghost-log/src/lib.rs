//! One logging setup for every Ghost binary. `tracing` events go to stderr and, when the
//! binary has a data directory, to a daily log file there; the last week of files is
//! kept. `GHOST_LOG` says what is logged, in tracing's filter syntax (`debug`,
//! `ghost_core=trace,info`, ...); unset, everything from `info` up.

use std::io::IsTerminal;
use std::path::PathBuf;

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};

/// The environment variable that sets what is logged.
pub const FILTER_ENV: &str = "GHOST_LOG";
/// Daily files kept, today's included.
const DAYS_KEPT: usize = 7;
const FILE_EXTENSION: &str = "log";

/// Where the daily log files go: `<dir>/<stem>.<date>.log`.
pub struct LogFile {
    pub dir: PathBuf,
    pub stem: &'static str,
}

/// Keeps the log file's writer thread alive. Hold it until the process ends, so the lines
/// logged last still reach the file.
#[must_use = "dropping the guard stops the log file from being written"]
pub struct LogGuard {
    _file_writer: Option<WorkerGuard>,
}

/// Install logging to stderr and, given a file, to daily log files. Call once, first
/// thing in `main`.
pub fn init(file: Option<LogFile>) -> LogGuard {
    let stderr = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_filter(filter());
    let (file_layer, file_writer, file_error) = match file.map(open_file) {
        Some(Ok((writer, guard))) => {
            let layer = tracing_subscriber::fmt::layer().with_writer(writer).with_ansi(false).with_filter(filter());
            (Some(layer), Some(guard), None)
        }
        Some(Err(e)) => (None, None, Some(e)),
        None => (None, None, None),
    };
    Registry::default().with(stderr).with(file_layer).init();
    if let Some(e) = file_error {
        tracing::error!("log file not opened; logging to stderr alone: {e}");
    }
    LogGuard { _file_writer: file_writer }
}

fn filter() -> EnvFilter {
    EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).with_env_var(FILTER_ENV).from_env_lossy()
}

/// A writer appending to today's file, rotating at midnight and dropping files past the
/// week kept. Writes go through a thread of their own, so logging never waits on disk.
fn open_file(file: LogFile) -> Result<(NonBlocking, WorkerGuard), Box<dyn std::error::Error + Send + Sync>> {
    std::fs::create_dir_all(&file.dir)?;
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(file.stem)
        .filename_suffix(FILE_EXTENSION)
        .max_log_files(DAYS_KEPT)
        .build(&file.dir)?;
    Ok(tracing_appender::non_blocking(appender))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn the_log_file_is_a_daily_file_in_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("deeper").join("logs");
        let (mut writer, guard) = open_file(LogFile { dir: logs.clone(), stem: "ghost-test" }).unwrap();
        writer.write_all(b"a line\n").unwrap();
        // Dropping the guard flushes the writer thread.
        drop(guard);
        let files: Vec<String> = std::fs::read_dir(&logs).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(files.len(), 1, "{files:?}");
        let name = &files[0];
        assert!(name.starts_with("ghost-test.") && name.ends_with(".log"), "{name}");
        assert_eq!(std::fs::read_to_string(logs.join(name)).unwrap(), "a line\n");
    }
}
