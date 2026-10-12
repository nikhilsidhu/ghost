//! Performance tooling for dev builds. The tracing spans of crates built with their
//! `devtools` feature feed timing statistics and a flight recorder of the last minute,
//! through `Devtools::layer` on the process's subscriber (see ghost-log). Nothing leaves
//! the app.

pub mod layer;
pub mod stats;
pub mod trace;

use std::sync::Arc;

use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::{Layer, Registry};

/// Span targets measured: Ghost's own crates, not their dependencies.
const TARGET_PREFIX: &str = "ghost";

/// Handles to what the layer feeds.
#[derive(Clone, Default)]
pub struct Devtools {
    pub stats: Arc<stats::Stats>,
    pub recorder: Arc<trace::Recorder>,
}

impl Devtools {
    /// The layer feeding these handles from every span of Ghost's own crates.
    pub fn layer(&self) -> impl Layer<Registry> + Send + Sync + 'static {
        layer::DevtoolsLayer::new(self.stats.clone(), self.recorder.clone())
            .with_filter(filter_fn(|metadata| metadata.target().starts_with(TARGET_PREFIX)))
    }

    /// A subscriber feeding these handles, for tests.
    #[cfg(test)]
    pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        use tracing_subscriber::layer::SubscriberExt;
        tracing_subscriber::registry().with(self.layer())
    }
}
