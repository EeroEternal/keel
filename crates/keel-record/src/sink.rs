use crate::chain::seal_event;
use crate::event::RecordEvent;
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[async_trait]
pub trait RecordSink: Send + Sync {
    async fn emit(&self, event: RecordEvent) -> std::io::Result<()>;
    async fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// In-memory sink for tests and demos.
#[derive(Default)]
pub struct MemorySink {
    events: Mutex<Vec<RecordEvent>>,
}

impl MemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn events(&self) -> Vec<RecordEvent> {
        self.events.lock().await.clone()
    }

    pub async fn len(&self) -> usize {
        self.events.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.events.lock().await.is_empty()
    }
}

#[async_trait]
impl RecordSink for MemorySink {
    async fn emit(&self, event: RecordEvent) -> std::io::Result<()> {
        self.events.lock().await.push(event);
        Ok(())
    }
}

/// Append-only JSONL file sink.
pub struct JsonlSink {
    path: PathBuf,
    file: Mutex<tokio::fs::File>,
}

impl JsonlSink {
    pub async fn create(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl RecordSink for JsonlSink {
    async fn emit(&self, event: RecordEvent) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(&event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        let mut f = self.file.lock().await;
        f.write_all(&line).await
    }

    async fn flush(&self) -> std::io::Result<()> {
        self.file.lock().await.flush().await
    }
}

/// Fan-out sink.
pub struct MultiSink {
    sinks: Vec<Arc<dyn RecordSink>>,
}

impl MultiSink {
    pub fn new(sinks: Vec<Arc<dyn RecordSink>>) -> Self {
        Self { sinks }
    }
}

/// Wraps an inner sink and seals each event into a SHA-256 hash chain.
pub struct HashChainSink {
    inner: Arc<dyn RecordSink>,
    last_hash: Mutex<Option<String>>,
}

impl HashChainSink {
    pub fn new(inner: Arc<dyn RecordSink>) -> Self {
        Self {
            inner,
            last_hash: Mutex::new(None),
        }
    }

    pub fn wrap(inner: Arc<dyn RecordSink>) -> Arc<dyn RecordSink> {
        Arc::new(Self::new(inner))
    }
}

#[async_trait]
impl RecordSink for HashChainSink {
    async fn emit(&self, event: RecordEvent) -> std::io::Result<()> {
        let mut guard = self.last_hash.lock().await;
        let prev = guard.as_deref();
        let sealed = seal_event(event, prev).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        *guard = sealed.event_hash.clone();
        drop(guard);
        self.inner.emit(sealed).await
    }

    async fn flush(&self) -> std::io::Result<()> {
        self.inner.flush().await
    }
}

/// Create the default on-disk JSONL sink for a space
/// (`~/.keel/spaces/<id>/events.jsonl`).
pub async fn default_space_sink(
    space_id: &keel_policy::SpaceId,
) -> std::io::Result<JsonlSink> {
    let path = crate::paths::space_events_path(space_id);
    JsonlSink::create(path).await
}

#[async_trait]
impl RecordSink for MultiSink {
    async fn emit(&self, event: RecordEvent) -> std::io::Result<()> {
        for s in &self.sinks {
            s.emit(event.clone()).await?;
        }
        Ok(())
    }

    async fn flush(&self) -> std::io::Result<()> {
        for s in &self.sinks {
            s.flush().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::verify_chain;
    use crate::event::EventKind;
    use keel_policy::{PolicyId, SpaceId};

    #[tokio::test]
    async fn memory_sink_collects() {
        let sink = MemorySink::new();
        sink.emit(RecordEvent::new(
            SpaceId::from_string("spc-1"),
            PolicyId::from_string("pol-1"),
            None,
            EventKind::Note {
                message: "hi".into(),
            },
        ))
        .await
        .unwrap();
        assert_eq!(sink.len().await, 1);
    }

    #[tokio::test]
    async fn hash_chain_sink_seals() {
        let mem = Arc::new(MemorySink::new());
        let chained = HashChainSink::wrap(mem.clone());
        for msg in ["a", "b", "c"] {
            chained
                .emit(RecordEvent::new(
                    SpaceId::from_string("spc"),
                    PolicyId::from_string("pol"),
                    None,
                    EventKind::Note {
                        message: msg.into(),
                    },
                ))
                .await
                .unwrap();
        }
        let events = mem.events().await;
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0].prev_hash.as_deref(),
            Some(crate::chain::GENESIS_PREV)
        );
        assert!(verify_chain(&events).is_ok());
    }
}
