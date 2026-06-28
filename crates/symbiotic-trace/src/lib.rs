//! Normalized invocation traces and pluggable sinks.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use symbiotic_core::{ModelIdentity, QueueId, QueueItemId, Sensitivity, TraceId};
use symbiotic_queue::{QueueEvent, QueueEventSink, QueueStatus};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationOutcome {
    Succeeded,
    Failed,
    RateLimited,
    BudgetExhausted,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheStatus {
    #[default]
    NotApplicable,
    Miss,
    Hit,
    PartialHit,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CacheTrace {
    pub response_cache: CacheStatus,
    pub prompt_cache: CacheStatus,
    pub cached_input_tokens: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UsageTrace {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub media_units: Option<u64>,
    pub cost_micro_usd: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TimingTrace {
    pub queued_ms: Option<u64>,
    pub provider_ms: Option<u64>,
    pub total_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelInvocationTrace {
    pub trace_id: TraceId,
    pub queue_item_id: Option<QueueItemId>,
    pub model: ModelIdentity,
    pub role_binding: Option<String>,
    pub source: Option<String>,
    pub sensitivity: Sensitivity,
    pub request_hash: String,
    pub response_hash: Option<String>,
    pub cache: CacheTrace,
    pub usage: UsageTrace,
    pub timing: TimingTrace,
    pub outcome: InvocationOutcome,
    pub error_class: Option<String>,
    pub audit_refs: Vec<String>,
    pub metadata: Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueueEventTrace {
    pub trace_id: TraceId,
    pub item_id: QueueItemId,
    pub queue_id: QueueId,
    pub kind: String,
    pub status: QueueStatus,
    pub attempt: u32,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub metadata: Value,
}

impl From<QueueEvent> for QueueEventTrace {
    fn from(event: QueueEvent) -> Self {
        Self {
            trace_id: TraceId::new(),
            item_id: event.item_id,
            queue_id: event.queue_id,
            kind: event.kind,
            status: event.status,
            attempt: event.attempt,
            error: event.error,
            timestamp: event.timestamp,
            metadata: serde_json::json!({}),
        }
    }
}

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("trace sink failed: {0}")]
    Sink(String),
}

#[async_trait]
pub trait TraceSink: Send + Sync {
    async fn record_model_invocation(&self, trace: ModelInvocationTrace) -> Result<(), TraceError>;
}

#[async_trait]
pub trait QueueTraceSink: Send + Sync {
    async fn record_queue_event(&self, trace: QueueEventTrace) -> Result<(), TraceError>;
}

pub struct FanoutTraceSink {
    sinks: Vec<Box<dyn TraceSink>>,
}

impl FanoutTraceSink {
    pub fn new(sinks: Vec<Box<dyn TraceSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl TraceSink for FanoutTraceSink {
    async fn record_model_invocation(&self, trace: ModelInvocationTrace) -> Result<(), TraceError> {
        for sink in &self.sinks {
            sink.record_model_invocation(trace.clone()).await?;
        }
        Ok(())
    }
}

pub struct FanoutQueueTraceSink {
    sinks: Vec<Box<dyn QueueTraceSink>>,
}

impl FanoutQueueTraceSink {
    pub fn new(sinks: Vec<Box<dyn QueueTraceSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl QueueTraceSink for FanoutQueueTraceSink {
    async fn record_queue_event(&self, trace: QueueEventTrace) -> Result<(), TraceError> {
        for sink in &self.sinks {
            sink.record_queue_event(trace.clone()).await?;
        }
        Ok(())
    }
}

pub struct BestEffortTraceSink {
    sink: Box<dyn TraceSink>,
}

impl BestEffortTraceSink {
    pub fn new(sink: Box<dyn TraceSink>) -> Self {
        Self { sink }
    }
}

#[async_trait]
impl TraceSink for BestEffortTraceSink {
    async fn record_model_invocation(&self, trace: ModelInvocationTrace) -> Result<(), TraceError> {
        let _ = self.sink.record_model_invocation(trace).await;
        Ok(())
    }
}

pub struct BestEffortQueueTraceSink {
    sink: Box<dyn QueueTraceSink>,
}

impl BestEffortQueueTraceSink {
    pub fn new(sink: Box<dyn QueueTraceSink>) -> Self {
        Self { sink }
    }
}

#[async_trait]
impl QueueTraceSink for BestEffortQueueTraceSink {
    async fn record_queue_event(&self, trace: QueueEventTrace) -> Result<(), TraceError> {
        let _ = self.sink.record_queue_event(trace).await;
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct InMemoryTraceSink {
    records: Arc<Mutex<Vec<ModelInvocationTrace>>>,
}

impl InMemoryTraceSink {
    pub fn records(&self) -> Vec<ModelInvocationTrace> {
        self.records.lock().expect("trace sink lock").clone()
    }
}

#[async_trait]
impl TraceSink for InMemoryTraceSink {
    async fn record_model_invocation(&self, trace: ModelInvocationTrace) -> Result<(), TraceError> {
        self.records.lock().expect("trace sink lock").push(trace);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct InMemoryQueueTraceSink {
    records: Arc<Mutex<Vec<QueueEventTrace>>>,
}

impl InMemoryQueueTraceSink {
    pub fn records(&self) -> Vec<QueueEventTrace> {
        self.records.lock().expect("queue trace sink lock").clone()
    }
}

#[async_trait]
impl QueueTraceSink for InMemoryQueueTraceSink {
    async fn record_queue_event(&self, trace: QueueEventTrace) -> Result<(), TraceError> {
        self.records
            .lock()
            .expect("queue trace sink lock")
            .push(trace);
        Ok(())
    }
}

pub struct JsonlTraceSink {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl JsonlTraceSink {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TraceError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(|err| TraceError::Sink(err.to_string()))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .map_err(|err| TraceError::Sink(err.to_string()))?;
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Vec<ModelInvocationTrace>, TraceError> {
        if !path.as_ref().is_file() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(path).map_err(|err| TraceError::Sink(err.to_string()))?;
        raw.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(|err| TraceError::Sink(err.to_string())))
            .collect()
    }
}

#[async_trait]
impl TraceSink for JsonlTraceSink {
    async fn record_model_invocation(&self, trace: ModelInvocationTrace) -> Result<(), TraceError> {
        use std::io::Write;

        let mut file = self
            .file
            .lock()
            .map_err(|_| TraceError::Sink("jsonl trace sink lock poisoned".to_string()))?;
        writeln!(
            file,
            "{}",
            serde_json::to_string(&trace).map_err(|err| TraceError::Sink(err.to_string()))?
        )
        .map_err(|err| TraceError::Sink(err.to_string()))?;
        file.flush()
            .map_err(|err| TraceError::Sink(err.to_string()))?;
        Ok(())
    }
}

pub struct JsonlQueueTraceSink {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl JsonlQueueTraceSink {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TraceError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(|err| TraceError::Sink(err.to_string()))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .map_err(|err| TraceError::Sink(err.to_string()))?;
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Vec<QueueEventTrace>, TraceError> {
        if !path.as_ref().is_file() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(path).map_err(|err| TraceError::Sink(err.to_string()))?;
        raw.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(|err| TraceError::Sink(err.to_string())))
            .collect()
    }
}

#[async_trait]
impl QueueTraceSink for JsonlQueueTraceSink {
    async fn record_queue_event(&self, trace: QueueEventTrace) -> Result<(), TraceError> {
        use std::io::Write;

        let mut file = self
            .file
            .lock()
            .map_err(|_| TraceError::Sink("jsonl queue trace sink lock poisoned".to_string()))?;
        writeln!(
            file,
            "{}",
            serde_json::to_string(&trace).map_err(|err| TraceError::Sink(err.to_string()))?
        )
        .map_err(|err| TraceError::Sink(err.to_string()))?;
        file.flush()
            .map_err(|err| TraceError::Sink(err.to_string()))?;
        Ok(())
    }
}

pub struct QueueEventTraceAdapter {
    sink: Arc<dyn QueueTraceSink>,
}

impl QueueEventTraceAdapter {
    pub fn new(sink: Arc<dyn QueueTraceSink>) -> Self {
        Self { sink }
    }
}

#[async_trait]
impl QueueEventSink for QueueEventTraceAdapter {
    async fn record_queue_event(&self, event: QueueEvent) {
        let _ = self.sink.record_queue_event(event.into()).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::Utc;
    use symbiotic_core::{ModelIdentity, QueueId, QueueItemId, Sensitivity, TraceId};
    use symbiotic_queue::{QueueEvent, QueueEventSink, QueueStatus};

    use super::*;

    struct VecSink {
        records: Arc<Mutex<Vec<ModelInvocationTrace>>>,
    }

    #[async_trait]
    impl TraceSink for VecSink {
        async fn record_model_invocation(
            &self,
            trace: ModelInvocationTrace,
        ) -> Result<(), TraceError> {
            self.records.lock().unwrap().push(trace);
            Ok(())
        }
    }

    fn sample_trace() -> ModelInvocationTrace {
        ModelInvocationTrace {
            trace_id: TraceId::new(),
            queue_item_id: None,
            model: ModelIdentity::new("chat", "codex", "gpt-5.5-codex"),
            role_binding: Some("agent.plan".to_string()),
            source: Some("test".to_string()),
            sensitivity: Sensitivity::Shareable,
            request_hash: "req".to_string(),
            response_hash: Some("res".to_string()),
            cache: CacheTrace::default(),
            usage: UsageTrace {
                input_tokens: Some(10),
                output_tokens: Some(5),
                reasoning_tokens: None,
                media_units: None,
                cost_micro_usd: Some(42),
            },
            timing: TimingTrace {
                queued_ms: Some(1),
                provider_ms: Some(2),
                total_ms: Some(3),
            },
            outcome: InvocationOutcome::Succeeded,
            error_class: None,
            audit_refs: vec!["audit:1".to_string()],
            metadata: serde_json::json!({}),
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn fanout_sends_trace_to_all_sinks() {
        let first = Arc::new(Mutex::new(Vec::new()));
        let second = Arc::new(Mutex::new(Vec::new()));
        let sink = FanoutTraceSink::new(vec![
            Box::new(VecSink {
                records: first.clone(),
            }),
            Box::new(VecSink {
                records: second.clone(),
            }),
        ]);

        sink.record_model_invocation(sample_trace()).await.unwrap();

        assert_eq!(first.lock().unwrap().len(), 1);
        assert_eq!(second.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn jsonl_sink_round_trips_trace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.jsonl");
        let sink = JsonlTraceSink::open(&path).unwrap();
        sink.record_model_invocation(sample_trace()).await.unwrap();

        let records = JsonlTraceSink::read(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].usage.input_tokens, Some(10));
    }

    #[tokio::test]
    async fn best_effort_sink_swallows_errors() {
        struct FailingSink;

        #[async_trait]
        impl TraceSink for FailingSink {
            async fn record_model_invocation(
                &self,
                _trace: ModelInvocationTrace,
            ) -> Result<(), TraceError> {
                Err(TraceError::Sink("boom".to_string()))
            }
        }

        let sink = BestEffortTraceSink::new(Box::new(FailingSink));
        sink.record_model_invocation(sample_trace()).await.unwrap();
    }

    fn sample_queue_trace() -> QueueEventTrace {
        QueueEventTrace {
            trace_id: TraceId::new(),
            item_id: QueueItemId::new(),
            queue_id: QueueId::new("model:deepseek:flash"),
            kind: "chat".to_string(),
            status: QueueStatus::Failed,
            attempt: 2,
            error: Some("rate limited".to_string()),
            timestamp: Utc::now(),
            metadata: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn jsonl_queue_sink_round_trips_trace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue-trace.jsonl");
        let sink = JsonlQueueTraceSink::open(&path).unwrap();
        sink.record_queue_event(sample_queue_trace()).await.unwrap();

        let records = JsonlQueueTraceSink::read(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, "chat");
        assert_eq!(records[0].status, QueueStatus::Failed);
    }

    #[tokio::test]
    async fn queue_event_adapter_records_queue_events() {
        let sink = Arc::new(InMemoryQueueTraceSink::default());
        let adapter = QueueEventTraceAdapter::new(sink.clone());

        adapter
            .record_queue_event(QueueEvent {
                item_id: QueueItemId::new(),
                queue_id: QueueId::new("model:gemini:embedding"),
                kind: "embedding".to_string(),
                status: QueueStatus::Succeeded,
                attempt: 1,
                timestamp: Utc::now(),
                error: None,
            })
            .await;

        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].queue_id.0, "model:gemini:embedding");
    }
}
