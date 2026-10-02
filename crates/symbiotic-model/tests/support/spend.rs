// Reuse the production SQLite implementation without linking SQLite into model contracts.
#[path = "../../../symbiotic-ai-runtime/src/spend.rs"]
mod sqlite;
use std::sync::Arc;
use symbiotic_model::{
    ModelError, SpendLedger, SpendReceipt, SpendReceiptRef, SpendReservation, SpendState,
};
use symbiotic_trace::UsageTrace;
struct Fixture {
    ledger: sqlite::SqliteSpendLedger,
    _state: tempfile::TempDir,
}
pub fn ledger() -> Arc<dyn SpendLedger> {
    let state = tempfile::tempdir().unwrap();
    let path = state.path().join("queue.sqlite");
    symbiotic_queue_sqlite::SqliteQueue::open(&path).unwrap();
    Arc::new(Fixture {
        ledger: sqlite::SqliteSpendLedger::open(&path).unwrap(),
        _state: state,
    })
}
impl SpendLedger for Fixture {
    fn reserve(&self, r: &SpendReservation) -> Result<bool, ModelError> {
        self.ledger.reserve(r)
    }
    fn receipt(&self, r: &SpendReceiptRef) -> Result<Option<SpendReceipt>, ModelError> {
        self.ledger.receipt(r)
    }
    fn invocation(&self, a: &str, i: &str) -> Result<Option<SpendReceipt>, ModelError> {
        self.ledger.invocation(a, i)
    }
    fn finish(
        &self,
        r: &SpendReceiptRef,
        s: SpendState,
        u: Option<UsageTrace>,
        o: Option<serde_json::Value>,
    ) -> Result<(), ModelError> {
        self.ledger.finish(r, s, u, o)
    }
}
