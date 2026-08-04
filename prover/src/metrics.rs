//! Metrics for ZiSK prover service.

use std::time::Duration;
use vise::{Buckets, EncodeLabelSet, EncodeLabelValue, Family, Histogram, Metrics};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EncodeLabelValue, EncodeLabelSet)]
#[metrics(label = "method")]
pub enum Method {
    #[metrics(rename = "pick")]
    Pick,
    #[metrics(rename = "submit")]
    Submit,
    #[metrics(rename = "pick_aggregation")]
    PickAggregation,
    #[metrics(rename = "submit_aggregation")]
    SubmitAggregation,
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Pick => write!(f, "pick"),
            Method::Submit => write!(f, "submit"),
            Method::PickAggregation => write!(f, "pick_aggregation"),
            Method::SubmitAggregation => write!(f, "submit_aggregation"),
        }
    }
}

const LATENCY_BUCKETS: Buckets = Buckets::exponential(0.01..=60.0, 2.0);
const PROOF_TIME_BUCKETS: Buckets = Buckets::exponential(10.0..=7200.0, 2.0);

#[derive(Debug, Metrics)]
#[metrics(prefix = "zisk_prover")]
pub struct ZiskProverMetrics {
    /// HTTP request latency by method.
    #[metrics(buckets = LATENCY_BUCKETS)]
    pub http_latency: Family<Method, Histogram<Duration>>,

    /// Total proof generation time (input write + prove + parse).
    #[metrics(buckets = PROOF_TIME_BUCKETS)]
    pub proof_generation_time: Histogram<Duration>,

    /// `cargo-zisk` prove time (integrated STARK, plus the PLONK wrap in
    /// per-batch and aggregation-range modes).
    #[metrics(buckets = PROOF_TIME_BUCKETS)]
    pub prove_time: Histogram<Duration>,

    /// One-time per-ELF program-setup duration.
    #[metrics(buckets = PROOF_TIME_BUCKETS)]
    pub program_setup_time: Histogram<Duration>,

    /// Proof attempts by outcome (success / failure / cancelled).
    pub proofs: Family<ProofOutcome, vise::Counter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EncodeLabelValue, EncodeLabelSet)]
#[metrics(label = "outcome", rename_all = "snake_case")]
pub enum ProofOutcome {
    Success,
    Failure,
    Cancelled,
}

#[vise::register]
pub static ZISK_PROVER_METRICS: vise::Global<ZiskProverMetrics> = vise::Global::new();
