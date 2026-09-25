//! Metrics for ZiSK prover service.
//!
//! `vise` and `vise-exporter` must share one major version: each version has
//! its own global registry, and an exporter of a different version serves an
//! empty page while the scrape still succeeds. `registers_with_the_exporter`
//! below guards that.

use std::time::Duration;
use vise::{
    Buckets, Counter, EncodeLabelSet, EncodeLabelValue, Family, Gauge, Histogram, LabeledFamily,
    Metrics, Unit,
};

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

/// What a proving run produces: one batch proof or one aggregation range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EncodeLabelValue, EncodeLabelSet)]
#[metrics(label = "job", rename_all = "snake_case")]
pub enum Job {
    Batch,
    Range,
}

const LATENCY_BUCKETS: Buckets = Buckets::exponential(0.01..=60.0, 2.0);
const PROOF_TIME_BUCKETS: Buckets = Buckets::exponential(10.0..=7200.0, 2.0);

#[derive(Debug, Metrics)]
#[metrics(prefix = "zisk_prover")]
pub struct ZiskProverMetrics {
    /// HTTP request latency by method, including requests that failed.
    #[metrics(unit = Unit::Seconds, buckets = LATENCY_BUCKETS)]
    pub http_latency: Family<Method, Histogram<Duration>>,

    /// Sequencer requests that failed by method: transport errors and any
    /// status other than success or 503 (lane disabled server-side).
    pub http_errors: Family<Method, Counter>,

    /// Total proof generation time (input write + prove + parse), by job.
    #[metrics(unit = Unit::Seconds, buckets = PROOF_TIME_BUCKETS)]
    pub proof_generation_time: Family<Job, Histogram<Duration>>,

    /// `cargo-zisk` prove time by job (integrated STARK, plus the PLONK wrap
    /// in per-batch and aggregation-range modes).
    #[metrics(unit = Unit::Seconds, buckets = PROOF_TIME_BUCKETS)]
    pub prove_time: Family<Job, Histogram<Duration>>,

    /// One-time per-ELF program-setup duration.
    #[metrics(unit = Unit::Seconds, buckets = PROOF_TIME_BUCKETS)]
    pub program_setup_time: Histogram<Duration>,

    /// Proof attempts by job and outcome (success / failure / cancelled).
    #[metrics(labels = ["job", "outcome"])]
    pub proofs: LabeledFamily<(Job, ProofOutcome), Counter, 2>,

    /// Highest batch number whose proof this daemon has submitted, the
    /// ZiSK counterpart of `fri_prover_latest_proven_batch`. 0 until the
    /// first submit after start.
    pub latest_proven_batch: Gauge<u64>,

    /// Last batch of the most recent aggregation range this daemon has
    /// submitted. 0 until the first submit after start.
    pub latest_aggregated_batch: Gauge<u64>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The metrics must land in the registry the exporter serves. With
    /// `vise` 0.2 metrics and a `vise-exporter` 0.3 the exporter served only
    /// its own `vise_exporter_*` series while `up` stayed 1.
    #[test]
    fn registers_with_the_exporter() {
        ZISK_PROVER_METRICS.proofs[&(Job::Batch, ProofOutcome::Success)].inc();
        ZISK_PROVER_METRICS.latest_proven_batch.set(42);
        let registry = vise::MetricsCollection::default().collect();
        let mut out = String::new();
        registry
            .encode(&mut out, vise::Format::OpenMetricsForPrometheus)
            .unwrap();
        for name in [
            "zisk_prover_http_latency_seconds",
            "zisk_prover_http_errors",
            "zisk_prover_proof_generation_time_seconds",
            "zisk_prover_prove_time_seconds",
            "zisk_prover_program_setup_time_seconds",
            "zisk_prover_proofs",
            "zisk_prover_latest_proven_batch 42",
            "zisk_prover_latest_aggregated_batch",
        ] {
            assert!(out.contains(name), "{name} missing from:\n{out}");
        }
        assert!(out.contains("job=\"batch\",outcome=\"success\""), "{out}");
    }
}
