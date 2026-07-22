//! HTTP client for the ZKsync OS server's ZiSK prover API.
//!
//! Uses the same pick/submit model as the Airbender prover:
//! - `POST /ZiSK/pick` — get assigned batch with ZiSK data
//! - `POST /ZiSK/submit` — submit the per-batch proof (PLONK-wrapped SNARK
//!   in per-batch mode, raw `vadcop_final` stream in aggregated mode)
//! - `POST /ZiSK-AGG/pick` — get an assigned aggregation range with its
//!   buffered per-batch `vadcop_final` streams
//! - `POST /ZiSK-AGG/submit` — submit the aggregated range proof
//!
//! Supports HTTP Basic Auth via credentials embedded in the URL
//! (e.g. `http://user:pass@host:port`). Credentials are extracted
//! and sent via the Authorization header; the URL is cleaned.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use url::Url;

use crate::metrics::{Method, ZISK_PROVER_METRICS};

/// Batch data returned by `/ZiSK/pick`.
pub struct ZiskBatchData {
    pub batch_number: u64,
    pub vk_hash: String,
    pub zisk_data: Vec<u8>,
}

/// An aggregation job returned by `/ZiSK-AGG/pick`: the per-batch
/// `vadcop_final` streams of one Airbender SNARK range, in batch order.
pub struct ZiskAggregationJobData {
    pub from_batch: u64,
    pub to_batch: u64,
    pub streams: Vec<(u64, Vec<u8>)>,
}

/// HTTP client for the server's prover API.
pub struct SequencerClient {
    base_url: Url,
    prover_id: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct PickResponse {
    batch_number: u64,
    vk_hash: String,
    zisk_data: String,
}

#[derive(Serialize)]
struct ZiskSubmitPayload {
    batch_number: u64,
    proof: String,
    public_values: String,
}

#[derive(Deserialize)]
struct AggregationBatchProof {
    batch_number: u64,
    proof: String,
}

#[derive(Deserialize)]
struct AggregationPickResponse {
    from_batch_number: u64,
    to_batch_number: u64,
    proofs: Vec<AggregationBatchProof>,
}

#[derive(Serialize)]
struct AggregationSubmitPayload {
    from_batch_number: u64,
    to_batch_number: u64,
    proof: String,
    public_values: String,
}

impl SequencerClient {
    /// Create a new client, extracting credentials from the URL if present.
    ///
    /// Example URLs:
    /// - `http://localhost:3124` (no auth)
    /// - `http://user:password@sequencer.example.com:3124` (Basic Auth)
    pub fn new(raw_url: &str, prover_id: &str) -> anyhow::Result<Self> {
        let mut url = Url::parse(raw_url)?;
        let mut headers = HeaderMap::new();

        // Extract and strip credentials from URL
        let username = url.username().to_string();
        let password = url.password().map(|p| p.to_string());

        if !username.is_empty() {
            let auth_value = format!(
                "Basic {}",
                BASE64.encode(format!(
                    "{}:{}",
                    username,
                    password.as_deref().unwrap_or("")
                ))
            );
            headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value)?);
            // Strip credentials from URL for logging
            url.set_username("").ok();
            url.set_password(None).ok();
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .default_headers(headers)
            .build()?;

        Ok(Self {
            base_url: url,
            prover_id: prover_id.to_string(),
            client,
        })
    }

    pub fn url(&self) -> &str {
        self.base_url.as_str()
    }

    /// Pick the next assigned ZiSK batch from the server.
    ///
    /// Returns `None` if no batches are available.
    pub async fn pick_next_batch(&self) -> anyhow::Result<Option<ZiskBatchData>> {
        let url = format!(
            "{}prover-jobs/v1/ZiSK/pick?id={}",
            self.base_url, self.prover_id
        );

        let started_at = Instant::now();
        let resp = self.client.post(&url).send().await?;
        ZISK_PROVER_METRICS.http_latency[&Method::Pick].observe(started_at.elapsed());

        if resp.status() == reqwest::StatusCode::NO_CONTENT
            || resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
        {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!("ZiSK pick failed: {}", resp.status());
        }

        let pick: PickResponse = resp.json().await?;
        let zisk_data = BASE64.decode(&pick.zisk_data)?;

        Ok(Some(ZiskBatchData {
            batch_number: pick.batch_number,
            vk_hash: pick.vk_hash,
            zisk_data,
        }))
    }

    /// Submit a per-batch ZiSK proof. In per-batch mode `proof` is the
    /// PLONK-wrapped SNARK and `public_values` the 320-byte wire layout;
    /// in aggregated mode `proof` is the raw `vadcop_final` stream and
    /// `public_values` must be empty.
    ///
    /// No VK hash is sent: the server derives the reported VK from the
    /// proof bytes themselves, so the client has nothing to add.
    pub async fn submit_zisk_proof(
        &self,
        batch_number: u64,
        proof: &[u8],
        public_values: &[u8],
    ) -> anyhow::Result<()> {
        let payload = ZiskSubmitPayload {
            batch_number,
            proof: BASE64.encode(proof),
            public_values: BASE64.encode(public_values),
        };

        let url = format!(
            "{}prover-jobs/v1/ZiSK/submit?id={}",
            self.base_url, self.prover_id
        );

        let started_at = Instant::now();
        let resp = self.client.post(&url).json(&payload).send().await?;
        ZISK_PROVER_METRICS.http_latency[&Method::Submit].observe(started_at.elapsed());

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("ZiSK submit failed for batch {batch_number}: {body}");
        }

        Ok(())
    }

    /// Pick the next assigned ZiSK aggregation range from the server.
    ///
    /// Returns `None` if no ranges are available (or aggregation is not
    /// enabled server-side). The returned streams are validated to be in
    /// contiguous batch order.
    pub async fn pick_next_aggregation_job(
        &self,
    ) -> anyhow::Result<Option<ZiskAggregationJobData>> {
        let url = format!(
            "{}prover-jobs/v1/ZiSK-AGG/pick?id={}",
            self.base_url, self.prover_id
        );

        let started_at = Instant::now();
        let resp = self.client.post(&url).send().await?;
        ZISK_PROVER_METRICS.http_latency[&Method::PickAggregation].observe(started_at.elapsed());

        if resp.status() == reqwest::StatusCode::NO_CONTENT
            || resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
        {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!("ZiSK aggregation pick failed: {}", resp.status());
        }

        let pick: AggregationPickResponse = resp.json().await?;
        let (from_batch, to_batch) = (pick.from_batch_number, pick.to_batch_number);
        let expected: Vec<u64> = (from_batch..=to_batch).collect();
        let got: Vec<u64> = pick.proofs.iter().map(|p| p.batch_number).collect();
        anyhow::ensure!(
            got == expected,
            "aggregation job {from_batch}..{to_batch} carries batches {got:?}, expected {expected:?}"
        );
        let streams = pick
            .proofs
            .into_iter()
            .map(|p| Ok((p.batch_number, BASE64.decode(&p.proof)?)))
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Some(ZiskAggregationJobData {
            from_batch,
            to_batch,
            streams,
        }))
    }

    /// Submit an aggregated ZiSK range proof (768-byte SNARK + 320-byte
    /// public values of the aggregator guest).
    pub async fn submit_aggregated_proof(
        &self,
        from_batch: u64,
        to_batch: u64,
        proof: &[u8],
        public_values: &[u8],
    ) -> anyhow::Result<()> {
        let payload = AggregationSubmitPayload {
            from_batch_number: from_batch,
            to_batch_number: to_batch,
            proof: BASE64.encode(proof),
            public_values: BASE64.encode(public_values),
        };

        let url = format!(
            "{}prover-jobs/v1/ZiSK-AGG/submit?id={}",
            self.base_url, self.prover_id
        );

        let started_at = Instant::now();
        let resp = self.client.post(&url).json(&payload).send().await?;
        ZISK_PROVER_METRICS.http_latency[&Method::SubmitAggregation].observe(started_at.elapsed());

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "ZiSK aggregation submit failed for range {from_batch}..{to_batch}: {body}"
            );
        }

        Ok(())
    }
}
