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
use tokio_util::sync::CancellationToken;
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
    pub vk_hash: String,
    pub streams: Vec<(u64, Vec<u8>)>,
}

/// HTTP client for the server's prover API.
pub struct SequencerClient {
    base_url: Url,
    prover_id: String,
    supported_vk_hashes: Vec<String>,
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
    #[serde(default)]
    vk_hash: String,
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
    pub fn new(
        raw_url: &str,
        prover_id: &str,
        supported_vk_hashes: &[String],
    ) -> anyhow::Result<Self> {
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
            supported_vk_hashes: supported_vk_hashes.to_vec(),
            client,
        })
    }

    pub fn url(&self) -> &str {
        self.base_url.as_str()
    }

    fn pick_url(&self, endpoint: &str) -> Url {
        let mut url = self
            .base_url
            .join(&format!("prover-jobs/v1/{endpoint}"))
            .expect("a valid base URL always accepts a relative API path");
        let mut query = url.query_pairs_mut();
        query.append_pair("id", &self.prover_id);
        if !self.supported_vk_hashes.is_empty() {
            let hashes = self
                .supported_vk_hashes
                .iter()
                .map(|hash| {
                    let hash = hash
                        .strip_prefix("0x")
                        .or_else(|| hash.strip_prefix("0X"))
                        .unwrap_or(hash);
                    format!("0x{hash}")
                })
                .collect::<Vec<_>>()
                .join(",");
            query.append_pair("supported_vk_hashes", &hashes);
        }
        drop(query);
        url
    }

    /// Pick the next assigned ZiSK batch from the server.
    ///
    /// Returns `None` if no batches are available.
    pub async fn pick_next_batch(&self) -> anyhow::Result<Option<ZiskBatchData>> {
        let url = self.pick_url("ZiSK/pick");

        let started_at = Instant::now();
        let resp = self.client.post(url).send().await?;
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
        cancel: &CancellationToken,
    ) -> anyhow::Result<bool> {
        let payload = ZiskSubmitPayload {
            batch_number,
            proof: BASE64.encode(proof),
            public_values: BASE64.encode(public_values),
        };

        let url = format!(
            "{}prover-jobs/v1/ZiSK/submit?id={}",
            self.base_url, self.prover_id
        );

        self.submit(&url, &payload, Method::Submit, cancel).await
    }

    /// Pick the next assigned ZiSK aggregation range from the server.
    ///
    /// Returns `None` if no ranges are available (or aggregation is not
    /// enabled server-side). The returned streams are validated to be in
    /// contiguous batch order.
    pub async fn pick_next_aggregation_job(
        &self,
    ) -> anyhow::Result<Option<ZiskAggregationJobData>> {
        let url = self.pick_url("ZiSK-AGG/pick");

        let started_at = Instant::now();
        let resp = self.client.post(url).send().await?;
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
            vk_hash: pick.vk_hash,
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
        cancel: &CancellationToken,
    ) -> anyhow::Result<bool> {
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

        self.submit(&url, &payload, Method::SubmitAggregation, cancel)
            .await
    }

    async fn submit(
        &self,
        url: &str,
        payload: &impl Serialize,
        method: Method,
        cancel: &CancellationToken,
    ) -> anyhow::Result<bool> {
        let result = crate::retry::run(
            cancel,
            async || {
                let started_at = Instant::now();
                let resp = self.client.post(url).json(payload).send().await?;
                ZISK_PROVER_METRICS.http_latency[&method].observe(started_at.elapsed());
                let status = resp.status();
                if let Err(error) = resp.error_for_status_ref() {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(anyhow::Error::new(error)
                        .context(format!("proof submission rejected: {body}")));
                }
                anyhow::ensure!(status.is_success(), "proof submission rejected: {status}");
                Ok(())
            },
            |error| {
                error
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(|error| match error.status() {
                        Some(status) => {
                            status.is_server_error()
                                || status == reqwest::StatusCode::REQUEST_TIMEOUT
                                || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        }
                        None => {
                            error.is_timeout()
                                || error.is_connect()
                                || error.is_request()
                                || error.is_body()
                        }
                    })
            },
        )
        .await?;
        Ok(result.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::SequencerClient;

    #[tokio::test]
    async fn permanent_submit_rejections_are_returned_without_retry() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        for status in [302, 400, 401, 403, 409, 422] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = SequencerClient::new(
                &format!("http://{}", listener.local_addr().unwrap()),
                "p",
                &[],
            )
            .unwrap();
            let server = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert!(socket.read_line(&mut line).await.unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                socket.read_exact(&mut vec![0; length]).await.unwrap();
                socket.write_all(format!("HTTP/1.1 {status} Rejected\r\nContent-Length: 8\r\nConnection: close\r\n\r\nrejected").as_bytes()).await.unwrap();
            };
            let cancel = tokio_util::sync::CancellationToken::new();
            let submit = client.submit_zisk_proof(1, b"proof", b"values", &cancel);
            let (result, ()) = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                tokio::join!(submit, server)
            })
            .await
            .expect("permanent rejection entered retry backoff");
            let error = result.unwrap_err();
            assert!(error.to_string().contains("submission rejected"));
        }
    }

    #[test]
    fn pick_urls_advertise_complete_zisk_identities() {
        let first = "11".repeat(32);
        let second = "22".repeat(32);
        let client = SequencerClient::new(
            "http://localhost:3124",
            "prover one",
            &[first.clone(), second.clone()],
        )
        .unwrap();

        for endpoint in ["ZiSK/pick", "ZiSK-AGG/pick"] {
            let url = client.pick_url(endpoint);
            let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
            assert_eq!(query.get("id").unwrap(), "prover one");
            assert_eq!(
                query.get("supported_vk_hashes").unwrap(),
                &format!("0x{first},0x{second}")
            );
        }
    }

    #[test]
    fn empty_capability_list_keeps_legacy_pick_query() {
        let client = SequencerClient::new("http://localhost:3124", "p", &[]).unwrap();
        let url = client.pick_url("ZiSK/pick");
        assert_eq!(url.query(), Some("id=p"));
    }
}
