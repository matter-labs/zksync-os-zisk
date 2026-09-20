#![cfg(unix)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "zisk-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn recovery(coordinator: bool, aggregation: bool, statuses: &[u16]) {
    let dir = TestDir::new();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/real_proof_zisk_v1.2.0-alpha.bin");
    std::fs::copy(fixture, dir.0.join("fixture.bin")).unwrap();
    std::fs::write(dir.0.join("guest"), b"elf").unwrap();
    let binary = dir.0.join("cargo-zisk");
    // The CLI is the process boundary; the daemon still parses the real proof fixture.
    std::fs::write(&binary, format!(r#"#!/bin/sh
cd "$(dirname "$0")"
if [ "$1" = remote ]; then shift 3; fi
kind="$1"
echo "$kind" >> calls
if [ "$kind" = setup ]; then exit 0; fi
count=$(grep -c '^prove$' calls)
if [ {coordinator} = true ] && [ "$count" -le 3 ]; then
  echo "code: 'The service is currently unavailable', message: Cluster unavailable: insufficient ready capacity for the request" >&2
  exit 1
fi
while [ $# -gt 0 ]; do
  if [ "$1" = -o ]; then cp fixture.bin "$2"; exit 0; fi
  shift
done
exit 2
"#)).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let mut command = Command::new(env!("CARGO_BIN_EXE_zksync-os-zisk-prover-service"));
    command
        .args([
            "--sequencer-url",
            &url,
            "--iterations",
            "1",
            "--poll-interval-secs",
            "1",
            "--metrics-address",
            "127.0.0.1:0",
        ])
        .arg("--zisk-binary")
        .arg(&binary)
        .arg("--elf-path")
        .arg(dir.0.join("guest"))
        .arg("--work-dir")
        .arg(dir.0.join("proofs"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if coordinator {
        command.args(["--coordinator-url", "http://coordinator"]);
    } else {
        command
            .arg("--no-gpu")
            .arg("--proving-key")
            .arg(&dir.0)
            .arg("--proving-key-plonk")
            .arg(&dir.0);
    }
    if aggregation {
        command
            .arg("--aggregation")
            .arg("--aggregator-elf")
            .arg(dir.0.join("guest"));
    }
    let mut child = command.spawn().unwrap();
    let server = async {
        let mut picked = false;
        let mut submissions = Vec::new();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let (header_end, length) = loop {
                let mut buf = [0; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&request[..end]).to_lowercase();
                    let length = header
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .unwrap_or("0")
                        .parse::<usize>()
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while request.len() < header_end + length {
                let mut buf = [0; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
            }
            let header = String::from_utf8_lossy(&request[..header_end]);
            let (status, body) = if header.contains("/pick?") {
                assert!(!picked, "daemon abandoned the current job and picked again");
                picked = true;
                let body = if aggregation {
                    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/data/real_vadcop_final_zisk_v1.2.0-alpha.bin");
                    let stream =
                        zksync_os_zisk_prover_service::aggregator_input::load_proof_stream(&path)
                            .unwrap();
                    serde_json::json!({"from_batch_number":1,"to_batch_number":1,"vk_hash":"", "proofs":[{"batch_number":1,"proof":STANDARD.encode(stream)}]})
                } else {
                    serde_json::json!({"batch_number":1,"vk_hash":"", "zisk_data":STANDARD.encode(b"input")})
                };
                (200, body.to_string())
            } else {
                assert!(header.contains("/submit?"), "unexpected request: {header}");
                let body = &request[header_end..header_end + length];
                if let Some(previous) = submissions.first() {
                    assert_eq!(previous, body, "submission retry changed the proof");
                }
                let status = statuses.get(submissions.len()).copied().unwrap_or(200);
                submissions.push(body.to_vec());
                (status, "{}".to_string())
            };
            if status == 0 {
                continue;
            }
            socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            if status == 200 && !submissions.is_empty() {
                return submissions.len();
            }
        }
    };
    let submissions = tokio::time::timeout(Duration::from_secs(25), server)
        .await
        .expect("job did not recover");
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success(), "daemon failed: {status}");
    assert_eq!(submissions, statuses.len() + 1);
    let calls = std::fs::read_to_string(dir.0.join("calls")).unwrap();
    assert_eq!(
        calls.lines().filter(|line| *line == "prove").count(),
        if coordinator { 4 } else { 1 }
    );
}

#[tokio::test]
async fn coordinator_waits_for_capacity_despite_cached_setup() {
    recovery(true, false, &[]).await;
}

#[tokio::test]
async fn batch_submission_retries_same_proof_without_picking_or_proving_again() {
    recovery(false, false, &[503, 429, 502]).await;
}

#[tokio::test]
async fn range_submission_retries_same_proof_without_picking_or_proving_again() {
    recovery(false, true, &[0, 503, 408]).await;
}

#[tokio::test]
async fn coordinator_range_waits_for_capacity_despite_cached_setup() {
    recovery(true, true, &[]).await;
}
