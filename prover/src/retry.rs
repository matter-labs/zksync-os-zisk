use std::time::Duration;
use tokio_util::sync::CancellationToken;

const ATTEMPTS: u32 = 8;

pub(crate) async fn run<T>(
    cancel: &CancellationToken,
    mut operation: impl AsyncFnMut() -> anyhow::Result<T>,
    retryable: impl Fn(&anyhow::Error) -> bool,
) -> anyhow::Result<Option<T>> {
    let mut delay = Duration::from_secs(1);
    for attempt in 1..=ATTEMPTS {
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(None),
            result = operation() => result,
        };
        match result {
            Ok(value) => return Ok(Some(value)),
            Err(error) if attempt < ATTEMPTS && retryable(&error) => {
                tracing::warn!(attempt, retry_secs = delay.as_secs(), %error, "retrying current proving job operation");
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Ok(None),
                    _ = tokio::time::sleep(delay) => {}
                }
                delay = (delay * 2).min(Duration::from_secs(30));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn transient_failures_stop_after_bounded_backoff() {
        let started = tokio::time::Instant::now();
        let mut attempts = Vec::new();
        let result = run::<()>(
            &CancellationToken::new(),
            async || {
                attempts.push(started.elapsed().as_secs());
                anyhow::bail!("unavailable")
            },
            |_| true,
        )
        .await;
        assert_eq!(result.unwrap_err().to_string(), "unavailable");
        assert_eq!(attempts, [0, 1, 3, 7, 15, 31, 61, 91]);
    }

    #[tokio::test]
    async fn permanent_error_does_not_retry() {
        let mut attempts = 0;
        let result = run::<()>(
            &CancellationToken::new(),
            async || {
                attempts += 1;
                anyhow::bail!("invalid proof")
            },
            |_| false,
        )
        .await;
        assert_eq!(result.unwrap_err().to_string(), "invalid proof");
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn cancellation_prevents_starting_an_operation() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(
            run::<()>(&cancel, async || panic!("started after shutdown"), |_| true)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_backoff() {
        let cancel = CancellationToken::new();
        let started = tokio::time::Instant::now();
        let mut attempts = 0;
        let operation = run::<()>(
            &cancel,
            async || {
                attempts += 1;
                anyhow::bail!("unavailable")
            },
            |_| true,
        );
        let shutdown = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel.cancel();
        };
        let (result, ()) = tokio::join!(operation, shutdown);
        assert!(result.unwrap().is_none());
        assert_eq!(attempts, 1);
        assert_eq!(started.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test]
    async fn cancellation_interrupts_an_active_operation() {
        let cancel = CancellationToken::new();
        let mut attempts = 0;
        let result = run::<()>(
            &cancel,
            async || {
                attempts += 1;
                cancel.cancel();
                std::future::pending().await
            },
            |_| true,
        )
        .await;
        assert!(result.unwrap().is_none());
        assert_eq!(attempts, 1);
    }
}
