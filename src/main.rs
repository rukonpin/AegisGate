use std::{
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
    serve,
};
use governor::{Quota, RateLimiter};
use regex::Regex;
use reqwest::StatusCode;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[derive(Debug, Serialize, Clone)]
enum AuditAction {
    Allowed,
    PiiRedacted,
    PromptInjectionBlocked,
    RateLimitExceeded,
}

#[derive(Default)]
struct AppMetrics {
    requests_total: AtomicU64,
    injections_blocked_total: AtomicU64,
    pii_redacted_total: AtomicU64,
    rate_limited_total: AtomicU64,
}

#[derive(Debug, Serialize, Clone)]
struct AuditEvent {
    timestamp: String,
    action: AuditAction,
    client_ip: String,
    model: String,
    details: String,
}

static EMAIL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+").unwrap());

static API_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-[a-zA-Z0-9]{20,}").unwrap());

static CREDIT_CARD_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{4}[ -]?){3}\d{4}\b").unwrap());

type GlobalLimiter = RateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

#[derive(Clone)]
struct AppState {
    http_client: reqwest::Client,
    upstream_url: String,
    limiter: Arc<GlobalLimiter>,
    audit_tx: mpsc::Sender<AuditEvent>,
    metrics: Arc<AppMetrics>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let metrics = Arc::new(AppMetrics::default());
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEvent>(1000);

    let quota = Quota::with_period(Duration::from_secs(2)).unwrap();
    let limiter = Arc::new(RateLimiter::direct(quota));

    let state = AppState {
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap(),
        upstream_url: "https://httpbin.org/post".to_string(),
        limiter,
        audit_tx,
        metrics,
    };

    tokio::spawn(async move {
        while let Some(event) = audit_rx.recv().await {
            let json_event = serde_json::to_string(&event).unwrap();
            tracing::warn!(target: "security_audit", "[AUDIT_EVENT] {}", json_event);
        }
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/v1/chat/completions", post(proxy_handler))
        .route("/v1/models", get(models_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
    serve(listener, app).await.unwrap();
}

async fn health_check() -> &'static str {
    "AegisGate is healthy"
}

async fn proxy_handler(
    State(state): State<AppState>,
    Json(mut payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    if state.limiter.check().is_err() {
        let _ = state.audit_tx.try_send(AuditEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            action: AuditAction::RateLimitExceeded,
            client_ip: "127.0.0.1".to_string(),
            model: "gpt-4".to_string(),
            details: "Detected signature: rate limit per client IP reached".to_string(),
        });

        state
            .metrics
            .rate_limited_total
            .fetch_add(1, Ordering::Relaxed);

        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "Too Many Requests: Rate limit exceeded. Please slow down.",
                "code": "OWASP_LLM04"
            })),
        ));
    }

    if let Some(messages) = payload.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for msg in messages {
            if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                if detect_prompt_injection(content) {
                    let _ = state.audit_tx.try_send(AuditEvent {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        action: AuditAction::PromptInjectionBlocked,
                        client_ip: "127.0.0.1".to_string(),
                        model: "gpt-4".to_string(),
                        details: "Detected signature: ignore previous instruction".to_string(),
                    });

                    state
                        .metrics
                        .injections_blocked_total
                        .fetch_add(1, Ordering::Relaxed);

                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": "Access Denied: Prompt Injection or Jailbreak detected by AegisGate WAF",
                            "code": "OWASP_LLM01"
                        })),
                    ));
                }

                let cleaned = sanitize_text(content);

                if cleaned != content {
                    let _ = state.audit_tx.try_send(AuditEvent {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        action: AuditAction::PiiRedacted,
                        client_ip: "127.0.0.1".to_string(),
                        model: "gpt-4".to_string(),
                        details: "Detected signature: sensitive data redacted to prevent PII leak"
                            .to_string(),
                    });

                    state
                        .metrics
                        .pii_redacted_total
                        .fetch_add(1, Ordering::Relaxed);
                }

                msg["content"] = serde_json::Value::String(cleaned);
            }
        }
    }

    let response = state
        .http_client
        .post(&state.upstream_url)
        .json(&payload)
        .send()
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "Upstream service unavailable" })),
            )
        })?;

    let res_json = response.json::<serde_json::Value>().await.map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "Upstream service unavailable" })),
        )
    })?;

    let _ = state.audit_tx.try_send(AuditEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        action: AuditAction::Allowed,
        client_ip: "127.0.0.1".to_string(),
        model: "gpt-4".to_string(),
        details: "Detected signature: request allowed and forwarded to upstream model".to_string(),
    });

    Ok(Json(res_json))
}

async fn models_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "object": "list",
        "data": [
            {"id": "gpt-4o", "object": "model"},
            { "id": "llama-3.3-70b", "object": "model" }
        ]
    }))
}

fn sanitize_text(text: &str) -> String {
    let text = EMAIL_REGEX.replace_all(text, "[REDACTED_EMAIL]");
    let text = API_KEY_REGEX.replace_all(&text, "[REDACTED_API_KEY]");
    let text = CREDIT_CARD_REGEX.replace_all(&text, "[REDACTED_CREDIT_CARD]");
    text.into_owned()
}

fn detect_prompt_injection(text: &str) -> bool {
    let lower = text.to_lowercase();
    let signatures = [
        "ignore all previous",
        "ignore previous instructions",
        "system prompt",
        "developer mode",
        "do anything now",
        "dan mode",
    ];

    signatures.iter().any(|&sig| lower.contains(sig))
}

async fn metrics_handler(State(state): State<AppState>) -> String {
    format!(
        "# HELP aegisgate_requests_total Total number of incoming HTTP requests\n\
         # TYPE aegisgate_requests_total counter\n\
         aegisgate_requests_total {}\n\n\
         # HELP aegisgate_injections_blocked_total Blocked prompt injections\n\
         # TYPE aegisgate_injections_blocked_total counter\n\
         aegisgate_injections_blocked_total {}\n\n\
         # HELP aegisgate_pii_redacted_total Masked PII data leaks\n\
         # TYPE aegisgate_pii_redacted_total counter\n\
         aegisgate_pii_redacted_total {}\n\n\
         # HELP aegisgate_rate_limited_total Blocked rate limit requests\n\
         # TYPE aegisgate_rate_limited_total counter\n\
         aegisgate_rate_limited_total {}\n",
        state.metrics.requests_total.load(Ordering::Relaxed),
        state
            .metrics
            .injections_blocked_total
            .load(Ordering::Relaxed),
        state.metrics.pii_redacted_total.load(Ordering::Relaxed),
        state.metrics.rate_limited_total.load(Ordering::Relaxed),
    )
}
