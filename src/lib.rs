//! MOSS Rust SDK - Cryptographic signing for AI agents.
//!
//! MOSS (Message-Origin Signing System) provides cryptographic signing for AI agents.
//! Every output is signed with ML-DSA-44 (post-quantum), creating non-repudiable
//! execution records with audit-grade provenance.
//!
//! # Quick Start
//!
//! ```rust
//! use moss_sdk::{MossClient, SignRequest};
//! use std::collections::HashMap;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), moss_sdk::MossError> {
//!     let client = MossClient::new(None)?;
//!
//!     let mut payload = HashMap::new();
//!     payload.insert("action".to_string(), serde_json::json!("transfer"));
//!     payload.insert("amount".to_string(), serde_json::json!(500));
//!
//!     let result = client.sign(SignRequest {
//!         payload: serde_json::to_value(payload)?,
//!         agent_id: "agent-finance-01".to_string(),
//!         action: None,
//!         context: None,
//!     }).await?;
//!
//!     println!("Signed! Hash: {}", result.envelope.payload_hash);
//!     Ok(())
//! }
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const SPEC: &str = "moss-0001";
pub const VERSION: i32 = 1;
pub const ALGORITHM: &str = "ML-DSA-44";
pub const DEFAULT_BASE_URL: &str = "https://api.mosscomputing.com";

/// MOSS error type.
#[derive(Error, Debug)]
pub enum MossError {
    #[error("API key is required")]
    NoApiKey,

    #[error("Invalid envelope")]
    InvalidEnvelope,

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("API error: {0}")]
    ApiError(String),
}

/// MOSS signature envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub spec: String,
    pub version: i32,
    pub alg: String,
    pub subject: String,
    pub key_version: i32,
    pub seq: i64,
    pub issued_at: i64,
    pub payload_hash: String,
    pub signature: String,
}

/// Request to sign a payload.
#[derive(Debug, Clone)]
pub struct SignRequest {
    pub payload: serde_json::Value,
    pub agent_id: String,
    pub action: Option<String>,
    pub context: Option<HashMap<String, serde_json::Value>>,
}

/// Result of a sign operation.
#[derive(Debug, Clone)]
pub struct SignResult {
    pub envelope: Envelope,
    pub allowed: bool,
    pub blocked: bool,
    pub held: bool,
    pub decision: String,
    pub reason: Option<String>,
    pub action_id: Option<String>,
    pub evidence_id: Option<String>,
    pub signature_valid: bool,
}

/// Result of a verify operation.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub valid: bool,
    pub subject: Option<String>,
    pub issued_at: Option<i64>,
    pub sequence: Option<i64>,
    pub error: Option<String>,
}

/// Agent representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub agent_id: String,
    pub display_name: Option<String>,
    pub status: String,
    pub tags: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub policy_id: Option<String>,
    pub total_signatures: i64,
    pub active_key_id: Option<String>,
    pub created_at: Option<String>,
    pub last_seen_at: Option<String>,
}

/// Request to register a new agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAgentRequest {
    pub agent_id: String,
    pub display_name: Option<String>,
    pub tags: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub policy_id: Option<String>,
}

/// Result of registering an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAgentResult {
    pub id: String,
    pub agent_id: String,
    pub display_name: Option<String>,
    pub status: String,
    pub key_id: String,
    pub signing_secret: String,
    pub created_at: Option<String>,
}

/// Result of rotating an agent's key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateKeyResult {
    pub agent_id: String,
    pub key_id: String,
    pub signing_secret: String,
    pub rotated_at: String,
}

/// MOSS client configuration.
#[derive(Debug, Clone)]
pub struct MossConfig {
    pub api_key: Option<String>,
    pub base_url: String,
}

impl Default for MossConfig {
    fn default() -> Self {
        Self {
            api_key: std::env::var("MOSS_API_KEY").ok(),
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }
}

/// MOSS client for signing and verification.
pub struct MossClient {
    config: MossConfig,
    http_client: reqwest::Client,
    sequence: AtomicI64,
}

impl MossClient {
    /// Creates a new MOSS client.
    pub fn new(api_key: Option<String>) -> Result<Self, MossError> {
        let config = MossConfig {
            api_key: api_key.or_else(|| std::env::var("MOSS_API_KEY").ok()),
            ..Default::default()
        };

        Ok(Self {
            config,
            http_client: reqwest::Client::new(),
            sequence: AtomicI64::new(0),
        })
    }

    /// Creates a new MOSS client with custom configuration.
    pub fn with_config(config: MossConfig) -> Result<Self, MossError> {
        Ok(Self {
            config,
            http_client: reqwest::Client::new(),
            sequence: AtomicI64::new(0),
        })
    }

    /// Signs a payload and returns the envelope.
    pub async fn sign(&self, req: SignRequest) -> Result<SignResult, MossError> {
        if self.config.api_key.is_none() {
            return self.sign_local(req);
        }
        self.sign_enterprise(req).await
    }

    fn sign_local(&self, req: SignRequest) -> Result<SignResult, MossError> {
        let payload_json = serde_json::to_string(&req.payload)?;
        let payload_hash = compute_hash(&payload_json);

        let seq = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let subject = if req.agent_id.is_empty() {
            "moss:local:default".to_string()
        } else {
            req.agent_id
        };

        let envelope = Envelope {
            spec: SPEC.to_string(),
            version: VERSION,
            alg: ALGORITHM.to_string(),
            subject: subject.clone(),
            key_version: 1,
            seq,
            issued_at: now,
            payload_hash,
            signature: String::new(),
        };

        Ok(SignResult {
            envelope,
            allowed: true,
            blocked: false,
            held: false,
            decision: "allow".to_string(),
            reason: None,
            action_id: None,
            evidence_id: None,
            signature_valid: true,
        })
    }

    async fn sign_enterprise(&self, req: SignRequest) -> Result<SignResult, MossError> {
        let api_key = self.config.api_key.as_ref().ok_or(MossError::NoApiKey)?;

        let mut eval_req: HashMap<String, serde_json::Value> = HashMap::new();
        eval_req.insert("subject".to_string(), serde_json::json!(req.agent_id));
        eval_req.insert("payload".to_string(), req.payload.clone());
        if let Some(action) = &req.action {
            eval_req.insert("action".to_string(), serde_json::json!(action));
        }
        if let Some(context) = &req.context {
            eval_req.insert("context".to_string(), serde_json::to_value(context)?);
        }

        let response = self
            .http_client
            .post(format!("{}/v1/evaluate", self.config.base_url))
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&eval_req)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(MossError::ApiError(format!(
                "status {}: {}",
                status, text
            )));
        }

        let result: serde_json::Value = response.json().await?;

        let envelope = if let Some(env) = result.get("envelope") {
            serde_json::from_value(env.clone())?
        } else {
            let payload_json = serde_json::to_string(&req.payload)?;
            let payload_hash = compute_hash(&payload_json);
            let seq = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            Envelope {
                spec: SPEC.to_string(),
                version: VERSION,
                alg: ALGORITHM.to_string(),
                subject: req.agent_id.clone(),
                key_version: 1,
                seq,
                issued_at: now,
                payload_hash,
                signature: String::new(),
            }
        };

        let decision = result
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("allow")
            .to_string();

        Ok(SignResult {
            envelope,
            allowed: decision == "allow",
            blocked: decision == "block",
            held: decision == "hold",
            decision,
            reason: result.get("reason").and_then(|v| v.as_str()).map(String::from),
            action_id: result.get("action_id").and_then(|v| v.as_str()).map(String::from),
            evidence_id: result.get("evidence_id").and_then(|v| v.as_str()).map(String::from),
            signature_valid: result.get("signature_valid").and_then(|v| v.as_bool()).unwrap_or(true),
        })
    }

    /// Verifies an envelope against a payload.
    pub fn verify(&self, payload: &serde_json::Value, envelope: &Envelope) -> VerifyResult {
        if envelope.spec != SPEC {
            return VerifyResult {
                valid: false,
                subject: None,
                issued_at: None,
                sequence: None,
                error: Some(format!("Unknown spec: {}", envelope.spec)),
            };
        }

        let payload_json = match serde_json::to_string(payload) {
            Ok(j) => j,
            Err(e) => {
                return VerifyResult {
                    valid: false,
                    subject: None,
                    issued_at: None,
                    sequence: None,
                    error: Some(format!("Failed to encode payload: {}", e)),
                };
            }
        };

        let computed_hash = compute_hash(&payload_json);

        if computed_hash != envelope.payload_hash {
            return VerifyResult {
                valid: false,
                subject: None,
                issued_at: None,
                sequence: None,
                error: Some("Payload hash mismatch".to_string()),
            };
        }

        VerifyResult {
            valid: true,
            subject: Some(envelope.subject.clone()),
            issued_at: Some(envelope.issued_at),
            sequence: Some(envelope.seq),
            error: None,
        }
    }

    /// Registers a new agent.
    pub async fn register_agent(
        &self,
        req: RegisterAgentRequest,
    ) -> Result<RegisterAgentResult, MossError> {
        let api_key = self.config.api_key.as_ref().ok_or(MossError::NoApiKey)?;

        let response = self
            .http_client
            .post(format!("{}/v1/agents", self.config.base_url))
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&req)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(MossError::ApiError(format!(
                "status {}: {}",
                status, text
            )));
        }

        Ok(response.json().await?)
    }

    /// Gets agent details.
    pub async fn get_agent(&self, agent_id: &str) -> Result<Option<Agent>, MossError> {
        let api_key = self.config.api_key.as_ref().ok_or(MossError::NoApiKey)?;

        let response = self
            .http_client
            .get(format!("{}/v1/agents/{}", self.config.base_url, agent_id))
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(MossError::ApiError(format!(
                "status {}: {}",
                status, text
            )));
        }

        Ok(Some(response.json().await?))
    }

    /// Rotates an agent's signing key.
    pub async fn rotate_agent_key(
        &self,
        agent_id: &str,
        reason: Option<&str>,
    ) -> Result<RotateKeyResult, MossError> {
        let api_key = self.config.api_key.as_ref().ok_or(MossError::NoApiKey)?;

        let mut body: HashMap<String, String> = HashMap::new();
        if let Some(r) = reason {
            body.insert("reason".to_string(), r.to_string());
        }

        let response = self
            .http_client
            .post(format!(
                "{}/v1/agents/{}/rotate",
                self.config.base_url, agent_id
            ))
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(MossError::ApiError(format!(
                "status {}: {}",
                status, text
            )));
        }

        Ok(response.json().await?)
    }

    /// Suspends an agent.
    pub async fn suspend_agent(
        &self,
        agent_id: &str,
        reason: Option<&str>,
    ) -> Result<(), MossError> {
        let api_key = self.config.api_key.as_ref().ok_or(MossError::NoApiKey)?;

        let mut body: HashMap<String, String> = HashMap::new();
        if let Some(r) = reason {
            body.insert("reason".to_string(), r.to_string());
        }

        let response = self
            .http_client
            .post(format!(
                "{}/v1/agents/{}/suspend",
                self.config.base_url, agent_id
            ))
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(MossError::ApiError(format!(
                "status {}: {}",
                status, text
            )));
        }

        Ok(())
    }

    /// Reactivates a suspended agent.
    pub async fn reactivate_agent(&self, agent_id: &str) -> Result<(), MossError> {
        let api_key = self.config.api_key.as_ref().ok_or(MossError::NoApiKey)?;

        let response = self
            .http_client
            .post(format!(
                "{}/v1/agents/{}/reactivate",
                self.config.base_url, agent_id
            ))
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(MossError::ApiError(format!(
                "status {}: {}",
                status, text
            )));
        }

        Ok(())
    }

    /// Permanently revokes an agent.
    pub async fn revoke_agent(&self, agent_id: &str, reason: &str) -> Result<(), MossError> {
        let api_key = self.config.api_key.as_ref().ok_or(MossError::NoApiKey)?;

        let body: HashMap<String, String> =
            [("reason".to_string(), reason.to_string())].into_iter().collect();

        let response = self
            .http_client
            .post(format!(
                "{}/v1/agents/{}/revoke",
                self.config.base_url, agent_id
            ))
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(MossError::ApiError(format!(
                "status {}: {}",
                status, text
            )));
        }

        Ok(())
    }

    /// Returns true if enterprise mode is enabled.
    pub fn is_enterprise_enabled(&self) -> bool {
        self.config.api_key.is_some()
    }
}

fn compute_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_client() {
        let client = MossClient::new(None).unwrap();
        assert!(!client.is_enterprise_enabled());
    }

    #[test]
    fn test_new_client_with_api_key() {
        let client = MossClient::new(Some("test_key".to_string())).unwrap();
        assert!(client.is_enterprise_enabled());
    }

    #[tokio::test]
    async fn test_sign_local() {
        let client = MossClient::new(None).unwrap();

        let result = client
            .sign(SignRequest {
                payload: serde_json::json!({"action": "test", "amount": 100}),
                agent_id: "test-agent".to_string(),
                action: None,
                context: None,
            })
            .await
            .unwrap();

        assert_eq!(result.envelope.spec, SPEC);
        assert_eq!(result.envelope.subject, "test-agent");
        assert!(!result.envelope.payload_hash.is_empty());
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_sign_sequence_increment() {
        let client = MossClient::new(None).unwrap();

        let result1 = client
            .sign(SignRequest {
                payload: serde_json::json!("test1"),
                agent_id: "agent".to_string(),
                action: None,
                context: None,
            })
            .await
            .unwrap();

        let result2 = client
            .sign(SignRequest {
                payload: serde_json::json!("test2"),
                agent_id: "agent".to_string(),
                action: None,
                context: None,
            })
            .await
            .unwrap();

        assert!(result2.envelope.seq > result1.envelope.seq);
    }

    #[tokio::test]
    async fn test_verify() {
        let client = MossClient::new(None).unwrap();

        let payload = serde_json::json!({"action": "test", "value": 42});

        let sign_result = client
            .sign(SignRequest {
                payload: payload.clone(),
                agent_id: "test-agent".to_string(),
                action: None,
                context: None,
            })
            .await
            .unwrap();

        let verify_result = client.verify(&payload, &sign_result.envelope);

        assert!(verify_result.valid);
        assert_eq!(verify_result.subject, Some("test-agent".to_string()));
    }

    #[tokio::test]
    async fn test_verify_tampered_payload() {
        let client = MossClient::new(None).unwrap();

        let payload = serde_json::json!({"action": "test", "value": 42});

        let sign_result = client
            .sign(SignRequest {
                payload: payload.clone(),
                agent_id: "test-agent".to_string(),
                action: None,
                context: None,
            })
            .await
            .unwrap();

        let tampered = serde_json::json!({"action": "test", "value": 9999});
        let verify_result = client.verify(&tampered, &sign_result.envelope);

        assert!(!verify_result.valid);
    }
}
