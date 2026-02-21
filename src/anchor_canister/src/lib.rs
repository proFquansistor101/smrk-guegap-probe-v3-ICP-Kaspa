use candid::{CandidType, Decode, Encode};
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
    SignWithEcdsaArgument,
};
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse,
    TransformArgs, TransformContext,
};
use ic_cdk_macros::{query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, DefaultMemoryImpl, StableCell, Storable};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;

// -------------------- Candid types --------------------

#[derive(CandidType, Deserialize, Clone)]
pub struct KaspaEndpoint {
    pub base_url: String,
    pub api_key: Option<String>,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct AnchorRunArgs {
    pub run_id: String,
    pub kaspa_network: String,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct AnchorRunResult {
    pub ok: bool,
    pub msg: String,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct AnchorAddressView {
    pub address_hint: String,
    pub pubkey_hex: String,
}

// -------------------- Registry types (subset; must match registry.did) --------------------

#[derive(CandidType, Deserialize, Clone)]
pub enum AnchorStatus {
    none,
    pending,
    broadcasted(String),
    confirmed {
        txid: String,
        confirmations: u32,
        block_time: Option<u64>,
    },
    failed(String),
}

#[derive(CandidType, Deserialize, Clone)]
pub struct AnchorRecord {
    pub run_id: String,
    pub anchor_commitment_hex: String,
    pub kaspa_network: String,
    pub status: AnchorStatus,
    pub created_at_ns: u64,
    pub updated_at_ns: u64,
}

#[derive(CandidType, Deserialize)]
pub struct RequestAnchorArgs {
    pub run_id: String,
    pub kaspa_network: String,
}

#[derive(CandidType, Deserialize)]
pub struct SetAnchorResultArgs {
    pub run_id: String,
    pub anchor_commitment_hex: String,
    pub status: AnchorStatus,
}

// -------------------- Stable endpoint storage --------------------

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEM_MGR: std::cell::RefCell<MemoryManager<DefaultMemoryImpl>> =
        std::cell::RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static ENDPOINT: std::cell::RefCell<StableCell<KaspaEndpointStable, Memory>> = std::cell::RefCell::new(
        StableCell::init(with_mem(MemoryId::new(0)), KaspaEndpointStable::default()).expect("init endpoint cell")
    );
}

fn with_mem(id: MemoryId) -> Memory {
    MEM_MGR.with(|m| m.borrow().get(id))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct KaspaEndpointStable {
    base_url: String,
    api_key: Option<String>,
}

impl Default for KaspaEndpointStable {
    fn default() -> Self {
        Self { base_url: "".into(), api_key: None }
    }
}

impl Storable for KaspaEndpointStable {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).expect("encode endpoint"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, KaspaEndpointStable).expect("decode endpoint")
    }
}

impl BoundedStorable for KaspaEndpointStable {
    const MAX_SIZE: u32 = 8_192;
    const IS_FIXED_SIZE: bool = false;
}

fn get_endpoint() -> KaspaEndpointStable {
    ENDPOINT.with(|c| c.borrow().get().clone())
}

fn set_endpoint(ep: KaspaEndpointStable) {
    ENDPOINT.with(|c| c.borrow_mut().set(ep).expect("set endpoint"));
}

// -------------------- Helpers --------------------

fn key_name() -> String {
    // Local dev uses dfx_test_key. Mainnet uses key_1 / test_key_1.
    option_env!("IC_ECDSA_KEY_NAME").unwrap_or("dfx_test_key").to_string()
}

fn decode_hex_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).unwrap_or_default();
    if bytes.len() != 32 {
        ic_cdk::trap("expected 32-byte hex");
    }
    bytes.try_into().unwrap()
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn json_get_field_string(body: &[u8], field: &str) -> Option<String> {
    let s = String::from_utf8_lossy(body);
    let needle = format!("\"{}\"", field);
    let idx = s.find(&needle)?;
    let after = &s[idx + needle.len()..];
    let colon = after.find(':')?;
    let mut rest = after[colon + 1..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    rest = &rest[1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// -------------------- HTTP transform --------------------

#[query]
fn transform(args: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: args.response.status,
        headers: vec![],
        body: args.response.body,
    }
}

// -------------------- Public API --------------------

#[update]
fn set_kaspa_endpoint(ep: KaspaEndpoint) {
    let caller = ic_cdk::caller();
    if caller != ic_cdk::id() && !ic_cdk::api::is_controller(&caller) {
        ic_cdk::trap("forbidden: controller only");
    }
    set_endpoint(KaspaEndpointStable { base_url: ep.base_url, api_key: ep.api_key });
}

#[update]
async fn get_anchor_address() -> AnchorAddressView {
    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: key_name(),
    };

    let arg = EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: vec![b"qfc".to_vec(), b"kaspa".to_vec()],
        key_id,
    };

    let (res,) = ecdsa_public_key(arg)
        .await
        .unwrap_or_else(|e| ic_cdk::trap(&format!("ecdsa_public_key failed: {:?}", e)));

    AnchorAddressView {
        address_hint: "TODO: derive kaspa address from secp256k1 pubkey".to_string(),
        pubkey_hex: hex::encode(res.public_key),
    }
}

#[update]
async fn anchor_run(args: AnchorRunArgs) -> AnchorRunResult {
    let ep = get_endpoint();
    if ep.base_url.trim().is_empty() {
        return AnchorRunResult { ok: false, msg: "kaspa endpoint not set".into() };
    }

    // 1) request anchor record from registry (computes anchor_commitment_hex)
    let (anchor_rec,): (AnchorRecord,) = match ic_cdk::call(
        "registry_canister",
        "request_anchor",
        (RequestAnchorArgs { run_id: args.run_id.clone(), kaspa_network: args.kaspa_network.clone() },),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return AnchorRunResult { ok: false, msg: format!("registry.request_anchor failed: {:?}", e) },
    };

    // 2) sign commitment with tECDSA
    let commitment = decode_hex_32(&anchor_rec.anchor_commitment_hex);
    let msg_hash = sha256_bytes(&commitment);

    let key_id = EcdsaKeyId { curve: EcdsaCurve::Secp256k1, name: key_name() };

    let sig_arg = SignWithEcdsaArgument {
        message_hash: msg_hash.to_vec(),
        derivation_path: vec![b"qfc".to_vec(), b"kaspa".to_vec()],
        key_id: key_id.clone(),
    };

    let sig_res = match sign_with_ecdsa(sig_arg).await {
        Ok((sig,)) => sig,
        Err(e) => {
            let _ : (bool,) = ic_cdk::call(
                "registry_canister",
                "set_anchor_result",
                (SetAnchorResultArgs {
                    run_id: anchor_rec.run_id.clone(),
                    anchor_commitment_hex: anchor_rec.anchor_commitment_hex.clone(),
                    status: AnchorStatus::failed(format!("sign_with_ecdsa failed: {:?}", e)),
                },),
            )
            .await
            .unwrap_or((false,));

            return AnchorRunResult { ok: false, msg: format!("sign_with_ecdsa failed: {:?}", e) };
        }
    };

    // 3) pubkey (for proxy verification)
    let (pub_res,) = ecdsa_public_key(EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: vec![b"qfc".to_vec(), b"kaspa".to_vec()],
        key_id,
    })
    .await
    .unwrap_or_else(|e| ic_cdk::trap(&format!("ecdsa_public_key failed: {:?}", e)));

    let pubkey_hex = hex::encode(pub_res.public_key);
    let signature_hex = hex::encode(sig_res.signature);

    // 4) HTTP outcall to proxy
    let url = format!("{}/broadcast", ep.base_url.trim_end_matches('/'));
    let body = format!(
        "{{\"network\":\"{}\",\"run_id\":\"{}\",\"anchor_commitment_hex\":\"{}\",\"pubkey_hex\":\"{}\",\"signature_hex\":\"{}\"}}",
        args.kaspa_network,
        args.run_id,
        anchor_rec.anchor_commitment_hex,
        pubkey_hex,
        signature_hex,
    );

    let mut headers = vec![HttpHeader { name: "Content-Type".to_string(), value: "application/json".to_string() }];
    if let Some(k) = ep.api_key.as_ref() {
        headers.push(HttpHeader { name: "x-api-key".to_string(), value: k.clone() });
    }

    let req = CanisterHttpRequestArgument {
        url,
        max_response_bytes: Some(20_000),
        method: HttpMethod::POST,
        headers,
        body: Some(body.into_bytes()),
        transform: Some(TransformContext {
            function: ic_cdk::api::management_canister::http_request::TransformFunc(candid::Func {
                principal: ic_cdk::id(),
                method: "transform".to_string(),
            }),
            context: vec![],
        }),
    };

    let (resp,) = match http_request(req).await {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("http_request failed: {:?}", e);
            let _ : (bool,) = ic_cdk::call(
                "registry_canister",
                "set_anchor_result",
                (SetAnchorResultArgs {
                    run_id: anchor_rec.run_id.clone(),
                    anchor_commitment_hex: anchor_rec.anchor_commitment_hex.clone(),
                    status: AnchorStatus::failed(msg.clone()),
                },),
            )
            .await
            .unwrap_or((false,));

            return AnchorRunResult { ok: false, msg };
        }
    };

    if resp.status >= 300 {
        let msg = format!("proxy HTTP status {}", resp.status);
        let _ : (bool,) = ic_cdk::call(
            "registry_canister",
            "set_anchor_result",
            (SetAnchorResultArgs {
                run_id: anchor_rec.run_id.clone(),
                anchor_commitment_hex: anchor_rec.anchor_commitment_hex.clone(),
                status: AnchorStatus::failed(msg.clone()),
            },),
        )
        .await
        .unwrap_or((false,));

        return AnchorRunResult { ok: false, msg };
    }

    let txid = json_get_field_string(&resp.body, "txid").unwrap_or_else(|| "unknown".to_string());

    // 5) store broadcasted status
    let (ok,): (bool,) = ic_cdk::call(
        "registry_canister",
        "set_anchor_result",
        (SetAnchorResultArgs {
            run_id: anchor_rec.run_id.clone(),
            anchor_commitment_hex: anchor_rec.anchor_commitment_hex.clone(),
            status: AnchorStatus::broadcasted(txid.clone()),
        },),
    )
    .await
    .unwrap_or((false,));

    if ok {
        AnchorRunResult { ok: true, msg: format!("broadcasted: {}", txid) }
    } else {
        AnchorRunResult { ok: false, msg: "registry rejected set_anchor_result".into() }
    }
}

ic_cdk::export_candid!();
