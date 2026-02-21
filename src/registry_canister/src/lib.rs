use candid::{CandidType, Decode, Encode, Principal};
use ic_cdk::api;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell, Storable, BoundedStorable};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::borrow::Cow;

// -------------------- Types --------------------

#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed(String),
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct JobRecord {
    pub run_id: String,
    pub input_sha256_hex: String,
    pub commit_hash_hex: Option<String>,
    pub status: JobStatus,
    pub created_at_ns: u64,
    pub updated_at_ns: u64,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct JobView {
    pub record: JobRecord,
    pub input: Vec<u8>,
    pub output: Option<Vec<u8>>,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct RegistryMeta {
    pub git_commit: String,
    pub crate_version: String,
    pub canister_version: u64,
    pub build_ts: String,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub enum AnchorStatus {
    None,
    Pending,
    Broadcasted(String),
    Confirmed {
        txid: String,
        confirmations: u32,
        block_time: Option<u64>,
    },
    Failed(String),
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct AnchorRecord {
    pub run_id: String,
    pub anchor_commitment_hex: String,
    pub kaspa_network: String,
    pub status: AnchorStatus,
    pub created_at_ns: u64,
    pub updated_at_ns: u64,
}

#[derive(CandidType, Deserialize)]
pub struct SubmitJobArgs {
    pub input: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct SubmitJobRes {
    pub run_id: String,
}

#[derive(CandidType, Deserialize)]
pub struct GetJobArgs {
    pub run_id: String,
}

#[derive(CandidType, Deserialize)]
pub struct ListJobsArgs {
    pub cursor: Option<String>,
    pub limit: u32,
}

#[derive(CandidType, Deserialize)]
pub struct SetResultArgs {
    pub run_id: String,
    pub output: Vec<u8>,
    pub commit_hash_hex: String,
}

#[derive(CandidType, Deserialize)]
pub struct RequestAnchorArgs {
    pub run_id: String,
    pub kaspa_network: String,
}

#[derive(CandidType, Deserialize)]
pub struct GetAnchorArgs {
    pub run_id: String,
}

#[derive(CandidType, Deserialize)]
pub struct SetAnchorResultArgs {
    pub run_id: String,
    pub anchor_commitment_hex: String,
    pub status: AnchorStatus,
}

// -------------------- Stable encoding helpers --------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobStable {
    record: JobRecord,
    input: Vec<u8>,
    output: Option<Vec<u8>>,
}

impl Storable for JobStable {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).expect("encode JobStable"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, JobStable).expect("decode JobStable")
    }
}

impl BoundedStorable for JobStable {
    const MAX_SIZE: u32 = 2_000_000; // keep within stable-structures bounds
    const IS_FIXED_SIZE: bool = false;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AnchorStable {
    record: AnchorRecord,
}

impl Storable for AnchorStable {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).expect("encode AnchorStable"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, AnchorStable).expect("decode AnchorStable")
    }
}

impl BoundedStorable for AnchorStable {
    const MAX_SIZE: u32 = 200_000;
    const IS_FIXED_SIZE: bool = false;
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct PrincipalsCfg {
    compute: Option<Principal>,
    anchor: Option<Principal>,
}

impl Storable for PrincipalsCfg {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).expect("encode PrincipalsCfg"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, PrincipalsCfg).expect("decode PrincipalsCfg")
    }
}

impl BoundedStorable for PrincipalsCfg {
    const MAX_SIZE: u32 = 1_024;
    const IS_FIXED_SIZE: bool = false;
}

// -------------------- Stable state --------------------

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEM_MGR: std::cell::RefCell<MemoryManager<DefaultMemoryImpl>> =
        std::cell::RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static JOBS: std::cell::RefCell<StableBTreeMap<String, JobStable, Memory>> = std::cell::RefCell::new(
        StableBTreeMap::init(with_mem(MemoryId::new(0)))
    );

    static ANCHORS: std::cell::RefCell<StableBTreeMap<String, AnchorStable, Memory>> = std::cell::RefCell::new(
        StableBTreeMap::init(with_mem(MemoryId::new(1)))
    );

    static CFG: std::cell::RefCell<StableCell<PrincipalsCfg, Memory>> = std::cell::RefCell::new(
        StableCell::init(with_mem(MemoryId::new(2)), PrincipalsCfg::default()).expect("init cell")
    );
}

fn with_mem(id: MemoryId) -> Memory {
    MEM_MGR.with(|m| m.borrow().get(id))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn now_ns() -> u64 {
    api::time()
}

fn is_controller_or_self() -> bool {
    // Very lightweight: allow the canister itself and controllers.
    // In local dev, caller == controller. On mainnet, you can tighten this.
    let caller = ic_cdk::caller();
    caller == ic_cdk::id() || api::is_controller(&caller)
}

fn require_caller_is(principal: Option<Principal>, role: &str) {
    let caller = ic_cdk::caller();
    match principal {
        Some(p) if p == caller => {}
        _ => ic_cdk::trap(&format!("forbidden: caller is not {role}")),
    }
}

// -------------------- Lifecycle --------------------

#[init]
fn init() {
    // No-op. Principals are set explicitly via set_compute_canister / set_anchor_canister.
}

#[pre_upgrade]
fn pre_upgrade() {
    // stable-structures already persists.
}

#[post_upgrade]
fn post_upgrade() {
    // stable-structures already persists.
}

// -------------------- Public API --------------------

#[update]
fn submit_job(args: SubmitJobArgs) -> SubmitJobRes {
    let input_sha = sha256_hex(&args.input);
    let run_id = input_sha.clone();

    let t = now_ns();
    let rec = JobRecord {
        run_id: run_id.clone(),
        input_sha256_hex: input_sha,
        commit_hash_hex: None,
        status: JobStatus::Queued,
        created_at_ns: t,
        updated_at_ns: t,
    };

    JOBS.with(|j| {
        let mut j = j.borrow_mut();
        // idempotent: if already exists, keep existing.
        if j.get(&run_id).is_none() {
            j.insert(
                run_id.clone(),
                JobStable {
                    record: rec,
                    input: args.input,
                    output: None,
                },
            );
        }
    });

    SubmitJobRes { run_id }
}

#[query]
fn get_job(args: GetJobArgs) -> Option<JobView> {
    JOBS.with(|j| {
        j.borrow().get(&args.run_id).map(|st| JobView {
            record: st.record,
            input: st.input,
            output: st.output,
        })
    })
}

#[query]
fn list_jobs(args: ListJobsArgs) -> Vec<String> {
    let limit = args.limit.min(500) as usize;
    let start = args.cursor;

    JOBS.with(|j| {
        let j = j.borrow();
        let mut out = Vec::with_capacity(limit);

        let iter: Box<dyn Iterator<Item = (String, JobStable)>> = match start {
            None => Box::new(j.iter()),
            Some(c) => Box::new(j.range(c..)),
        };

        for (k, _) in iter {
            out.push(k);
            if out.len() >= limit {
                break;
            }
        }
        out
    })
}

#[update]
fn set_result(args: SetResultArgs) -> bool {
    // only compute canister
    let compute = CFG.with(|c| c.borrow().get().compute);
    require_caller_is(compute, "compute_canister");

    JOBS.with(|j| {
        let mut j = j.borrow_mut();
        let Some(mut st) = j.get(&args.run_id) else { return false; };

        st.record.commit_hash_hex = Some(args.commit_hash_hex);
        st.record.status = JobStatus::Done;
        st.record.updated_at_ns = now_ns();
        st.output = Some(args.output);
        j.insert(args.run_id, st);
        true
    })
}

#[update]
fn request_anchor(args: RequestAnchorArgs) -> AnchorRecord {
    // Anyone can request anchoring once job is done.
    let job = JOBS.with(|j| j.borrow().get(&args.run_id));
    let Some(job) = job else { ic_cdk::trap("unknown run_id"); };

    let commit_hash = job
        .record
        .commit_hash_hex
        .clone()
        .unwrap_or_else(|| ic_cdk::trap("job not done yet (missing commit_hash)"));

    // anchor_commitment = SHA256("QFC|v3|KASPA|" || run_id || commit_hash)
    let mut h = Sha256::new();
    h.update(b"QFC|v3|KASPA|");
    h.update(args.run_id.as_bytes());
    h.update(commit_hash.as_bytes());
    let anchor_commitment_hex = hex::encode(h.finalize());

    let t = now_ns();
    let rec = AnchorRecord {
        run_id: args.run_id.clone(),
        anchor_commitment_hex: anchor_commitment_hex.clone(),
        kaspa_network: args.kaspa_network,
        status: AnchorStatus::Pending,
        created_at_ns: t,
        updated_at_ns: t,
    };

    ANCHORS.with(|a| {
        a.borrow_mut().insert(
            args.run_id,
            AnchorStable {
                record: rec.clone(),
            },
        )
    });

    rec
}

#[query]
fn get_anchor(args: GetAnchorArgs) -> Option<AnchorRecord> {
    ANCHORS.with(|a| a.borrow().get(&args.run_id).map(|x| x.record))
}

#[update]
fn set_anchor_result(args: SetAnchorResultArgs) -> bool {
    let anchor = CFG.with(|c| c.borrow().get().anchor);
    require_caller_is(anchor, "anchor_canister");

    ANCHORS.with(|a| {
        let mut a = a.borrow_mut();
        let Some(mut st) = a.get(&args.run_id) else { return false; };

        // sanity: commitment must match stored record
        if st.record.anchor_commitment_hex != args.anchor_commitment_hex {
            ic_cdk::trap("anchor_commitment mismatch");
        }

        st.record.status = args.status;
        st.record.updated_at_ns = now_ns();
        a.insert(args.run_id, st);
        true
    })
}

#[query]
fn get_registry_meta() -> RegistryMeta {
    let git_commit = option_env!("GIT_COMMIT").unwrap_or("unknown").to_string();
    let build_ts = option_env!("BUILD_TS").unwrap_or("unknown").to_string();
    let crate_version = env!("CARGO_PKG_VERSION").to_string();
    let canister_version = api::canister_version();

    RegistryMeta {
        git_commit,
        crate_version,
        canister_version,
        build_ts,
    }
}

#[update]
fn set_compute_canister(p: Principal) {
    if !is_controller_or_self() {
        ic_cdk::trap("forbidden: only controller can set principals");
    }
    CFG.with(|c| {
        let mut cell = c.borrow_mut();
        let mut cfg = cell.get().clone();
        cfg.compute = Some(p);
        cell.set(cfg).expect("set cfg");
    });
}

#[update]
fn set_anchor_canister(p: Principal) {
    if !is_controller_or_self() {
        ic_cdk::trap("forbidden: only controller can set principals");
    }
    CFG.with(|c| {
        let mut cell = c.borrow_mut();
        let mut cfg = cell.get().clone();
        cfg.anchor = Some(p);
        cell.set(cfg).expect("set cfg");
    });
}

// Export candid
ic_cdk::export_candid!();
