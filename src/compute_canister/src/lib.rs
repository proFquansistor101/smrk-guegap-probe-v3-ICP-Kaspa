use candid::{CandidType, Deserialize};
use ic_cdk::api;
use ic_cdk::call;
use ic_cdk_macros::update;
use sha2::{Digest, Sha256};

#[derive(CandidType, Deserialize, Clone)]
pub struct RunArgs {
    pub run_id: String,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct RunRes {
    pub ok: bool,
    pub msg: String,
}

// --- Registry types (must match registry.did) ---

#[derive(CandidType, Deserialize, Clone)]
pub enum JobStatus {
    queued,
    running,
    done,
    failed(String),
}

#[derive(CandidType, Deserialize, Clone)]
pub struct JobRecord {
    pub run_id: String,
    pub input_sha256_hex: String,
    pub commit_hash_hex: Option<String>,
    pub status: JobStatus,
    pub created_at_ns: u64,
    pub updated_at_ns: u64,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct JobView {
    pub record: JobRecord,
    pub input: Vec<u8>,
    pub output: Option<Vec<u8>>,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct RegistryMeta {
    pub git_commit: String,
    pub crate_version: String,
    pub canister_version: u64,
    pub build_ts: String,
}

#[derive(CandidType, Deserialize)]
pub struct GetJobArgs {
    pub run_id: String,
}

#[derive(CandidType, Deserialize)]
pub struct SetResultArgs {
    pub run_id: String,
    pub output: Vec<u8>,
    pub commit_hash_hex: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn screening_stub(run_id: &str, input: &[u8], reg_meta: &RegistryMeta) -> Vec<u8> {
    // Deterministic stub. Replace with real N=256 dense diagonalization later.
    // Just derive a couple floats from sha256(input).
    let mut h = Sha256::new();
    h.update(input);
    let digest = h.finalize();

    let a = u64::from_le_bytes(digest[0..8].try_into().unwrap());
    let b = u64::from_le_bytes(digest[8..16].try_into().unwrap());

    let r_mean = (a as f64) / (u64::MAX as f64);
    let delta1 = (b as f64) / (u64::MAX as f64);
    let pass = if r_mean > 0.45 && r_mean < 0.65 { "H1_pass" } else { "H1_fail" };

    let git_commit = option_env!("GIT_COMMIT").unwrap_or("unknown");
    let build_ts = option_env!("BUILD_TS").unwrap_or("unknown");
    let crate_version = env!("CARGO_PKG_VERSION");
    let canister_version = api::canister_version();

    let input_sha256_hex = sha256_hex(input);

    let json = format!(
        "{{\
\"probe_version\":\"smrk-guegap-icp-v2\",\
\"N\":256,\
\"bulk_r\":{{\"r_mean\":{:.16},\"count\":100}},\
\"gap\":{{\"delta1\":{:.16}}},\
\"H1_H2_proxy\":\"{}\",\
\"meta\":{{\
  \"run_id\":\"{}\",\
  \"input_sha256_hex\":\"{}\",\
  \"compute\":{{\
    \"git_commit\":\"{}\",\
    \"crate_version\":\"{}\",\
    \"canister_version\":{},\
    \"build_ts\":\"{}\"\
  }},\
  \"registry\":{{\
    \"git_commit\":\"{}\",\
    \"crate_version\":\"{}\",\
    \"canister_version\":{},\
    \"build_ts\":\"{}\"\
  }}\
}}\
}}",
        r_mean,
        delta1,
        pass,
        run_id,
        input_sha256_hex,
        git_commit,
        crate_version,
        canister_version,
        build_ts,
        reg_meta.git_commit,
        reg_meta.crate_version,
        reg_meta.canister_version,
        reg_meta.build_ts,
    );

    json.into_bytes()
}

#[update]
async fn run_screening(args: RunArgs) -> RunRes {
    // 1) get job
    let (job_opt,): (Option<JobView>,) = call(
        "registry_canister",
        "get_job",
        (GetJobArgs {
            run_id: args.run_id.clone(),
        },),
    )
    .await
    .map_err(|e| format!("get_job call failed: {:?}", e))
    .map(|x| x)
    .unwrap_or((None,));

    let Some(job) = job_opt else {
        return RunRes { ok: false, msg: "unknown run_id".into() };
    };

    // 2) get registry meta
    let (reg_meta,): (RegistryMeta,) = call("registry_canister", "get_registry_meta", ())
        .await
        .unwrap_or((RegistryMeta {
            git_commit: "unknown".into(),
            crate_version: "unknown".into(),
            canister_version: 0,
            build_ts: "unknown".into(),
        },));

    // 3) compute output
    let output = screening_stub(&args.run_id, &job.input, &reg_meta);
    let commit_hash_hex = sha256_hex(&output);

    // 4) write result
    let (ok,): (bool,) = call(
        "registry_canister",
        "set_result",
        (SetResultArgs {
            run_id: args.run_id,
            output,
            commit_hash_hex,
        },),
    )
    .await
    .map(|x| x)
    .unwrap_or((false,));

    if ok {
        RunRes { ok: true, msg: "done".into() }
    } else {
        RunRes { ok: false, msg: "registry rejected set_result".into() }
    }
}

ic_cdk::export_candid!();
