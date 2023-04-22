use std::time::{Duration, Instant};
use adder::{hash_state, BlockData, HeadData};
use parity_scale_codec::{Decode, Encode};
use polkadot_parachain::primitives::{
    BlockData as GenericBlockData, HeadData as GenericHeadData, RelayChainBlockNumber,
    ValidationParams, ValidationResult,
};

use dlopen::wrapper::{Container, WrapperApi};
use dlopen_derive::WrapperApi;

const ADDER_PATH: &str = "/home/s0me0ne/wrk/parity/wasm2native-poc/adder.so";

static mut MEMORY: usize = 0;

#[derive(WrapperApi)]
struct PvfApi {
    init_pvf: unsafe extern "C" fn(),
    validate_block: unsafe extern "C" fn(param: u32, len: u32) -> u64,
    __heap_base: *const usize,
    memory: *const u8,
}

#[inline]
fn polka_wasm_result_to_slice(result: u64) -> &'static [u8] {
    let result_len = (result >> 32) as u32;
    let result_p = result as u32;
    unsafe {
        std::slice::from_raw_parts(
            (MEMORY + result_p as usize) as *const u8,
            result_len as usize,
        )
    }
}

#[inline]
fn polka_wasm_result_to_slice_mut(result: u64) -> &'static mut [u8] {
    let result_len = (result >> 32) as u32;
    let result_p = result as u32;
    unsafe {
        std::slice::from_raw_parts_mut((MEMORY + result_p as usize) as *mut u8, result_len as usize)
    }
}

#[inline]
fn polka_wasm_result_to_str(result: u64) -> &'static str {
    unsafe { std::str::from_utf8_unchecked(polka_wasm_result_to_slice(result)) }
}

#[no_mangle]
pub fn ext_logging_log_version_1(level: u32, target: u64, message: u64) {
    println!(
        "L{} [{}] {}",
        level,
        polka_wasm_result_to_str(target),
        polka_wasm_result_to_str(message)
    );
}

struct Stats {
    to_load: Duration,
    to_prepare_data: Duration,
    to_execute: Duration,
    to_postprocess: Duration,
}

fn main() {
    const NITER: u64 = 10000;

    let mut number = 0;
    let mut parent_hash = [0; 32];
    let mut last_state = 0;
    let mut stats: Vec<Stats> = Vec::with_capacity(NITER as usize);

    for add in 0..NITER {
        let time0 = Instant::now();

        let adder: Container<PvfApi> = unsafe {
            Container::load(ADDER_PATH)
                .expect("Cannot load library")
        };

        let to_load = time0.elapsed();

        unsafe {
            adder.init_pvf();
            MEMORY = adder.memory as usize;
        }

        let parent_head = HeadData {
            number,
            parent_hash,
            post_state: hash_state(last_state),
        };

        let block_data = BlockData { state: last_state, add };

        let params = ValidationParams {
            parent_head: GenericHeadData(parent_head.encode()),
            block_data: GenericBlockData(block_data.encode()),
            relay_parent_number: number as RelayChainBlockNumber + 1,
            relay_parent_storage_root: Default::default(),
        };
        let params = params.encode();

        unsafe {
            std::slice::from_raw_parts_mut(
                (MEMORY + *(adder.__heap_base)) as *mut u8,
                params.len(),
            )
            .clone_from_slice(&params[..]);
        }

        let to_prepare_data = time0.elapsed();

        let res = unsafe { adder.validate_block(*(adder.__heap_base) as u32, params.len() as u32) };

        let to_execute = time0.elapsed();

        let res = polka_wasm_result_to_slice_mut(res);
        let vr = ValidationResult::decode(&mut &res[..]).expect("Cannot decode result");

        // println!("RESULT: {:?}", vr);
        let new_head = HeadData::decode(&mut &vr.head_data.0[..]).expect("Cannot decode head data");
        // println!("HEAD DATA {:?}", new_head);

        number += 1;
        parent_hash = new_head.hash();
        last_state += add;

        let to_postprocess = time0.elapsed();

        stats.push(Stats { to_load, to_prepare_data, to_execute, to_postprocess });
    }

    let mut stat_load = 0u128;
    let mut stat_prepare_data = 0u128;
    let mut stat_execute = 0u128;
    let mut stat_postprocess = 0u128;
    let mut stat_total = 0u128;

    stats.into_iter().for_each(|s| {
        stat_load += s.to_load.as_nanos();
        stat_prepare_data += (s.to_prepare_data - s.to_load).as_nanos();
        stat_execute += (s.to_execute - s.to_prepare_data).as_nanos();
        stat_postprocess += (s.to_postprocess - s.to_execute).as_nanos();
        stat_total += s.to_postprocess.as_nanos();
    });

    println!(
        "Load:\t\t{:>10} ns\nPrepare data:\t{:>10} ns\nExecute:\t{:>10} ns\nPost-process:\t{:>10} ns\nTOTAL:\t\t{:>10} ns\n",
        stat_load / NITER as u128,
        stat_prepare_data / NITER as u128,
        stat_execute / NITER as u128,
        stat_postprocess / NITER as u128,
        stat_total / NITER as u128,
    );
}
