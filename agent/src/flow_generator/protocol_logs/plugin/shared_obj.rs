/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::{
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use log::error;
use public::l7_protocol::{CustomProtocol, L7Protocol};
use serde::Serialize;

use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        protocol_logs::{L7ResponseStatus, LogMessageType},
        Error, Result,
    },
    plugin::{
        c_ffi::{
            ParseCtx, ParseInfo, ACTION_CONTINUE, ACTION_ERROR, ACTION_OK, CHECK_PAYLOAD_FUNC_SYM,
            PARSE_PAYLOAD_FUNC_SYM,
        },
        shared_obj::get_so_plug_metric_counter_map_key,
        CustomInfo,
    },
};

const RESULT_LEN: i32 = 8;

#[derive(Debug, Default, Serialize)]
pub struct SoLog {
    proto_num: Option<u8>,
    proto_str: String,
    #[serde(skip)]
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for SoLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        let Some(c_funcs) = param.so_func.as_ref() else {
            return false;
        };
        let ctx = &ParseCtx::from((param, payload));

        for c in c_funcs.as_ref() {
            let counter = param.so_plugin_counter_map.as_ref().and_then(|h| {
                h.so_mertic
                    .get(&get_so_plug_metric_counter_map_key(
                        &c.name,
                        CHECK_PAYLOAD_FUNC_SYM,
                    ))
                    .clone()
            });
            let start_time = SystemTime::now();
            let start_time = start_time.duration_since(UNIX_EPOCH).unwrap();

            /*
                call the func from so, correctness depends on plugin implementation.

                there is impossible to verify the plugin implemention correctness, so plugin maybe do some UB,
                for eaxmple, modify the payload (due to the payload is not copy but pass the ptr to ctx directly and should
                not be modify, modify the payload is UB).

                the plugin correctness depend on the implementation of the developer
            */
            let res = unsafe { (c.check_payload)(ctx as *const ParseCtx) };

            counter.map(|c| {
                c.exe_duration.swap(
                    {
                        let end_time = SystemTime::now();
                        let end_time = end_time.duration_since(UNIX_EPOCH).unwrap();
                        (end_time - start_time).as_micros() as u64
                    },
                    Ordering::Relaxed,
                )
            });

            if res.proto != 0 {
                self.proto_num = res.proto.into();
                match std::str::from_utf8(&res.proto_name) {
                    Ok(s) => self.proto_str = s.to_owned(),
                    Err(e) => {
                        error!("read proto str from so plugin fail: {}", e);
                        counter.map(|c| c.fail_cnt.fetch_add(1, Ordering::Relaxed));
                        return false;
                    }
                }
                return true;
            }
        }
        false
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        let Some(c_funcs) = param.so_func.as_ref() else {
            return Err(Error::NoParseConfig);
        };

        let ctx = &mut ParseCtx::from((param, payload));
        ctx.proto = self.proto_num.unwrap();
        let mut resp = [ParseInfo::default(); RESULT_LEN as usize];

        if self.perf_stats.is_none() {
            self.perf_stats = Some(L7PerfStats::default());
        }
        let perf_stats = self.perf_stats.as_mut().unwrap();

        for c in c_funcs.as_ref() {
            let counter = param.so_plugin_counter_map.as_ref().and_then(|h| {
                h.so_mertic
                    .get(&get_so_plug_metric_counter_map_key(
                        &c.name,
                        PARSE_PAYLOAD_FUNC_SYM,
                    ))
                    .clone()
            });
            let start_time = SystemTime::now();
            let start_time = start_time.duration_since(UNIX_EPOCH).unwrap();

            /*
                call the func from so, correctness depends on plugin implementation

                there is impossible to verify the plugin implemention correctness, so plugin maybe do some UB,
                for example, set the wrong msg_type will make the log take the incorrect data in union.

                the plugin correctness depend on the implementation of the developer
            */
            let res = unsafe {
                (c.parse_payload)(
                    ctx as *const ParseCtx,
                    &mut resp as *mut ParseInfo,
                    RESULT_LEN,
                )
            };

            counter.map(|c| {
                c.exe_duration.swap(
                    {
                        let end_time = SystemTime::now();
                        let end_time = end_time.duration_since(UNIX_EPOCH).unwrap();
                        (end_time - start_time).as_micros() as u64
                    },
                    Ordering::Relaxed,
                )
            });

            match res.action {
                ACTION_OK => {
                    if res.len == 0 {
                        return Ok(vec![]);
                    }
                    if res.len > RESULT_LEN {
                        error!(
                            "so plugin {} return large result length {}",
                            c.name, res.len
                        );
                        counter.map(|c| c.fail_cnt.fetch_add(1, Ordering::Relaxed));
                        return Err(Error::SoReturnUnexpectVal);
                    }
                    let mut v = vec![];
                    for i in 0..res.len as usize {
                        match CustomInfo::try_from(resp[i]) {
                            Ok(mut info) => {
                                info.proto_str = self.proto_str.clone();
                                info.proto = self.proto_num.unwrap();

                                match info.msg_type {
                                    LogMessageType::Request => perf_stats.inc_req(),
                                    LogMessageType::Response => perf_stats.inc_resp(),
                                    _ => unreachable!(),
                                }

                                match info.resp.status {
                                    L7ResponseStatus::ClientError => perf_stats.inc_req_err(),
                                    L7ResponseStatus::ServerError => perf_stats.inc_resp_err(),
                                    _ => {}
                                }

                                info.cal_rrt(param, None).map(|rrt| {
                                    info.rrt = rrt;
                                    perf_stats.update_rrt(rrt);
                                });
                                v.push(L7ProtocolInfo::CustomInfo(info));
                            }
                            Err(e) => {
                                counter.map(|c| c.fail_cnt.fetch_add(1, Ordering::Relaxed));
                                error!("so plugin {} convert l7 info fail: {}", c.name, e);
                            }
                        }
                    }
                    return Ok(v);
                }
                ACTION_CONTINUE => continue,
                ACTION_ERROR => {
                    counter.map(|c| c.fail_cnt.fetch_add(1, Ordering::Relaxed));
                    return Err(Error::SoParseFail);
                }

                _ => {
                    error!("so plugin {} return unknown action {}", c.name, res.action);
                    counter.map(|c| c.fail_cnt.fetch_add(1, Ordering::Relaxed));
                    return Err(Error::SoReturnUnexpectVal);
                }
            }
        }
        Err(Error::SoParseFail)
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Custom
    }

    fn custom_protocol(&self) -> Option<CustomProtocol> {
        Some(CustomProtocol::So(
            self.proto_num.unwrap(),
            self.proto_str.clone(),
        ))
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

pub fn get_so_parser(p: u8, s: String) -> SoLog {
    SoLog {
        proto_num: Some(p),
        proto_str: s,
        perf_stats: None,
    }
}