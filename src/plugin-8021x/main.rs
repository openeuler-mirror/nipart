// SPDX-License-Identifier: Apache-2.0

mod apply;
mod plugin;

use nipart::{NipartError, NipartPlugin};

use self::plugin::NipartPlugin8021x;

fn init_logger() {
    let mut log_builder = env_logger::Builder::new();
    log_builder.filter(Some("nipart"), log::LevelFilter::Debug);
    log_builder.filter(Some("nipart_plugin"), log::LevelFilter::Debug);
    log_builder.filter(Some("nipart-plugin-8021x"), log::LevelFilter::Debug);
    log_builder.filter(Some("shuli"), log::LevelFilter::Debug);
    log_builder.init();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), NipartError> {
    init_logger();
    NipartPlugin8021x::run().await
}
