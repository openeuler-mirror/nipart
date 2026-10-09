// SPDX-License-Identifier: Apache-2.0

use nipart::{InterfaceLinkEvent, NipartError};

use super::{
    super::commander::NipartCommander, NipartEventCmd, NipartEventReply,
    NipartEventWorker,
};
use crate::TaskManager;

// Responsibilities of NipartEventManager:
//  * Redirect InterfaceLinkEvent sequentially to NipartEventWorker

#[derive(Debug, Clone)]
pub(crate) struct NipartEventManager {
    mgr: TaskManager<NipartEventCmd, NipartEventReply>,
}

impl NipartEventManager {
    pub(crate) async fn new() -> Result<Self, NipartError> {
        Ok(Self {
            mgr: TaskManager::new::<NipartEventWorker>("event").await?,
        })
    }

    pub(crate) async fn shutdown(&self) {
        self.mgr.shutdown().await
    }

    pub(crate) async fn set_commander(
        &mut self,
        commander: NipartCommander,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartEventCmd::SetCommander(Box::new(commander)))
            .await?;
        Ok(())
    }

    pub(crate) async fn handle_event(
        &mut self,
        event: InterfaceLinkEvent,
    ) -> Result<(), NipartError> {
        self.handle_events(vec![event], false).await
    }

    pub(crate) async fn handle_events(
        &mut self,
        events: Vec<InterfaceLinkEvent>,
        boot: bool,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartEventCmd::HandleEvents {
                events: events.into_boxed_slice(),
                boot,
            })
            .await?;
        Ok(())
    }
}
