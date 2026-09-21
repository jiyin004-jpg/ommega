use super::*;

static MIRROR_RECOVERY_STATE: LazyLock<Mutex<MirrorRecoveryState>> =
    LazyLock::new(|| Mutex::new(MirrorRecoveryState::default()));
static MIRROR_RECOVERY_WORKER: OnceLock<Result<std::sync::mpsc::SyncSender<()>, String>> =
    OnceLock::new();

const MAX_PENDING_MIRROR_REPLAYS: usize = 64;
const MIRROR_RECOVERY_RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MirrorStateKind {
    Authorization,
    Maintenance,
}

#[derive(Clone)]
enum MirrorReplayEvent {
    Authorization {
        request: ParsedAuthorizationRequest,
        caller: CallerInfo,
    },
    Maintenance {
        request: ParsedMaintenanceRequest,
        caller: CallerInfo,
    },
}

#[derive(Clone)]
struct SequencedMirrorReplay {
    sequence: u64,
    kind: MirrorStateKind,
    event: Option<MirrorReplayEvent>,
    retry_not_before: Option<Instant>,
}

pub(super) struct MirrorUpdateReservation {
    kind: MirrorStateKind,
    sequence: u64,
    active: bool,
}

#[derive(Default)]
struct MirrorRecoveryLane {
    pending: VecDeque<SequencedMirrorReplay>,
    draining: bool,
    poisoned: bool,
}

struct MirrorRecoveryState {
    authorization: MirrorRecoveryLane,
    maintenance: MirrorRecoveryLane,
    next_sequence: u64,
}

impl Default for MirrorRecoveryState {
    fn default() -> Self {
        Self {
            authorization: MirrorRecoveryLane::default(),
            maintenance: MirrorRecoveryLane::default(),
            next_sequence: 1,
        }
    }
}

impl MirrorRecoveryState {
    fn lane(&self, kind: MirrorStateKind) -> &MirrorRecoveryLane {
        match kind {
            MirrorStateKind::Authorization => &self.authorization,
            MirrorStateKind::Maintenance => &self.maintenance,
        }
    }

    fn lane_mut(&mut self, kind: MirrorStateKind) -> &mut MirrorRecoveryLane {
        match kind {
            MirrorStateKind::Authorization => &mut self.authorization,
            MirrorStateKind::Maintenance => &mut self.maintenance,
        }
    }

    fn pending_len(&self) -> usize {
        self.authorization.pending.len() + self.maintenance.pending.len()
    }

    fn next_pending(&self) -> Option<&SequencedMirrorReplay> {
        self.authorization
            .pending
            .front()
            .into_iter()
            .chain(self.maintenance.pending.front())
            .min_by_key(|pending| pending.sequence)
    }

    fn next_worker_wait(&self, now: Instant) -> Option<Duration> {
        if self.authorization.poisoned
            || self.maintenance.poisoned
            || self.authorization.draining
            || self.maintenance.draining
        {
            return None;
        }
        let pending = self.next_pending()?;
        pending.event.as_ref()?;
        Some(
            pending
                .retry_not_before
                .map(|deadline| deadline.saturating_duration_since(now))
                .unwrap_or(Duration::ZERO),
        )
    }
}

impl MirrorStateKind {
    fn label(self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::Maintenance => "maintenance",
        }
    }
}

impl MirrorReplayEvent {
    fn kind(&self) -> MirrorStateKind {
        match self {
            Self::Authorization { .. } => MirrorStateKind::Authorization,
            Self::Maintenance { .. } => MirrorStateKind::Maintenance,
        }
    }

    fn method(&self) -> String {
        match self {
            Self::Authorization { request, .. } => format!("{:?}", request.method()),
            Self::Maintenance { request, .. } => format!("{:?}", request.method()),
        }
    }

    fn caller(&self) -> &CallerInfo {
        match self {
            Self::Authorization { caller, .. } | Self::Maintenance { caller, .. } => caller,
        }
    }

    fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::Authorization { request, caller } => {
                execute_authorization_mirror(request, caller)
            }
            Self::Maintenance { request, caller } => execute_maintenance_mirror(request, caller),
        }
    }
}

pub(super) fn authorization_requires_mirror(request: &ParsedAuthorizationRequest) -> bool {
    !matches!(
        request,
        ParsedAuthorizationRequest::GetAuthTokensForCredStore { .. }
            | ParsedAuthorizationRequest::GetLastAuthTime { .. }
    )
}

pub(super) fn maintenance_requires_mirror(request: &ParsedMaintenanceRequest) -> bool {
    !matches!(
        request,
        ParsedMaintenanceRequest::GetState { .. }
            | ParsedMaintenanceRequest::OnDeviceOffBody
            | ParsedMaintenanceRequest::MigrateKeyNamespace { .. }
            | ParsedMaintenanceRequest::GetAppUidsAffectedBySid { .. }
    )
}

#[cfg(test)]
fn mirror_state_dirty(kind: MirrorStateKind) -> bool {
    let state = MIRROR_RECOVERY_STATE
        .lock()
        .expect("mirror recovery state poisoned");
    let lane = state.lane(kind);
    lane.poisoned || !lane.pending.is_empty()
}

fn poison_mirror_state(state: &mut MirrorRecoveryState, kind: MirrorStateKind) {
    let lane = state.lane_mut(kind);
    lane.poisoned = true;
    lane.draining = false;
}

#[cfg(test)]
pub(super) fn reset_mirror_state_for_tests() {
    let mut state = MIRROR_RECOVERY_STATE
        .lock()
        .expect("mirror recovery state poisoned");
    *state = MirrorRecoveryState::default();
}

fn remove_reserved_mirror_update(
    state: &mut MirrorRecoveryState,
    kind: MirrorStateKind,
    sequence: u64,
) {
    state
        .lane_mut(kind)
        .pending
        .retain(|pending| pending.sequence != sequence);
}

pub(super) fn reserve_mirror_update(
    kind: MirrorStateKind,
) -> anyhow::Result<MirrorUpdateReservation> {
    let mut state = MIRROR_RECOVERY_STATE
        .lock()
        .expect("mirror recovery state poisoned");
    if state.authorization.poisoned || state.maintenance.poisoned {
        anyhow::bail!("ommega mirror recovery is poisoned by a non-retryable failure");
    }
    if state.lane(kind).pending.len() >= MAX_PENDING_MIRROR_REPLAYS {
        anyhow::bail!(
            "{} mirror recovery queue reached {} events",
            kind.label(),
            MAX_PENDING_MIRROR_REPLAYS
        );
    }

    let sequence = state.next_sequence;
    state.next_sequence = state.next_sequence.wrapping_add(1).max(1);
    state
        .lane_mut(kind)
        .pending
        .push_back(SequencedMirrorReplay {
            sequence,
            kind,
            event: None,
            retry_not_before: None,
        });
    Ok(MirrorUpdateReservation {
        kind,
        sequence,
        active: true,
    })
}

impl MirrorUpdateReservation {
    fn enqueue(mut self, event: MirrorReplayEvent) -> anyhow::Result<()> {
        debug_assert_eq!(event.kind(), self.kind);
        let method = event.method();
        let caller_uid = event.caller().uid;
        let caller_pid = event.caller().pid;
        let mut state = MIRROR_RECOVERY_STATE
            .lock()
            .expect("mirror recovery state poisoned");
        let Some(pending) = state
            .lane_mut(self.kind)
            .pending
            .iter_mut()
            .find(|pending| pending.sequence == self.sequence)
        else {
            poison_mirror_state(&mut state, self.kind);
            self.active = false;
            drop(state);
            wake_mirror_recovery_worker();
            anyhow::bail!("mirror update reservation disappeared");
        };
        if pending.kind != self.kind || pending.event.is_some() {
            poison_mirror_state(&mut state, self.kind);
            self.active = false;
            drop(state);
            wake_mirror_recovery_worker();
            anyhow::bail!("mirror update reservation changed unexpectedly");
        }
        pending.event = Some(event);
        pending.retry_not_before = None;
        let pending = state.pending_len();
        self.active = false;
        drop(state);
        debug!(
            "event=mirror queued update sequence={} domain={} method={} uid={} pid={} pending={}",
            self.sequence,
            self.kind.label(),
            method,
            caller_uid,
            caller_pid,
            pending
        );
        wake_mirror_recovery_worker();
        Ok(())
    }

    fn cancel(mut self) {
        let mut state = MIRROR_RECOVERY_STATE
            .lock()
            .expect("mirror recovery state poisoned");
        remove_reserved_mirror_update(&mut state, self.kind, self.sequence);
        self.active = false;
        drop(state);
        wake_mirror_recovery_worker();
    }
}

impl Drop for MirrorUpdateReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = MIRROR_RECOVERY_STATE
            .lock()
            .expect("mirror recovery state poisoned");
        remove_reserved_mirror_update(&mut state, self.kind, self.sequence);
        poison_mirror_state(&mut state, self.kind);
        self.active = false;
        drop(state);
        warn!(
            "event=mirror {} update lost its System reply; ommega routes are fail-closed until process restart",
            self.kind.label()
        );
        wake_mirror_recovery_worker();
    }
}

pub(super) fn ensure_mirror_state_recovered() -> anyhow::Result<()> {
    let state = MIRROR_RECOVERY_STATE
        .lock()
        .expect("mirror recovery state poisoned");
    if state.authorization.poisoned || state.maintenance.poisoned {
        anyhow::bail!("ommega mirror recovery is poisoned by a non-retryable failure");
    }
    if state.authorization.draining || state.maintenance.draining {
        anyhow::bail!("ommega mirror recovery is busy");
    }
    if state.pending_len() == 0 {
        return Ok(());
    }
    drop(state);
    wake_mirror_recovery_worker();
    anyhow::bail!("ommega mirror recovery is pending")
}

fn recover_mirror_state_with(
    execute: &mut impl FnMut(&MirrorReplayEvent) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    loop {
        let pending = {
            let mut state = MIRROR_RECOVERY_STATE
                .lock()
                .expect("mirror recovery state poisoned");
            if state.authorization.poisoned || state.maintenance.poisoned {
                anyhow::bail!("ommega mirror recovery is poisoned by a non-retryable failure");
            }
            if state.authorization.draining || state.maintenance.draining {
                anyhow::bail!("ommega mirror recovery is busy");
            }
            let Some(pending) = state.next_pending().cloned() else {
                return Ok(());
            };
            if pending.event.is_none() {
                anyhow::bail!(
                    "{} mirror update is awaiting its System reply",
                    pending.kind.label()
                );
            }
            if pending
                .retry_not_before
                .is_some_and(|deadline| deadline > Instant::now())
            {
                anyhow::bail!("{} mirror retry is delayed", pending.kind.label());
            }
            state.lane_mut(pending.kind).draining = true;
            pending
        };

        let event = pending
            .event
            .as_ref()
            .expect("ready mirror replay lost its event");
        let method = event.method();
        let result = execute(event);
        let mut state = MIRROR_RECOVERY_STATE
            .lock()
            .expect("mirror recovery state poisoned");
        if state
            .lane(pending.kind)
            .pending
            .front()
            .map(|front| front.sequence)
            != Some(pending.sequence)
        {
            state.authorization.poisoned = true;
            state.authorization.draining = false;
            state.maintenance.poisoned = true;
            state.maintenance.draining = false;
            drop(state);
            wake_mirror_recovery_worker();
            anyhow::bail!("mirror recovery sequence changed while replaying");
        }

        match result {
            Ok(()) => {
                let lane = state.lane_mut(pending.kind);
                lane.pending.pop_front();
                lane.draining = false;
                let remaining = state.pending_len();
                drop(state);
                debug!(
                    "event=mirror replay sequence={} domain={} method={} succeeded; pending={}",
                    pending.sequence,
                    pending.kind.label(),
                    method,
                    remaining
                );
                wake_mirror_recovery_worker();
            }
            Err(error) if ommega_unavailable_error(&error) => {
                let lane = state.lane_mut(pending.kind);
                lane.draining = false;
                lane.pending
                    .front_mut()
                    .expect("checked mirror replay disappeared")
                    .retry_not_before = Some(Instant::now() + MIRROR_RECOVERY_RETRY_DELAY);
                drop(state);
                warn!(
                    "event=mirror replay sequence={} domain={} method={} unavailable: {:#}; retrying in {:?}",
                    pending.sequence,
                    pending.kind.label(),
                    method,
                    error,
                    MIRROR_RECOVERY_RETRY_DELAY
                );
                wake_mirror_recovery_worker();
                return Err(error);
            }
            Err(error) => {
                poison_mirror_state(&mut state, pending.kind);
                drop(state);
                warn!(
                    "event=mirror replay sequence={} domain={} method={} failed: {:#}; preserving the in-memory event and blocking ommega routes",
                    pending.sequence,
                    pending.kind.label(),
                    method,
                    error
                );
                wake_mirror_recovery_worker();
                return Err(error);
            }
        }
    }
}

fn recover_mirror_state() -> anyhow::Result<()> {
    recover_mirror_state_with(&mut MirrorReplayEvent::execute)
}

fn wake_mirror_recovery_worker() {
    if let Some(Ok(sender)) = MIRROR_RECOVERY_WORKER.get() {
        let _ = sender.try_send(());
    }
}

pub(in crate::hook) fn start_mirror_recovery_worker() -> Result<(), String> {
    let worker = MIRROR_RECOVERY_WORKER.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("ommega-mirror-recovery".to_string())
            .spawn(move || mirror_recovery_worker(receiver))
            .map_err(|error| format!("failed to start mirror recovery worker: {error}"))?;
        Ok(sender)
    });
    match worker {
        Ok(sender) => {
            let _ = sender.try_send(());
            Ok(())
        }
        Err(error) => Err(error.clone()),
    }
}

fn mirror_recovery_worker(receiver: std::sync::mpsc::Receiver<()>) {
    loop {
        let _ = recover_mirror_state();
        let wait = {
            let state = MIRROR_RECOVERY_STATE
                .lock()
                .expect("mirror recovery state poisoned");
            state.next_worker_wait(Instant::now())
        };
        match wait {
            Some(duration) if duration.is_zero() => continue,
            Some(duration) => match receiver.recv_timeout(duration) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            },
            None if receiver.recv().is_err() => return,
            None => {}
        }
    }
}

pub(super) unsafe fn build_authorization_reply_mirror(
    tr: &binder_transaction_data,
    call: &mut PendingAuthorizationCall,
) -> anyhow::Result<Option<OutboundReply>> {
    let method = call.method;
    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    let status = parcel::parse_reply_status(data, data_size, offsets, offsets_size)?;
    if !status.is_ok() {
        if let Some(reservation) = call.mirror_update.take() {
            reservation.cancel();
        }
        debug!(
            "event=mirror domain=authorization system {:?} failed with {}; skipping ommega mirror",
            method, status
        );
        return Ok(None);
    }
    if !authorization_requires_mirror(&call.request) {
        debug!(
            "event=mirror domain=authorization {:?} is read-only; preserving system reply",
            method
        );
        return Ok(None);
    }

    let event = MirrorReplayEvent::Authorization {
        request: call.request.clone(),
        caller: call.caller.clone(),
    };
    let reservation = call
        .mirror_update
        .take()
        .ok_or_else(|| anyhow::anyhow!("authorization mirror reservation is missing"))?;
    match reservation.enqueue(event) {
        Ok(()) => Ok(None),
        Err(error) => {
            warn!(
                "event=mirror domain=authorization failed to queue {:?} for ommega for uid={} pid={}: {:#}",
                method, call.caller.uid, call.caller.pid, error
            );
            Ok(Some(synthetic_fallback_reply()))
        }
    }
}

fn execute_authorization_mirror(
    request: &ParsedAuthorizationRequest,
    caller: &CallerInfo,
) -> anyhow::Result<()> {
    match request {
        ParsedAuthorizationRequest::AddAuthToken { auth_token } => {
            ipc::with_ommega_authorization_once(|auth| {
                Ok(auth.r#addAuthToken(Some(caller), auth_token)?)
            })
        }
        ParsedAuthorizationRequest::OnDeviceUnlocked { user_id, password } => {
            ipc::with_ommega_authorization_once(|auth| {
                Ok(auth.r#onDeviceUnlocked(Some(caller), *user_id, password.as_deref())?)
            })
        }
        ParsedAuthorizationRequest::OnDeviceLocked {
            user_id,
            unlocking_sids,
            weak_unlock_enabled,
        } => ipc::with_ommega_authorization_once(|auth| {
            Ok(auth.r#onDeviceLocked(
                Some(caller),
                *user_id,
                unlocking_sids,
                *weak_unlock_enabled,
            )?)
        }),
        ParsedAuthorizationRequest::OnUserStorageLocked { user_id } => {
            ipc::with_ommega_authorization_once(|auth| {
                Ok(auth.r#onUserStorageLocked(Some(caller), *user_id)?)
            })
        }
        ParsedAuthorizationRequest::OnWeakUnlockMethodsExpired { user_id } => {
            ipc::with_ommega_authorization_once(|auth| {
                Ok(auth.r#onWeakUnlockMethodsExpired(Some(caller), *user_id)?)
            })
        }
        ParsedAuthorizationRequest::OnNonLskfUnlockMethodsExpired { user_id } => {
            ipc::with_ommega_authorization_once(|auth| {
                Ok(auth.r#onNonLskfUnlockMethodsExpired(Some(caller), *user_id)?)
            })
        }
        ParsedAuthorizationRequest::GetAuthTokensForCredStore { .. }
        | ParsedAuthorizationRequest::GetLastAuthTime { .. } => Ok(()),
    }
}

pub(super) unsafe fn build_maintenance_reply_mirror(
    tr: &binder_transaction_data,
    call: &mut PendingMaintenanceCall,
) -> anyhow::Result<Option<OutboundReply>> {
    let method = call.request.method();
    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    let status = parcel::parse_reply_status(data, data_size, offsets, offsets_size)?;
    if !status.is_ok() {
        if let Some(reservation) = call.mirror_update.take() {
            reservation.cancel();
        }
        debug!(
            "event=mirror domain=maintenance system {:?} failed with {}; skipping ommega mirror",
            method, status
        );
        return Ok(None);
    }
    if !maintenance_requires_mirror(&call.request) {
        debug!(
            "event=mirror domain=maintenance {:?} is read-only or has no ommega mirror endpoint; preserving system reply",
            method
        );
        return Ok(None);
    }

    let event = MirrorReplayEvent::Maintenance {
        request: call.request.clone(),
        caller: call.caller.clone(),
    };
    let reservation = call
        .mirror_update
        .take()
        .ok_or_else(|| anyhow::anyhow!("maintenance mirror reservation is missing"))?;
    match reservation.enqueue(event) {
        Ok(()) => Ok(None),
        Err(error) => {
            warn!(
                "event=mirror domain=maintenance failed to queue {:?} for ommega for uid={} pid={}: {:#}",
                method, call.caller.uid, call.caller.pid, error
            );
            Ok(Some(synthetic_fallback_reply()))
        }
    }
}

fn execute_maintenance_mirror(
    request: &ParsedMaintenanceRequest,
    caller: &CallerInfo,
) -> anyhow::Result<()> {
    match request {
        ParsedMaintenanceRequest::OnUserAdded { user_id } => {
            ipc::with_ommega_maintenance_once(|maintenance| {
                Ok(maintenance.r#onUserAdded(Some(caller), *user_id)?)
            })
        }
        ParsedMaintenanceRequest::InitUserSuperKeys {
            user_id,
            password,
            allow_existing,
        } => ipc::with_ommega_maintenance_once(|maintenance| {
            Ok(maintenance.r#initUserSuperKeys(
                Some(caller),
                *user_id,
                password,
                *allow_existing,
            )?)
        }),
        ParsedMaintenanceRequest::OnUserRemoved { user_id } => {
            ipc::with_ommega_maintenance_once(|maintenance| {
                Ok(maintenance.r#onUserRemoved(Some(caller), *user_id)?)
            })
        }
        ParsedMaintenanceRequest::OnUserLskfRemoved { user_id } => {
            ipc::with_ommega_maintenance_once(|maintenance| {
                Ok(maintenance.r#onUserLskfRemoved(Some(caller), *user_id)?)
            })
        }
        ParsedMaintenanceRequest::ClearNamespace { domain, nspace } => {
            ipc::with_ommega_maintenance_once(|maintenance| {
                Ok(maintenance.r#clearNamespace(Some(caller), *domain, *nspace)?)
            })
        }
        ParsedMaintenanceRequest::EarlyBootEnded => {
            ipc::with_ommega_maintenance_once(|maintenance| {
                Ok(maintenance.r#earlyBootEnded(Some(caller))?)
            })
        }
        ParsedMaintenanceRequest::MigrateKeyNamespace { .. } => {
            unreachable!("migrateKeyNamespace is handled before maintenance mirroring")
        }
        ParsedMaintenanceRequest::DeleteAllKeys => {
            ipc::with_ommega_maintenance_once(|maintenance| {
                Ok(maintenance.r#deleteAllKeys(Some(caller))?)
            })
        }
        ParsedMaintenanceRequest::OnUserPasswordChanged { user_id, password } => {
            ipc::with_ommega_maintenance_once(|maintenance| {
                Ok(maintenance.r#onUserPasswordChanged(
                    Some(caller),
                    *user_id,
                    password.as_deref(),
                )?)
            })
        }
        ParsedMaintenanceRequest::GetState { .. }
        | ParsedMaintenanceRequest::OnDeviceOffBody
        | ParsedMaintenanceRequest::GetAppUidsAffectedBySid { .. } => Ok(()),
    }
}

#[cfg(test)]
mod tests;
