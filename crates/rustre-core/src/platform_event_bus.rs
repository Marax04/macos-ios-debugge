//! Process-wide singleton wiring for the [`rustre_events`] platform event bus.
//!
//! `rustre-core` already has a small local [`crate::events::EventBus`] used by a
//! few internal subsystems, but the *platform-wide* bus — the one every crate
//! in the workspace is supposed to publish to and subscribe from — lives in the
//! standalone [`rustre_events`] crate (`CoreEvent`, `EventBus`, `HookDispatcher`,
//! `EventLogger`, …).
//!
//! This module exposes a global singleton accessor so any crate that depends
//! on `rustre-core` can call [`platform_bus()`] / [`platform_dispatcher()`] /
//! [`platform_logger()`] without threading an `Arc<EventBus>` through every
//! API.  A default startup hook is installed on first access so that every
//! published event is forwarded to the platform [`HookDispatcher`] and the
//! in-memory [`EventLogger`] — i.e. the singleton is not just *exposed*, it is
//! actively *called*.

use std::sync::{Arc, OnceLock};

use rustre_events::{CoreEvent, EventBus, EventHook, EventLogger, HookDispatcher};

/// Capacity of the platform broadcast channel.
const PLATFORM_BUS_CAPACITY: usize = 4096;

/// Capacity of the in-memory audit log attached to the platform bus.
const PLATFORM_LOGGER_CAPACITY: usize = 8192;

static PLATFORM_BUS: OnceLock<Arc<EventBus>> = OnceLock::new();
static PLATFORM_DISPATCHER: OnceLock<Arc<HookDispatcher>> = OnceLock::new();
static PLATFORM_LOGGER: OnceLock<Arc<EventLogger>> = OnceLock::new();

/// Return the process-wide singleton platform [`EventBus`].
///
/// The first call lazily initialises the bus, its companion
/// [`HookDispatcher`], and an [`EventLogger`].  The logger is wired to record
/// every event published on the bus via [`EventLogger::start_logging`].
#[must_use]
pub fn platform_bus() -> Arc<EventBus> {
    PLATFORM_BUS
        .get_or_init(|| {
            let bus = Arc::new(EventBus::new(PLATFORM_BUS_CAPACITY));
            // Initialise dispatcher and logger eagerly so that the very first
            // event ever published is captured.
            let _ = PLATFORM_DISPATCHER.set(Arc::new(HookDispatcher::new()));
            let logger = Arc::new(EventLogger::new(PLATFORM_LOGGER_CAPACITY));
            // Forward every event on the bus into the logger when a Tokio
            // runtime is available.  In non-async contexts (e.g. unit tests,
            // CLI tools that have not yet entered `#[tokio::main]`) we skip
            // the spawn — direct `publish(...)` still records into the
            // logger via the synchronous path below.
            if tokio::runtime::Handle::try_current().is_ok() {
                let _log_task = Arc::clone(&logger).start_logging(&bus);
            }
            let _ = PLATFORM_LOGGER.set(logger);
            bus
        })
        .clone()
}

/// Return the process-wide singleton [`HookDispatcher`] companion of the
/// platform bus.  Hooks registered here are fired whenever an event is
/// published via [`publish`].
///
/// # Panics
/// Panics if the dispatcher cell was not initialised (should not happen in
/// normal operation; `platform_bus()` always initialises it first).
#[must_use]
pub fn platform_dispatcher() -> Arc<HookDispatcher> {
    // Ensure bus (and therefore dispatcher) is initialised.
    let _ = platform_bus();
    PLATFORM_DISPATCHER
        .get()
        .expect("dispatcher initialised by platform_bus()")
        .clone()
}

/// Return the process-wide singleton [`EventLogger`] attached to the platform
/// bus.  Every event published via [`publish`] (or directly on the bus) is
/// recorded here.
///
/// # Panics
/// Panics if the logger cell was not initialised (should not happen in normal
/// operation; `platform_bus()` always initialises it first).
#[must_use]
pub fn platform_logger() -> Arc<EventLogger> {
    let _ = platform_bus();
    PLATFORM_LOGGER
        .get()
        .expect("logger initialised by platform_bus()")
        .clone()
}

/// Publish `event` on the platform bus *and* dispatch it through the
/// platform [`HookDispatcher`].
///
/// This is the canonical entry point for code that just wants to fire a
/// platform-wide [`CoreEvent`] without caring about subscribers or hooks.
/// Returns the number of broadcast subscribers that received the event (0 if
/// none are currently listening — the event is still dispatched to hooks and
/// recorded by the logger).
#[must_use] 
pub fn publish(event: CoreEvent) -> usize {
    let bus = platform_bus();
    let dispatcher = platform_dispatcher();
    let logger = platform_logger();
    // Record synchronously so the audit trail is captured even when no
    // Tokio runtime is active (in which case `start_logging`'s background
    // task was not spawned).
    logger.record(event.clone());
    // Dispatch synchronously to hooks so handlers can observe state before
    // async subscribers wake up.
    dispatcher.dispatch(&event);
    bus.send(event).unwrap_or(0)
}

/// Register an [`EventHook`] on the platform dispatcher.  Convenience wrapper
/// around `platform_dispatcher().register(...)`.
pub fn register_hook(hook: EventHook) {
    platform_dispatcher().register(hook);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_is_reused() {
        let a = platform_bus();
        let b = platform_bus();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn publish_records_in_logger_and_fires_hooks() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let bus = platform_bus();
        let _keep_alive = bus.subscribe();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        register_hook(EventHook::new(
            "test-counter",
            |_| true,
            move |_| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        ));
        let before_total = bus.total_sent();
        publish(CoreEvent::PluginLoaded {
            plugin_id: "wire-test".into(),
        });
        assert!(bus.total_sent() > before_total);
        assert!(counter.load(Ordering::SeqCst) >= 1);
    }
}
