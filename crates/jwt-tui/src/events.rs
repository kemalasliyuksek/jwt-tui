//! Crossterm event polling helpers.

use std::time::Duration;

use crossterm::event::{Event, KeyEvent, KeyEventKind};

/// Poll for the next user event, with a timeout. Returns `Ok(None)` on
/// timeout. Filters out `KeyEventKind::Release` so callers don't see each
/// keypress twice on Windows.
pub fn poll(timeout: Duration) -> std::io::Result<Option<Event>> {
    if !crossterm::event::poll(timeout)? {
        return Ok(None);
    }
    let ev = crossterm::event::read()?;
    if let Event::Key(KeyEvent {
        kind: KeyEventKind::Release,
        ..
    }) = ev
    {
        return Ok(None);
    }
    Ok(Some(ev))
}
