//! TUI views.

pub mod attack_view;
pub mod decode_view;
pub mod help_overlay;
pub mod jar_view;
pub mod sign_view;
pub mod verify_view;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::theme::Theme;

/// Top status bar shown on every screen.
pub fn render_status_bar(f: &mut Frame, area: Rect, theme: &Theme, current: &str, mode: &str) {
    let line = Line::from(vec![
        Span::styled(" jwt-tui ", theme.accent()),
        Span::styled(format!("│ {current} "), theme.fg()),
        Span::styled(format!("[{mode}]"), theme.muted()),
        Span::styled("    `?` help  `q` quit  `g` jump", theme.muted()),
    ]);
    let p = Paragraph::new(line).block(Block::default());
    f.render_widget(p, area);
}

/// Bottom hint line — view-specific keybindings.
pub fn render_hints(f: &mut Frame, area: Rect, theme: &Theme, hints: &[(&str, &str)]) {
    let mut spans = vec![Span::raw(" ")];
    for (k, label) in hints {
        spans.push(Span::styled(format!("[{k}] "), theme.accent()));
        spans.push(Span::styled(format!("{label}  "), theme.muted()));
    }
    let p = Paragraph::new(Line::from(spans));
    f.render_widget(p, area);
}

/// Standard top/bottom layout.
#[must_use]
pub fn three_band(area: Rect) -> [Rect; 3] {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);
    [chunks[0], chunks[1], chunks[2]]
}

pub fn bordered<'a>(theme: &Theme, title: &'a str) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border())
        .title(Span::styled(format!(" {title} "), theme.accent()))
}
