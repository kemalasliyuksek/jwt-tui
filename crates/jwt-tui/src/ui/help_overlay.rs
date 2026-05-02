//! `?`-triggered help overlay listing every keybinding.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};
use ratatui::Frame;

use crate::theme::Theme;

const ROWS: &[(&str, &str)] = &[
    ("?", "Toggle this help overlay"),
    ("q / Esc", "Quit (or close overlay)"),
    ("g d", "Go to Decode"),
    ("g s", "Go to Sign"),
    ("g v", "Go to Verify"),
    ("g a", "Go to Attack lab"),
    ("g j", "Go to Token jar"),
    ("Tab / Shift+Tab", "Cycle panes / fields"),
    ("i", "Insert mode (text fields)"),
    ("Esc", "Leave insert mode"),
    (":", "Command prompt"),
    ("Ctrl+S", "Save current token to jar"),
    ("Ctrl+Y / y", "Yank to clipboard"),
    ("←/→ in Sign", "Cycle algorithm"),
    ("s in Sign", "Re-sign with current inputs"),
    ("v in Verify", "Run HMAC verification"),
];

pub fn render(f: &mut Frame, area: Rect, theme: &Theme) {
    let popup = centered_rect(70, 70, area);
    f.render_widget(Clear, popup);

    let lines: Vec<Line> = std::iter::once(Line::from(Span::styled(
        "jwt-tui keybindings",
        theme.accent(),
    )))
    .chain(std::iter::once(Line::from("")))
    .chain(ROWS.iter().map(|(k, v)| {
        Line::from(vec![
            Span::styled(format!("{k:<18}", k = k), theme.accent()),
            Span::styled((*v).to_string(), theme.fg()),
        ])
    }))
    .collect();

    let p = Paragraph::new(lines).block(crate::ui::bordered(theme, "Help (press `?` to close)"));
    f.render_widget(p, popup);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let chunks_y = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    let chunks_x = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(chunks_y[1]);
    chunks_x[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn render_does_not_panic() {
        let theme = Theme::for_env();
        let backend = TestBackend::new(120, 40);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, f.area(), &theme)).unwrap();
    }
}
