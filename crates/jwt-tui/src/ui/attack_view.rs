//! Attack lab view (TUI).

use jwt_core::attacks::{kid_injection, LAB_BANNER};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::theme::Theme;

#[derive(Debug, Default)]
pub struct AttackViewState;

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, _state: &AttackViewState) {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(LAB_BANNER, theme.warn())));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Available attacks (run via CLI for full power):",
        theme.accent(),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  alg-none, hs-confusion, kid (templates below), hs-brute, jku-redirect",
        theme.fg(),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("kid templates:", theme.accent())));
    for t in kid_injection::TEMPLATES {
        lines.push(Line::from(vec![
            Span::styled(format!("  [{:<22}] ", t.label), theme.muted()),
            Span::styled(t.kid.to_string(), theme.fg()),
        ]));
    }

    f.render_widget(
        Paragraph::new(lines).block(crate::ui::bordered(theme, "Attack Lab")),
        area,
    );
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
        term.draw(|f| render(f, f.area(), &theme, &AttackViewState))
            .unwrap();
    }
}
