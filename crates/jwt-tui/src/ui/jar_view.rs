//! Token-jar view (TUI).

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem};
use ratatui::Frame;

use crate::jar::{Jar, JarEntry};
use crate::theme::Theme;

#[derive(Debug, Default)]
pub struct JarViewState {
    pub entries: Vec<JarEntry>,
    pub error: Option<String>,
    pub selected: usize,
}

impl JarViewState {
    pub fn refresh(&mut self) {
        match Jar::open_default().and_then(|j| j.list()) {
            Ok(e) => {
                self.entries = e;
                self.error = None;
                if self.selected >= self.entries.len() && !self.entries.is_empty() {
                    self.selected = self.entries.len() - 1;
                }
            }
            Err(e) => {
                self.error = Some(e.to_string());
            }
        }
    }
}

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, state: &JarViewState) {
    if let Some(e) = &state.error {
        let p = ratatui::widgets::Paragraph::new(Span::styled(e.clone(), theme.bad()))
            .block(crate::ui::bordered(theme, "Token Jar"));
        f.render_widget(p, area);
        return;
    }
    let items: Vec<ListItem> = state
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let style = if i == state.selected {
                theme.accent()
            } else {
                theme.fg()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:>3}  ", e.id), theme.muted()),
                Span::styled(e.label.clone(), style),
                Span::styled(format!("  [{}]", e.tags.join(",")), theme.muted()),
            ]))
        })
        .collect();
    let list = List::new(items).block(crate::ui::bordered(theme, "Token Jar"));
    f.render_widget(list, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn render_does_not_panic() {
        let theme = Theme::for_env();
        let state = JarViewState::default();
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, f.area(), &theme, &state)).unwrap();
    }
}
