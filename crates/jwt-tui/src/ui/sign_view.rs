//! Sign / forge view.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::theme::Theme;
use jwt_core::sign::{self, Algorithm, SigningKey};

#[derive(Debug, Clone)]
pub struct SignViewState {
    pub alg_idx: usize,
    pub header_text: String,
    pub payload_text: String,
    pub secret_text: String,
    pub generated_token: Option<String>,
    pub error: Option<String>,
}

impl Default for SignViewState {
    fn default() -> Self {
        Self {
            alg_idx: 0,
            header_text: r#"{"alg":"HS256","typ":"JWT"}"#.into(),
            payload_text: r#"{"sub":"alice","iat":1700000000}"#.into(),
            secret_text: "shh".into(),
            generated_token: None,
            error: None,
        }
    }
}

impl SignViewState {
    pub fn current_alg(&self) -> Algorithm {
        Algorithm::ALL[self.alg_idx % Algorithm::ALL.len()]
    }

    pub fn cycle_alg(&mut self, delta: i32) {
        let n = Algorithm::ALL.len() as i32;
        let idx = ((self.alg_idx as i32 + delta).rem_euclid(n)) as usize;
        self.alg_idx = idx;
    }

    pub fn try_sign(&mut self) {
        let alg = self.current_alg();
        let header: serde_json::Value = match serde_json::from_str(&self.header_text) {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(format!("header JSON: {e}"));
                self.generated_token = None;
                return;
            }
        };
        let payload: serde_json::Value = match serde_json::from_str(&self.payload_text) {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(format!("payload JSON: {e}"));
                self.generated_token = None;
                return;
            }
        };
        let key = match alg {
            Algorithm::None => SigningKey::None,
            a if a.is_symmetric() => SigningKey::Hmac(self.secret_text.as_bytes().to_vec()),
            a => {
                self.error = Some(format!(
                    "asymmetric algorithm {a} not supported in TUI sign view yet — use CLI"
                ));
                return;
            }
        };
        match sign::sign(alg, &key, &header, &payload) {
            Ok(t) => {
                self.generated_token = Some(t);
                self.error = None;
            }
            Err(e) => {
                self.generated_token = None;
                self.error = Some(e.to_string());
            }
        }
    }
}

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, state: &SignViewState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // alg picker
            Constraint::Min(0),    // header / payload / secret
            Constraint::Length(5), // output
        ])
        .split(area);

    render_alg_picker(f, chunks[0], theme, state);
    render_inputs(f, chunks[1], theme, state);
    render_output(f, chunks[2], theme, state);
}

fn render_alg_picker(f: &mut Frame, area: Rect, theme: &Theme, state: &SignViewState) {
    let mut spans = Vec::new();
    for (i, a) in Algorithm::ALL.iter().enumerate() {
        let style = if i == state.alg_idx {
            theme.accent()
        } else {
            theme.muted()
        };
        spans.push(Span::styled(format!(" {a} "), style));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)).block(crate::ui::bordered(theme, "Algorithm  (←/→)")),
        area,
    );
}

fn render_inputs(f: &mut Frame, area: Rect, theme: &Theme, state: &SignViewState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(area);
    f.render_widget(
        Paragraph::new(state.header_text.clone())
            .style(theme.fg())
            .block(crate::ui::bordered(theme, "Header JSON")),
        cols[0],
    );
    f.render_widget(
        Paragraph::new(state.payload_text.clone())
            .style(theme.fg())
            .block(crate::ui::bordered(theme, "Payload JSON")),
        cols[1],
    );
    f.render_widget(
        Paragraph::new(state.secret_text.clone())
            .style(theme.fg())
            .block(crate::ui::bordered(theme, "Secret / Key")),
        cols[2],
    );
}

fn render_output(f: &mut Frame, area: Rect, theme: &Theme, state: &SignViewState) {
    let block = crate::ui::bordered(theme, "Output");
    let body = if let Some(err) = &state.error {
        Paragraph::new(Span::styled(err.clone(), theme.bad())).block(block)
    } else if let Some(t) = &state.generated_token {
        Paragraph::new(Span::styled(t.clone(), theme.good())).block(block)
    } else {
        Paragraph::new(Span::styled("press `s` to sign", theme.muted())).block(block)
    };
    f.render_widget(body, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn round_trip_signing_via_state() {
        let mut s = SignViewState::default();
        s.try_sign();
        assert!(s.generated_token.is_some(), "{:?}", s.error);
    }

    #[test]
    fn render_does_not_panic() {
        let s = SignViewState::default();
        let theme = Theme::for_env();
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, f.area(), &theme, &s)).unwrap();
    }
}
