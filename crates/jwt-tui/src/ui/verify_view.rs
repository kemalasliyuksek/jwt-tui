//! Verify view.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::theme::Theme;
use jwt_core::sign::Algorithm;
use jwt_core::verify::{self, VerificationOptions, VerificationOutcome, VerifyingKey};

#[derive(Debug, Default, Clone)]
pub struct VerifyViewState {
    pub token: String,
    pub secret: String,
    pub last: Option<VerificationOutcome>,
    pub error: Option<String>,
}

impl VerifyViewState {
    pub fn run_hmac(&mut self) {
        let token = self.token.trim();
        let mut opts = VerificationOptions::strict();
        // Pin to the alg in the header — we only do HMAC here.
        if let Ok(d) = jwt_core::parse::decode_unverified(token) {
            opts.expected_alg = Algorithm::from_jose(&d.header.alg).ok();
        }
        match verify::verify(
            token,
            &VerifyingKey::Hmac(self.secret.as_bytes().to_vec()),
            &opts,
        ) {
            Ok(o) => {
                self.last = Some(o);
                self.error = None;
            }
            Err(e) => {
                self.last = None;
                self.error = Some(e.to_string());
            }
        }
    }
}

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, state: &VerifyViewState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);
    f.render_widget(
        Paragraph::new(state.token.clone())
            .style(theme.fg())
            .block(crate::ui::bordered(theme, "Token")),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(state.secret.clone())
            .style(theme.fg())
            .block(crate::ui::bordered(theme, "HMAC secret")),
        chunks[1],
    );
    let block = crate::ui::bordered(theme, "Result");
    let body = if let Some(err) = &state.error {
        Paragraph::new(Span::styled(err.clone(), theme.bad())).block(block)
    } else {
        match &state.last {
            None => Paragraph::new(Span::styled("press `v` to verify", theme.muted())).block(block),
            Some(VerificationOutcome::Valid(d)) => {
                let line1 = Line::from(Span::styled("VALID", theme.good()));
                let line2 = Line::from(Span::styled(
                    format!("alg = {}", d.header.alg),
                    theme.muted(),
                ));
                Paragraph::new(vec![line1, line2]).block(block)
            }
            Some(VerificationOutcome::Invalid { reason, .. }) => {
                Paragraph::new(Span::styled(format!("INVALID: {reason}"), theme.bad())).block(block)
            }
        }
    };
    f.render_widget(body, chunks[2]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn renders_without_panic() {
        let s = VerifyViewState::default();
        let theme = Theme::for_env();
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, f.area(), &theme, &s)).unwrap();
    }
}
