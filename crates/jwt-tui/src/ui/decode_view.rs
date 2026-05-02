//! Three-pane decode view: token (raw) | header | payload.

use chrono::{DateTime, Utc};
use jwt_core::parse::{decode_unverified, DecodedToken};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::theme::Theme;

#[derive(Debug, Default)]
pub struct DecodeViewState {
    pub token: String,
    pub error: Option<String>,
    pub decoded: Option<DecodedToken>,
}

impl DecodeViewState {
    pub fn new(initial_token: &str) -> Self {
        let mut s = Self {
            token: initial_token.to_string(),
            ..Default::default()
        };
        s.refresh();
        s
    }

    pub fn set_token(&mut self, token: String) {
        self.token = token;
        self.refresh();
    }

    pub fn refresh(&mut self) {
        match decode_unverified(self.token.trim()) {
            Ok(d) => {
                self.decoded = Some(d);
                self.error = None;
            }
            Err(e) => {
                self.decoded = None;
                self.error = Some(e.to_string());
            }
        }
    }
}

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, state: &DecodeViewState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // raw token area
            Constraint::Min(0),    // panes
            Constraint::Length(3), // signature footer
        ])
        .split(area);

    render_token_pane(f, chunks[0], theme, state);

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    render_header_pane(f, panes[0], theme, state);
    render_payload_pane(f, panes[1], theme, state);

    render_signature_footer(f, chunks[2], theme, state);
}

fn render_token_pane(f: &mut Frame, area: Rect, theme: &Theme, state: &DecodeViewState) {
    let block = crate::ui::bordered(theme, "Token (raw)");
    let body = if state.token.is_empty() {
        Paragraph::new(Span::styled(
            "Paste a token (i to enter insert mode).",
            theme.muted(),
        ))
        .block(block)
    } else {
        Paragraph::new(state.token.clone())
            .style(theme.fg())
            .wrap(Wrap { trim: false })
            .block(block)
    };
    f.render_widget(body, area);
}

fn render_header_pane(f: &mut Frame, area: Rect, theme: &Theme, state: &DecodeViewState) {
    let block = crate::ui::bordered(theme, "Header");
    let lines: Vec<Line> = match (&state.decoded, &state.error) {
        (Some(d), _) => {
            let mut out =
                json_to_lines(&serde_json::to_value(&d.header).unwrap_or_default(), theme);
            let warnings = d.header.dangerous_warnings();
            if !warnings.is_empty() {
                out.push(Line::from(""));
                for w in warnings {
                    out.push(Line::from(Span::styled(format!("! {w}"), theme.warn())));
                }
            }
            out
        }
        (None, Some(err)) => vec![Line::from(Span::styled(err, theme.bad()))],
        _ => Vec::new(),
    };
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_payload_pane(f: &mut Frame, area: Rect, theme: &Theme, state: &DecodeViewState) {
    let block = crate::ui::bordered(theme, "Payload");
    let lines: Vec<Line> = match &state.decoded {
        Some(d) => {
            let mut out = json_to_lines(&d.payload, theme);
            // append humanized time claims
            for k in ["exp", "iat", "nbf"] {
                if let Some(v) = d.payload.get(k).and_then(|v| v.as_i64()) {
                    let when = DateTime::<Utc>::from_timestamp(v, 0)
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_else(|| "?".into());
                    let now = Utc::now().timestamp();
                    let style = match k {
                        "exp" if v < now => theme.bad(),
                        "nbf" if v > now => theme.warn(),
                        _ => theme.muted(),
                    };
                    out.push(Line::from(Span::styled(format!("{k} → {when}"), style)));
                }
            }
            out
        }
        None => Vec::new(),
    };
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_signature_footer(f: &mut Frame, area: Rect, theme: &Theme, state: &DecodeViewState) {
    let block = crate::ui::bordered(theme, "Signature");
    let body = match &state.decoded {
        Some(d) if !d.signature.is_empty() => {
            let hex = hex::encode(&d.signature);
            let short_hex = if hex.len() > 64 {
                format!("{}…", &hex[..63])
            } else {
                hex
            };
            Paragraph::new(Line::from(vec![
                Span::styled("hex: ", theme.muted()),
                Span::styled(short_hex, theme.fg()),
                Span::raw("    "),
                Span::styled("b64url: ", theme.muted()),
                Span::styled(d.raw_signature.clone(), theme.fg()),
            ]))
            .block(block)
        }
        Some(_) => Paragraph::new(Span::styled("(empty — alg=none)", theme.warn())).block(block),
        None => Paragraph::new("").block(block),
    };
    f.render_widget(body, area);
}

fn json_to_lines<'a>(v: &serde_json::Value, theme: &Theme) -> Vec<Line<'a>> {
    let pretty = serde_json::to_string_pretty(v).unwrap_or_default();
    pretty
        .lines()
        .map(|l| Line::from(Span::styled(l.to_string(), theme.fg())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn renders_decode_view_without_panic() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
            SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let theme = Theme::for_env();
        let state = DecodeViewState::new(token);
        let backend = TestBackend::new(120, 40);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render(f, f.area(), &theme, &state);
        })
        .unwrap();
    }

    #[test]
    fn renders_below_minimum_size_without_panic() {
        let theme = Theme::for_env();
        let state = DecodeViewState::new("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhYmMifQ.");
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render(f, f.area(), &theme, &state);
        })
        .unwrap();
    }
}
