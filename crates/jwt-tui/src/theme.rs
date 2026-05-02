//! Color theme. Loaded from `theme.toml` if present, with three built-ins.

use ratatui::style::{Color, Modifier, Style};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub enum BuiltinTheme {
    Dark,
    Light,
    HighContrast,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeColors {
    pub bg: String,
    pub fg: String,
    pub accent: String,
    pub muted: String,
    pub good: String,
    pub bad: String,
    pub warn: String,
    pub border: String,
    pub selection: String,
}

impl ThemeColors {
    #[must_use]
    pub fn dark() -> Self {
        Self {
            bg: "#0b0d10".into(),
            fg: "#d6d6d6".into(),
            accent: "#7eb6ff".into(),
            muted: "#7d8590".into(),
            good: "#7ee787".into(),
            bad: "#ff7b72".into(),
            warn: "#f0883e".into(),
            border: "#30363d".into(),
            selection: "#264f78".into(),
        }
    }
    #[must_use]
    pub fn light() -> Self {
        Self {
            bg: "#ffffff".into(),
            fg: "#1f2328".into(),
            accent: "#0969da".into(),
            muted: "#656d76".into(),
            good: "#1a7f37".into(),
            bad: "#cf222e".into(),
            warn: "#9a6700".into(),
            border: "#d0d7de".into(),
            selection: "#ddf4ff".into(),
        }
    }
    #[must_use]
    pub fn high_contrast() -> Self {
        Self {
            bg: "#000000".into(),
            fg: "#ffffff".into(),
            accent: "#ffff00".into(),
            muted: "#c0c0c0".into(),
            good: "#00ff00".into(),
            bad: "#ff0000".into(),
            warn: "#ffaa00".into(),
            border: "#ffffff".into(),
            selection: "#444400".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub colors: ThemeColors,
    pub no_color: bool,
}

impl Theme {
    pub fn for_env() -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        Self {
            colors: ThemeColors::dark(),
            no_color,
        }
    }

    pub fn from_builtin(b: BuiltinTheme) -> Self {
        Self {
            colors: match b {
                BuiltinTheme::Dark => ThemeColors::dark(),
                BuiltinTheme::Light => ThemeColors::light(),
                BuiltinTheme::HighContrast => ThemeColors::high_contrast(),
            },
            no_color: std::env::var_os("NO_COLOR").is_some(),
        }
    }

    pub fn fg(&self) -> Style {
        if self.no_color {
            Style::default()
        } else {
            Style::default().fg(parse_color(&self.colors.fg))
        }
    }

    pub fn accent(&self) -> Style {
        if self.no_color {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(parse_color(&self.colors.accent))
                .add_modifier(Modifier::BOLD)
        }
    }

    pub fn muted(&self) -> Style {
        if self.no_color {
            Style::default().add_modifier(Modifier::DIM)
        } else {
            Style::default().fg(parse_color(&self.colors.muted))
        }
    }

    pub fn good(&self) -> Style {
        if self.no_color {
            Style::default()
        } else {
            Style::default().fg(parse_color(&self.colors.good))
        }
    }

    pub fn bad(&self) -> Style {
        if self.no_color {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().fg(parse_color(&self.colors.bad))
        }
    }

    pub fn warn(&self) -> Style {
        if self.no_color {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(parse_color(&self.colors.warn))
        }
    }

    pub fn border(&self) -> Style {
        if self.no_color {
            Style::default()
        } else {
            Style::default().fg(parse_color(&self.colors.border))
        }
    }
}

fn parse_color(s: &str) -> Color {
    if let Some(hex) = s.strip_prefix('#') {
        if hex.len() == 6 {
            let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(255);
            let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(255);
            let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(255);
            return Color::Rgb(r, g, b);
        }
    }
    match s {
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "white" => Color::White,
        _ => Color::Reset,
    }
}
