//! TUI application loop.

use std::io::{self, Stdout};
use std::process::ExitCode;
use std::time::Duration;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::{execute, terminal};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use ratatui::Terminal;

use crate::events;
use crate::theme::Theme;
use crate::ui;
use crate::ui::{
    attack_view::AttackViewState, decode_view::DecodeViewState, help_overlay,
    jar_view::JarViewState, sign_view::SignViewState, verify_view::VerifyViewState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Decode,
    Sign,
    Verify,
    Attack,
    Jar,
}

impl Screen {
    fn name(self) -> &'static str {
        match self {
            Self::Decode => "decode",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::Attack => "attack",
            Self::Jar => "jar",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    Insert,
    Command,
    Pending(char), // for `g d`, `g s`, etc.
}

struct AppState {
    screen: Screen,
    mode: Mode,
    show_help: bool,
    too_small: bool,
    decode: DecodeViewState,
    sign: SignViewState,
    verify: VerifyViewState,
    attack: AttackViewState,
    jar: JarViewState,
    command_buf: String,
    status_msg: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            screen: Screen::Decode,
            mode: Mode::Normal,
            show_help: false,
            too_small: false,
            decode: DecodeViewState::new(""),
            sign: SignViewState::default(),
            verify: VerifyViewState::default(),
            attack: AttackViewState,
            jar: JarViewState::default(),
            command_buf: String::new(),
            status_msg: None,
        }
    }
}

pub fn run() -> anyhow::Result<ExitCode> {
    let mut state = AppState::default();
    let mut terminal = setup_terminal()?;
    let theme = Theme::for_env();

    let result = (|| -> anyhow::Result<()> {
        loop {
            terminal.draw(|f| draw(f, &mut state, &theme))?;
            if let Some(ev) = events::poll(Duration::from_millis(250))? {
                if handle_event(&mut state, ev) {
                    break;
                }
            }
        }
        Ok(())
    })();

    teardown_terminal(&mut terminal)?;
    result.map(|_| ExitCode::SUCCESS)
}

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn teardown_terminal(term: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    let _ = terminal::disable_raw_mode();
    let _ = execute!(term.backend_mut(), terminal::LeaveAlternateScreen);
    let _ = term.show_cursor();
    Ok(())
}

fn draw(f: &mut Frame, state: &mut AppState, theme: &Theme) {
    let area = f.area();
    state.too_small = area.width < 80 || area.height < 24;
    if state.too_small {
        let msg = format!(
            "Terminal too small ({}x{}). Resize to at least 80x24.",
            area.width, area.height
        );
        f.render_widget(Paragraph::new(msg).style(theme.warn()), area);
        return;
    }

    let bands = ui::three_band(area);
    let mode_label = match state.mode {
        Mode::Normal => "NORMAL",
        Mode::Insert => "INSERT",
        Mode::Command => "COMMAND",
        Mode::Pending(_) => "PENDING",
    };
    ui::render_status_bar(f, bands[0], theme, state.screen.name(), mode_label);

    match state.screen {
        Screen::Decode => crate::ui::decode_view::render(f, bands[1], theme, &state.decode),
        Screen::Sign => crate::ui::sign_view::render(f, bands[1], theme, &state.sign),
        Screen::Verify => crate::ui::verify_view::render(f, bands[1], theme, &state.verify),
        Screen::Attack => crate::ui::attack_view::render(f, bands[1], theme, &state.attack),
        Screen::Jar => crate::ui::jar_view::render(f, bands[1], theme, &state.jar),
    }

    render_footer(f, bands[2], theme, state);

    if state.show_help {
        help_overlay::render(f, area, theme);
    }
}

fn render_footer(f: &mut Frame, area: Rect, theme: &Theme, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let hints: Vec<(&str, &str)> = match state.screen {
        Screen::Decode => vec![
            ("i", "edit"),
            ("y", "yank"),
            ("Ctrl-S", "save to jar"),
            ("?", "help"),
        ],
        Screen::Sign => vec![("←/→", "alg"), ("s", "sign"), ("y", "yank"), ("?", "help")],
        Screen::Verify => vec![("v", "verify"), ("?", "help")],
        Screen::Attack => vec![("?", "help")],
        Screen::Jar => vec![("d", "delete"), ("Enter", "open"), ("?", "help")],
    };
    crate::ui::render_hints(f, chunks[0], theme, &hints);

    let right = match state.mode {
        Mode::Command => format!(":{}", state.command_buf),
        _ => state.status_msg.clone().unwrap_or_default(),
    };
    f.render_widget(Paragraph::new(right).style(theme.muted()), chunks[1]);
}

/// Returns `true` to quit.
fn handle_event(state: &mut AppState, ev: Event) -> bool {
    let Event::Key(KeyEvent {
        code, modifiers, ..
    }) = ev
    else {
        return false;
    };

    if state.show_help {
        if matches!(code, KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q')) {
            state.show_help = false;
        }
        return false;
    }

    match state.mode {
        Mode::Insert => return handle_insert(state, code, modifiers),
        Mode::Command => return handle_command(state, code),
        Mode::Pending(prefix) => return handle_pending(state, prefix, code),
        Mode::Normal => {}
    }

    match (code, modifiers) {
        (KeyCode::Char('q') | KeyCode::Esc, _) => return true,
        (KeyCode::Char('?'), _) => state.show_help = true,
        (KeyCode::Char(':'), _) => state.mode = Mode::Command,
        (KeyCode::Char('g'), _) => state.mode = Mode::Pending('g'),
        (KeyCode::Char('i'), _) => state.mode = Mode::Insert,
        (KeyCode::Char('s'), m) if m.contains(KeyModifiers::CONTROL) => save_token(state),
        (KeyCode::Char('y'), m) if m.contains(KeyModifiers::CONTROL) => yank(state),
        (KeyCode::Char('y' | 'Y'), _) => yank(state),
        (KeyCode::Char('s'), _) if state.screen == Screen::Sign => state.sign.try_sign(),
        (KeyCode::Char('v'), _) if state.screen == Screen::Verify => state.verify.run_hmac(),
        (KeyCode::Left, _) if state.screen == Screen::Sign => state.sign.cycle_alg(-1),
        (KeyCode::Right, _) if state.screen == Screen::Sign => state.sign.cycle_alg(1),
        _ => {}
    }
    false
}

fn handle_insert(state: &mut AppState, code: KeyCode, modifiers: KeyModifiers) -> bool {
    if matches!(code, KeyCode::Esc) {
        state.mode = Mode::Normal;
        return false;
    }
    let target: &mut String = match state.screen {
        Screen::Decode => &mut state.decode.token,
        Screen::Sign => &mut state.sign.payload_text,
        Screen::Verify => &mut state.verify.token,
        _ => return false,
    };
    match code {
        KeyCode::Char(c) if !modifiers.contains(KeyModifiers::CONTROL) => {
            target.push(c);
        }
        KeyCode::Backspace => {
            target.pop();
        }
        KeyCode::Enter => target.push('\n'),
        _ => {}
    }
    if state.screen == Screen::Decode {
        state.decode.refresh();
    }
    false
}

fn handle_command(state: &mut AppState, code: KeyCode) -> bool {
    match code {
        KeyCode::Esc => {
            state.command_buf.clear();
            state.mode = Mode::Normal;
        }
        KeyCode::Enter => {
            let cmd = std::mem::take(&mut state.command_buf);
            state.mode = Mode::Normal;
            return run_command(state, &cmd);
        }
        KeyCode::Backspace => {
            state.command_buf.pop();
        }
        KeyCode::Char(c) => state.command_buf.push(c),
        _ => {}
    }
    false
}

fn handle_pending(state: &mut AppState, prefix: char, code: KeyCode) -> bool {
    state.mode = Mode::Normal;
    if prefix != 'g' {
        return false;
    }
    let next = match code {
        KeyCode::Char('d') => Screen::Decode,
        KeyCode::Char('s') => Screen::Sign,
        KeyCode::Char('v') => Screen::Verify,
        KeyCode::Char('a') => Screen::Attack,
        KeyCode::Char('j') => {
            state.jar.refresh();
            Screen::Jar
        }
        _ => return false,
    };
    state.screen = next;
    false
}

fn run_command(state: &mut AppState, cmd: &str) -> bool {
    match cmd.trim() {
        "q" | "quit" => return true,
        "help" => state.show_help = true,
        other => state.status_msg = Some(format!("unknown command: {other}")),
    }
    false
}

fn yank(state: &mut AppState) {
    let payload = match state.screen {
        Screen::Decode => state.decode.token.clone(),
        Screen::Sign => state.sign.generated_token.clone().unwrap_or_default(),
        Screen::Verify => state.verify.token.clone(),
        _ => return,
    };
    if payload.is_empty() {
        state.status_msg = Some("nothing to yank".into());
        return;
    }
    match arboard::Clipboard::new().and_then(|mut c| c.set_text(payload)) {
        Ok(()) => state.status_msg = Some("yanked".into()),
        Err(e) => state.status_msg = Some(format!("clipboard: {e}")),
    }
}

fn save_token(state: &mut AppState) {
    let token = match state.screen {
        Screen::Decode => state.decode.token.clone(),
        Screen::Sign => state.sign.generated_token.clone().unwrap_or_default(),
        Screen::Verify => state.verify.token.clone(),
        _ => return,
    };
    if token.is_empty() {
        state.status_msg = Some("nothing to save".into());
        return;
    }
    match crate::jar::Jar::open_default()
        .and_then(|mut j| j.insert("quick-save", token.trim(), &[], None))
    {
        Ok(id) => state.status_msg = Some(format!("saved as #{id}")),
        Err(e) => state.status_msg = Some(format!("save failed: {e}")),
    }
}
