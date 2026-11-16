//! Everything a run touches outside its own arguments, injectable so tests (and the
//! in-process mode) can drive the CLI without a real terminal or network.

use crate::prompt::{LineSource, PROMPT_TIMEOUT};
use crate::resolve::{PipResolver, Resolver};
use crate::wizard::{InteractiveWizard, Wizard};
use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use trustedlicenses_core::index::{default_cache_dir, Client, HttpClient};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Red,
    Green,
    Yellow,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Style {
    pub color: Option<Color>,
    pub bold: bool,
    pub dim: bool,
}

impl Style {
    #[must_use]
    pub fn bold(color: Color) -> Self {
        Self {
            color: Some(color),
            bold: true,
            dim: false,
        }
    }

    #[must_use]
    pub fn dim() -> Self {
        Self {
            dim: true,
            ..Self::default()
        }
    }
}

pub struct Terminal {
    pub out: Box<dyn Write + Send>,
    pub err: Box<dyn Write + Send>,
    pub input: LineSource,
    pub prompt_timeout: std::time::Duration,
    /// Whether to emit ANSI styling: only on a real terminal, and never with `NO_COLOR`.
    pub color: bool,
    pub stdin_is_tty: bool,
}

impl Terminal {
    pub fn echo(&mut self, text: &str) {
        let _ = writeln!(self.out, "{text}");
    }

    pub fn secho(&mut self, text: &str, style: Style) {
        if !self.color {
            self.echo(text);
            return;
        }
        let mut codes: Vec<&str> = Vec::new();
        if style.bold {
            codes.push("1");
        }
        if style.dim {
            codes.push("2");
        }
        match style.color {
            Some(Color::Red) => codes.push("31"),
            Some(Color::Green) => codes.push("32"),
            Some(Color::Yellow) => codes.push("33"),
            None => {}
        }
        if codes.is_empty() {
            self.echo(text);
        } else {
            let _ = writeln!(self.out, "\x1b[{}m{text}\x1b[0m", codes.join(";"));
        }
    }
}

pub struct Context {
    pub term: Terminal,
    pub env: HashMap<String, String>,
    pub client: Box<dyn Client + Send>,
    pub resolver: Box<dyn Resolver + Send + Sync>,
    pub wizard: Box<dyn Wizard + Send>,
    /// Where fetched license metadata is cached; `None` means use a throwaway directory.
    pub cache_dir: Option<PathBuf>,
}

impl Context {
    #[must_use]
    pub fn from_process() -> Self {
        let env: HashMap<String, String> = std::env::vars().collect();
        let stdout_is_tty = std::io::stdout().is_terminal();
        Self {
            term: Terminal {
                out: Box::new(std::io::stdout()),
                err: Box::new(std::io::stderr()),
                input: LineSource::threaded(Box::new(std::io::BufReader::new(std::io::stdin()))),
                prompt_timeout: PROMPT_TIMEOUT,
                color: stdout_is_tty && !env.contains_key("NO_COLOR"),
                stdin_is_tty: std::io::stdin().is_terminal(),
            },
            client: Box::new(HttpClient::new()),
            resolver: Box::new(PipResolver),
            wizard: Box::new(InteractiveWizard::default()),
            cache_dir: default_cache_dir(),
            env,
        }
    }
}

/// A shareable buffer that collects what a run writes.
#[derive(Clone, Default)]
pub struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned()
    }
}

impl Context {
    /// A context for a run whose output is collected rather than printed, and which never
    /// prompts: the process environment and network, but no terminal.
    #[must_use]
    pub fn captured() -> (Self, Capture, Capture) {
        let mut context = Self::from_process();
        let (out, err) = (Capture::default(), Capture::default());
        context.term.out = Box::new(out.clone());
        context.term.err = Box::new(err.clone());
        context.term.input = LineSource::Direct(Box::new(std::io::Cursor::new(Vec::new())));
        context.term.color = false;
        context.term.stdin_is_tty = false;
        (context, out, err)
    }
}
