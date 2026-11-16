//! Prompting, at the level the wizard needs: ask a yes/no question, ask for a line.
//!
//! The real implementation follows click's conventions (`[Y/n]` hints, re-asking on invalid
//! input, EOF aborts) and gives every prompt a time limit, so a CI job that still has a
//! terminal attached cannot hang forever waiting for an answer nobody is there to give.

use crate::context::{Color, Style, Terminal};
use std::io::{BufRead, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

/// How long to wait for an answer to any single prompt before giving up. A safety net for
/// a misconfigured non-interactive job, not a knob anyone should need to tune.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptError {
    /// No answer arrived in time.
    Timeout,
    /// The input ended (EOF) or was interrupted: abort the whole run.
    Aborted,
}

/// Where answers come from.
pub enum LineSource {
    /// Read directly, without a time limit (tests, piped input).
    Direct(Box<dyn BufRead + Send>),
    /// Lines delivered by a reader thread, so a read can time out.
    Threaded(Receiver<String>),
}

impl LineSource {
    /// Spawn a reader thread over `input`.
    pub fn threaded(mut input: Box<dyn BufRead + Send>) -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || loop {
            let mut line = String::new();
            match input.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            }
        });
        Self::Threaded(receiver)
    }

    fn read(&mut self, timeout: Duration) -> Result<String, PromptError> {
        match self {
            Self::Direct(input) => {
                let mut line = String::new();
                match input.read_line(&mut line) {
                    Ok(0) | Err(_) => Err(PromptError::Aborted),
                    Ok(_) => Ok(line),
                }
            }
            Self::Threaded(receiver) => match receiver.recv_timeout(timeout) {
                Ok(line) => Ok(line),
                Err(RecvTimeoutError::Timeout) => Err(PromptError::Timeout),
                Err(RecvTimeoutError::Disconnected) => Err(PromptError::Aborted),
            },
        }
    }
}

pub trait Prompter {
    fn echo(&mut self, text: &str);
    fn secho(&mut self, text: &str, style: Style);

    /// Ask a yes/no question.
    ///
    /// # Errors
    ///
    /// [`PromptError::Timeout`] when unanswered, [`PromptError::Aborted`] on end of input.
    fn confirm(&mut self, text: &str, default: bool) -> Result<bool, PromptError>;

    /// Ask for a line of text, returning `default` for an empty answer. The default is not
    /// shown.
    ///
    /// # Errors
    ///
    /// As for [`Prompter::confirm`].
    fn prompt(&mut self, text: &str, default: &str) -> Result<String, PromptError>;

    /// The time limit the wizard reports in its timeout message.
    fn timeout(&self) -> Duration {
        PROMPT_TIMEOUT
    }
}

impl Prompter for Terminal {
    fn echo(&mut self, text: &str) {
        Terminal::echo(self, text);
    }

    fn secho(&mut self, text: &str, style: Style) {
        Terminal::secho(self, text, style);
    }

    fn confirm(&mut self, text: &str, default: bool) -> Result<bool, PromptError> {
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        loop {
            let answer = self.ask(&format!("{text} {hint}: "))?;
            match answer.trim().to_lowercase().as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => self.echo("Error: invalid input"),
            }
        }
    }

    fn prompt(&mut self, text: &str, default: &str) -> Result<String, PromptError> {
        let answer = self.ask(&format!("{text}: "))?;
        let answer = answer.trim_end_matches(['\r', '\n']);
        Ok(if answer.is_empty() {
            default.to_owned()
        } else {
            answer.to_owned()
        })
    }

    fn timeout(&self) -> Duration {
        self.prompt_timeout
    }
}

impl Terminal {
    /// Print `question`, then read one line. Input that is not coming from a keyboard is
    /// echoed back, so a transcript of the run reads like a conversation.
    fn ask(&mut self, question: &str) -> Result<String, PromptError> {
        let _ = write!(self.out, "{question}");
        let _ = self.out.flush();
        let line = self.input.read(self.prompt_timeout)?;
        if !self.stdin_is_tty {
            let _ = writeln!(self.out, "{}", line.trim_end_matches(['\r', '\n']));
        }
        Ok(line)
    }
}

/// The message shown when a prompt times out, so the user knows how to avoid it.
pub fn timeout_notice(io: &mut dyn Prompter, what: &str, tail: &str) {
    io.secho(
        &format!(
            "\nNo answer received within {:.0}s -- {what}. {tail}",
            io.timeout().as_secs_f64()
        ),
        Style::bold(Color::Yellow),
    );
}
