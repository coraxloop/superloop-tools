mod entries;
mod planners;

use std::collections::VecDeque;
use std::time::Duration;

use crate::{CommandOutput, CommandSpec, RunError, Runner};

pub(super) struct Reply {
    label: String,
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Reply {
    pub(super) fn success(label: impl Into<String>, stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            label: label.into(),
            status: 0,
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    pub(super) fn status(label: impl Into<String>, status: i32) -> Self {
        Self {
            label: label.into(),
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    pub(super) fn failure(label: impl Into<String>, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            label: label.into(),
            status: 1,
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }
}

#[derive(Default)]
pub(super) struct ScriptedRunner {
    replies: VecDeque<Reply>,
    pub(super) commands: Vec<CommandSpec>,
}

impl ScriptedRunner {
    pub(super) fn new(replies: Vec<Reply>) -> Self {
        Self {
            replies: replies.into(),
            commands: Vec::new(),
        }
    }

    pub(super) fn assert_done(&self) {
        assert!(self.replies.is_empty(), "script has unread replies");
    }
}

impl Runner for ScriptedRunner {
    fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RunError> {
        let reply = self.replies.pop_front().expect("scripted command reply");
        assert_eq!(command.label, reply.label, "unexpected command order");
        self.commands.push(command.clone());
        Ok(CommandOutput {
            status: reply.status,
            stdout: reply.stdout,
            stderr: reply.stderr,
            wall: Duration::from_millis(5),
        })
    }
}

pub(super) fn missing_surface_replies(account: &str) -> Vec<Reply> {
    ["ssh", "authorized-keys", "git", "loops", "correspondence"]
        .into_iter()
        .flat_map(|label| {
            [
                Reply::status(format!("probe-{account}-{label}-symlink"), 1),
                Reply::status(format!("probe-{account}-{label}-exists"), 1),
            ]
        })
        .collect()
}

pub(super) fn guarded_account_replies(account: &str, uid: u32) -> Vec<Reply> {
    let mut replies = vec![
        Reply::success(format!("sudo-preflight-{account}"), Vec::new()),
        Reply::success(
            format!("probe-{account}-account"),
            format!("{account}:x:{uid}:{uid}::/var/home/{account}:/bin/bash\n"),
        ),
        Reply::success(format!("probe-{account}-groups"), format!("{account}\n")),
        Reply::success(
            format!("probe-{account}-selinux-login"),
            format!("Login Name SELinux User\n{account} staff_u s0\n"),
        ),
    ];
    replies.extend(missing_surface_replies(account));
    replies
}
