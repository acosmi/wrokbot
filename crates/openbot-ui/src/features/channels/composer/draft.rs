//! Pure boundary between editor segments and one message draft.

#![cfg_attr(not(test), allow(dead_code))]

use std::borrow::Cow;

use openbot_contracts::text::trim_ecmascript;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChipTrigger {
    Agent,
    Command,
}

impl ChipTrigger {
    const fn marker(self) -> char {
        match self {
            Self::Agent => '@',
            Self::Command => '/',
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Segment {
    Text(String),
    Chip {
        trigger: ChipTrigger,
        value: String,
        display_text: String,
    },
}

impl Segment {
    pub(crate) fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    pub(crate) fn chip(
        trigger: ChipTrigger,
        value: impl Into<String>,
        display_text: impl Into<String>,
    ) -> Self {
        Self::Chip {
            trigger,
            value: value.into(),
            display_text: display_text.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ComposerDraft {
    pub(crate) text: String,
    pub(crate) agent_id: Option<String>,
    pub(crate) command_ids: Vec<String>,
    pub(crate) is_empty: bool,
}

pub(crate) fn to_draft(segments: &[Segment]) -> ComposerDraft {
    let mut plain = String::new();
    let mut agent_id = None;
    let mut command_ids = Vec::new();
    let mut is_empty = true;
    for segment in segments {
        match segment {
            Segment::Text(text) => {
                plain.push_str(text);
                if !trim_ecmascript(text).is_empty() {
                    is_empty = false;
                }
            }
            Segment::Chip {
                trigger,
                value,
                display_text,
            } => {
                is_empty = false;
                plain.push(trigger.marker());
                plain.push_str(display_text);
                match trigger {
                    ChipTrigger::Agent => agent_id = Some(value.clone()),
                    ChipTrigger::Command => command_ids.push(value.clone()),
                }
            }
        }
    }
    ComposerDraft {
        text: trim_ecmascript(&plain).to_owned(),
        agent_id,
        command_ids,
        is_empty,
    }
}

pub(crate) fn enforce_single_agent(segments: &[Segment]) -> Cow<'_, [Segment]> {
    let agent_count = segments
        .iter()
        .filter(|segment| {
            matches!(
                segment,
                Segment::Chip {
                    trigger: ChipTrigger::Agent,
                    ..
                }
            )
        })
        .count();
    if agent_count <= 1 {
        return Cow::Borrowed(segments);
    }
    let mut remaining = agent_count;
    let kept = segments
        .iter()
        .filter(|segment| {
            if matches!(
                segment,
                Segment::Chip {
                    trigger: ChipTrigger::Agent,
                    ..
                }
            ) {
                remaining -= 1;
                remaining == 0
            } else {
                true
            }
        })
        .cloned()
        .collect();
    Cow::Owned(merge_adjacent_text(kept))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CommandKind {
    #[default]
    Chip,
    Prompt,
    Action,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommandOption {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) kind: CommandKind,
    pub(crate) prompt: Option<String>,
    pub(crate) action_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommandAction {
    pub(crate) id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AppliedCommands<'a> {
    pub(crate) segments: Cow<'a, [Segment]>,
    pub(crate) actions: Vec<CommandAction>,
}

pub(crate) fn apply_command_chips<'a>(
    segments: &'a [Segment],
    commands: &[CommandOption],
) -> AppliedCommands<'a> {
    let mut actions = Vec::new();
    let mut changed = false;
    let mut rewritten = Vec::with_capacity(segments.len());
    for segment in segments {
        let Segment::Chip {
            trigger: ChipTrigger::Command,
            value,
            ..
        } = segment
        else {
            rewritten.push(segment.clone());
            continue;
        };
        let command = commands.iter().find(|command| command.id == *value);
        match command.map_or(CommandKind::Chip, |command| command.kind) {
            CommandKind::Chip => rewritten.push(segment.clone()),
            CommandKind::Prompt => {
                changed = true;
                if let Some(prompt) = command
                    .and_then(|command| command.prompt.as_deref())
                    .filter(|prompt| !prompt.is_empty())
                {
                    rewritten.push(Segment::text(prompt));
                }
            }
            CommandKind::Action => {
                changed = true;
                if let Some(id) = command.and_then(|command| command.action_id.clone()) {
                    actions.push(CommandAction { id });
                }
            }
        }
    }
    AppliedCommands {
        segments: if changed {
            Cow::Owned(merge_adjacent_text(rewritten))
        } else {
            Cow::Borrowed(segments)
        },
        actions,
    }
}

pub(crate) fn dispatch_actions(
    actions: &[CommandAction],
    mut dispatch: impl FnMut(&CommandAction),
) {
    for action in actions {
        dispatch(action);
    }
}

fn merge_adjacent_text(segments: Vec<Segment>) -> Vec<Segment> {
    let mut merged = Vec::with_capacity(segments.len());
    for segment in segments {
        match (merged.last_mut(), segment) {
            (Some(Segment::Text(previous)), Segment::Text(next)) => previous.push_str(&next),
            (_, segment) => merged.push(segment),
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: &str, name: &str) -> Segment {
        Segment::chip(ChipTrigger::Agent, id, name)
    }

    fn command(id: &str, name: &str) -> Segment {
        Segment::chip(ChipTrigger::Command, id, name)
    }

    fn option(id: &str, kind: CommandKind) -> CommandOption {
        CommandOption {
            id: id.to_owned(),
            name: id.to_owned(),
            description: None,
            kind,
            prompt: None,
            action_id: None,
        }
    }

    #[test]
    fn flattens_chips_back_into_the_plain_text_sent_to_the_runt() {
        let draft = to_draft(&[
            agent("knowledge", "Knowledge"),
            Segment::text(" what changed last week?"),
        ]);
        assert_eq!(draft.text, "@Knowledge what changed last week?");
        assert_eq!(draft.agent_id.as_deref(), Some("knowledge"));
        assert!(!draft.is_empty);
    }

    #[test]
    fn reports_no_agent_when_the_message_does_not_address_one() {
        assert_eq!(to_draft(&[Segment::text("hello")]).agent_id, None);
    }

    #[test]
    fn collects_command_chips_in_the_order_they_were_typed() {
        assert_eq!(
            to_draft(&[
                command("search", "search"),
                Segment::text(" "),
                command("summarize", "summarize"),
            ])
            .command_ids,
            ["search", "summarize"]
        );
    }

    #[test]
    fn treats_whitespace_only_content_as_empty() {
        assert!(to_draft(&[Segment::text("   ")]).is_empty);
        assert!(to_draft(&[]).is_empty);
    }

    #[test]
    fn keeps_the_most_recent_mention_when_a_second_agent_is_add() {
        let segments = [
            agent("knowledge", "Knowledge"),
            Segment::text(" and "),
            agent("computer", "Computer"),
            Segment::text(" check this"),
        ];
        let result = enforce_single_agent(&segments);
        assert_eq!(to_draft(&result).agent_id.as_deref(), Some("computer"));
        assert_eq!(to_draft(&result).text, "and @Computer check this");
    }

    #[test]
    fn returns_the_same_array_when_there_is_nothing_to_collapse() {
        let segments = [agent("knowledge", "Knowledge"), Segment::text(" hi")];
        assert!(matches!(enforce_single_agent(&segments), Cow::Borrowed(_)));
    }

    #[test]
    fn expands_a_prompt_command_into_editable_text() {
        let mut summarize = option("summarize", CommandKind::Prompt);
        summarize.prompt = Some("Summarize this channel.".to_owned());
        let segments = [command("summarize", "summarize")];
        let result = apply_command_chips(&segments, &[summarize]);
        assert_eq!(to_draft(&result.segments).text, "Summarize this channel.");
        assert!(to_draft(&result.segments).command_ids.is_empty());
        assert!(result.actions.is_empty());
    }

    #[test]
    fn removes_an_action_command_and_defers_its_side_effect() {
        let mut clear = option("clear", CommandKind::Action);
        clear.action_id = Some("clear".to_owned());
        let segments = [command("clear", "clear")];
        let result = apply_command_chips(&segments, &[clear]);
        assert!(to_draft(&result.segments).is_empty);
        assert_eq!(
            result.actions,
            [CommandAction {
                id: "clear".to_owned()
            }]
        );
        let mut ran = false;
        assert!(!ran);
        dispatch_actions(&result.actions, |action| ran = action.id == "clear");
        assert!(ran);
    }

    #[test]
    fn leaves_chip_commands_alone_and_returns_the_same_array() {
        let segments = [command("search", "search"), Segment::text(" invoices")];
        let result = apply_command_chips(&segments, &[option("search", CommandKind::Chip)]);
        assert!(matches!(result.segments, Cow::Borrowed(_)));
        assert!(result.actions.is_empty());
    }

    #[test]
    fn keeps_a_chip_for_a_command_that_is_no_longer_registered() {
        assert_eq!(
            to_draft(&apply_command_chips(&[command("search", "search")], &[]).segments)
                .command_ids,
            ["search"]
        );
    }
}
