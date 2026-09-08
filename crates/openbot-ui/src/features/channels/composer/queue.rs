//! Transient in-mount queue reduction for messages typed during one active turn.

#![cfg_attr(not(test), allow(dead_code))]

use std::borrow::Cow;

use super::draft::ComposerDraft;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QueuedMessage {
    pub(crate) id: String,
    pub(crate) text: String,
    pub(crate) command_ids: Vec<String>,
}

pub(crate) enum QueueAction<'a> {
    Submit {
        id: &'a str,
        draft: &'a ComposerDraft,
        busy: bool,
    },
    Settle,
    Remove {
        id: &'a str,
    },
}

pub(crate) struct QueueTransition<'a> {
    pub(crate) queue: Cow<'a, [QueuedMessage]>,
    pub(crate) run: Option<Cow<'a, ComposerDraft>>,
}

pub(crate) fn reduce_queue<'a>(
    queue: &'a [QueuedMessage],
    action: QueueAction<'a>,
) -> QueueTransition<'a> {
    match action {
        QueueAction::Submit { id, draft, busy } if !busy => {
            if queue.is_empty() {
                QueueTransition {
                    queue: Cow::Borrowed(queue),
                    run: Some(Cow::Borrowed(draft)),
                }
            } else {
                let mut joined = queue.to_vec();
                joined.push(QueuedMessage {
                    id: id.to_owned(),
                    text: draft.text.clone(),
                    command_ids: draft.command_ids.clone(),
                });
                QueueTransition {
                    queue: Cow::Owned(Vec::new()),
                    run: Some(Cow::Owned(join_queued(&joined))),
                }
            }
        }
        QueueAction::Submit { id, draft, .. } => {
            let mut queued = queue.to_vec();
            queued.push(QueuedMessage {
                id: id.to_owned(),
                text: draft.text.clone(),
                command_ids: draft.command_ids.clone(),
            });
            QueueTransition {
                queue: Cow::Owned(queued),
                run: None,
            }
        }
        QueueAction::Settle if queue.is_empty() => QueueTransition {
            queue: Cow::Borrowed(queue),
            run: None,
        },
        QueueAction::Settle => QueueTransition {
            queue: Cow::Owned(Vec::new()),
            run: Some(Cow::Owned(join_queued(queue))),
        },
        QueueAction::Remove { id } => {
            let kept = queue
                .iter()
                .filter(|message| message.id != id)
                .cloned()
                .collect::<Vec<_>>();
            QueueTransition {
                queue: if kept.len() == queue.len() {
                    Cow::Borrowed(queue)
                } else {
                    Cow::Owned(kept)
                },
                run: None,
            }
        }
    }
}

fn join_queued(queue: &[QueuedMessage]) -> ComposerDraft {
    let mut command_ids = Vec::new();
    for id in queue.iter().flat_map(|message| &message.command_ids) {
        if !command_ids.contains(id) {
            command_ids.push(id.clone());
        }
    }
    ComposerDraft {
        text: queue
            .iter()
            .map(|message| message.text.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        agent_id: None,
        command_ids,
        is_empty: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(text: &str, command_ids: &[&str]) -> ComposerDraft {
        ComposerDraft {
            text: text.to_owned(),
            agent_id: None,
            command_ids: command_ids.iter().map(|id| (*id).to_owned()).collect(),
            is_empty: false,
        }
    }

    fn park(
        queue: &[QueuedMessage],
        id: &str,
        text: &str,
        command_ids: &[&str],
    ) -> Vec<QueuedMessage> {
        let message = draft(text, command_ids);
        reduce_queue(
            queue,
            QueueAction::Submit {
                id,
                draft: &message,
                busy: true,
            },
        )
        .queue
        .into_owned()
    }

    #[test]
    fn an_idle_send_goes_straight_out_and_queues_nothing() {
        let sent = draft("open the invoices page", &[]);
        let result = reduce_queue(
            &[],
            QueueAction::Submit {
                id: "one",
                draft: &sent,
                busy: false,
            },
        );
        assert!(matches!(result.run, Some(Cow::Borrowed(_))));
        assert!(result.queue.is_empty());
    }

    #[test]
    fn an_idle_send_takes_anything_already_waiting_with_it() {
        let waiting = park(&[], "one", "no, the other one", &[]);
        let current = draft("the Q3 file", &[]);
        let result = reduce_queue(
            &waiting,
            QueueAction::Submit {
                id: "two",
                draft: &current,
                busy: false,
            },
        );
        assert_eq!(result.run.unwrap().text, "no, the other one\nthe Q3 file");
        assert!(result.queue.is_empty());
    }

    #[test]
    fn an_idle_send_that_empties_a_queue_carries_its_skills_too() {
        let waiting = park(&[], "one", "/search invoices", &["search"]);
        let current = draft("/summarize it", &["summarize"]);
        let result = reduce_queue(
            &waiting,
            QueueAction::Submit {
                id: "two",
                draft: &current,
                busy: false,
            },
        );
        assert_eq!(result.run.unwrap().command_ids, ["search", "summarize"]);
    }

    #[test]
    fn a_send_while_the_bot_is_working_waits_instead_of_running() {
        let message = draft("no, the other one", &[]);
        let result = reduce_queue(
            &[],
            QueueAction::Submit {
                id: "one",
                draft: &message,
                busy: true,
            },
        );
        assert!(result.run.is_none());
        assert_eq!(
            result.queue.as_ref(),
            [QueuedMessage {
                id: "one".to_owned(),
                text: "no, the other one".to_owned(),
                command_ids: Vec::new(),
            }]
        );
    }

    #[test]
    fn keeps_the_order_they_were_typed_in() {
        let mut queue = park(&[], "one", "first", &[]);
        queue = park(&queue, "two", "second", &[]);
        queue = park(&queue, "three", "third", &[]);
        assert_eq!(
            queue
                .iter()
                .map(|message| message.text.as_str())
                .collect::<Vec<_>>(),
            ["first", "second", "third"]
        );
    }

    #[test]
    fn a_burst_of_corrections_costs_one_turn_not_three() {
        let mut queue = park(&[], "one", "no, the other one", &[]);
        queue = park(&queue, "two", "the Q3 file", &[]);
        queue = park(&queue, "three", "and skip the summary", &[]);
        let result = reduce_queue(&queue, QueueAction::Settle);
        assert_eq!(
            result.run.unwrap().text,
            "no, the other one\nthe Q3 file\nand skip the summary"
        );
        assert!(result.queue.is_empty());
    }

    #[test]
    fn stopping_the_bot_is_what_makes_the_correction_run() {
        let queue = park(&[], "one", "stop reading, just summarise it", &[]);
        let result = reduce_queue(&queue, QueueAction::Settle);
        assert_eq!(result.run.unwrap().text, "stop reading, just summarise it");
        assert!(result.queue.is_empty());
    }

    #[test]
    fn a_turn_ending_with_nothing_waiting_starts_nothing() {
        let result = reduce_queue(&[], QueueAction::Settle);
        assert!(result.run.is_none());
        assert!(result.queue.is_empty());
    }

    #[test]
    fn the_drained_turn_is_addressed_to_nobody_in_particular() {
        let queue = park(&[], "one", "@Knowledge check that again", &[]);
        assert_eq!(
            reduce_queue(&queue, QueueAction::Settle)
                .run
                .unwrap()
                .agent_id,
            None
        );
    }

    #[test]
    fn carries_the_skills_that_were_invoked_once_each() {
        let mut queue = park(&[], "one", "/search invoices", &["search"]);
        queue = park(&queue, "two", "/search receipts too", &["search"]);
        queue = park(&queue, "three", "/summarize it", &["summarize"]);
        assert_eq!(
            reduce_queue(&queue, QueueAction::Settle)
                .run
                .unwrap()
                .command_ids,
            ["search", "summarize"]
        );
    }

    #[test]
    fn draining_twice_does_not_resend_what_has_already_gone() {
        let queue = park(&[], "one", "no, the other one", &[]);
        let drained = reduce_queue(&queue, QueueAction::Settle);
        assert!(
            reduce_queue(&drained.queue, QueueAction::Settle)
                .run
                .is_none()
        );
    }

    #[test]
    fn takes_a_message_back_before_it_runs() {
        let mut queue = park(&[], "one", "no, the other one", &[]);
        queue = park(&queue, "two", "actually never mind", &[]);
        let result = reduce_queue(&queue, QueueAction::Remove { id: "two" });
        assert_eq!(
            result
                .queue
                .iter()
                .map(|message| message.text.as_str())
                .collect::<Vec<_>>(),
            ["no, the other one"]
        );
        assert!(result.run.is_none());
    }

    #[test]
    fn what_is_left_is_what_still_runs_on_settle() {
        let mut queue = park(&[], "one", "keep this", &[]);
        queue = park(&queue, "two", "drop this", &[]);
        let left = reduce_queue(&queue, QueueAction::Remove { id: "two" });
        assert_eq!(
            reduce_queue(&left.queue, QueueAction::Settle)
                .run
                .unwrap()
                .text,
            "keep this"
        );
    }

    #[test]
    fn removing_the_last_one_leaves_nothing_to_run() {
        let queue = park(&[], "one", "second thoughts", &[]);
        let left = reduce_queue(&queue, QueueAction::Remove { id: "one" });
        assert!(left.queue.is_empty());
        assert!(reduce_queue(&left.queue, QueueAction::Settle).run.is_none());
    }

    #[test]
    fn an_id_that_is_not_in_the_queue_changes_nothing_at_all() {
        let queue = park(&[], "one", "no, the other one", &[]);
        assert!(matches!(
            reduce_queue(&queue, QueueAction::Remove { id: "elsewhere" }).queue,
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn two_identical_corrections_are_two_entries_and_only_one_i() {
        let mut queue = park(&[], "one", "no, the other one", &[]);
        queue = park(&queue, "two", "no, the other one", &[]);
        assert_eq!(
            reduce_queue(&queue, QueueAction::Remove { id: "one" })
                .queue
                .as_ref(),
            [QueuedMessage {
                id: "two".to_owned(),
                text: "no, the other one".to_owned(),
                command_ids: Vec::new(),
            }]
        );
    }
}
