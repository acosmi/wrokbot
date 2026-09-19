//! Channel destination route slices.

pub mod composer;
pub mod conversation;
pub mod detail;
pub(crate) mod markdown;
pub mod new;
pub mod recipient_field;

pub use conversation::ChannelConversation;
pub use detail::ChannelDetailPage;
pub use new::ChannelNewPage;
pub use recipient_field::RecipientField;
