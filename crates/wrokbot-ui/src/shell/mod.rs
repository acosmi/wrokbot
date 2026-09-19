//! Production application shell business composition.

pub mod admin_components;
pub mod app_sidebar;
pub mod auth;
pub mod bot;
pub mod home;
pub mod layout;

pub use admin_components::{AdminComponentDetailPage, AdminComponentsPage};
pub use app_sidebar::AppSidebar;
pub use auth::AuthenticatedBoundary;
pub use bot::BotChatPage;
pub use home::HomePage;
pub use layout::{AppLayout, RootLayout};
