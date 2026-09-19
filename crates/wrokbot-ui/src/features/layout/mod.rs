//! Configuration-page layout components shared by Web and Desktop hosts.

pub mod detail_panel;
pub mod page_shell;
pub mod row_mark;
pub mod stagger;

pub use detail_panel::{DetailPanel, DetailPanelLayout, DetailPanelMain};
pub use page_shell::{
    PageBackLink, PageEmpty, PageHeader, PageRows, PageSection, PageShell, PageTopbar, PageWidth,
};
pub use row_mark::RowMark;
pub use stagger::StaggerItem;
