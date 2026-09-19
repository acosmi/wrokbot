//! CommonMark AST parser with strict security constraints.
//!
//! Enforces GUI Design Specification §6.4:
//! - Enables TABLES, STRIKETHROUGH, and TASKLISTS.
//! - Raw HTML is NEVER evaluated or inserted as innerHTML; emitted strictly as plain text nodes.
//! - All URLs and images are validated through `SafeUrl` and `ImagePolicy`.

use super::sanitize::{ImagePolicy, SafeUrl};
use pulldown_cmark::{
    Alignment as CmarkAlignment, Event, HeadingLevel, Options, Parser, Tag, TagEnd,
};
use std::sync::Arc;

/// Source and rendering budgets are local GUI limits, not provider or runtime budget receipts.
pub const MAX_MARKDOWN_BYTES: usize = 128 * 1024;
/// Maximum nested parser containers accepted by the recursive view renderer.
pub const MAX_MARKDOWN_DEPTH: usize = 64;
/// Maximum CommonMark events in one document.
pub const MAX_MARKDOWN_EVENTS: usize = 16_384;

/// Why a document is shown as an explicit bounded plain-text preview.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkdownLimit {
    Bytes,
    Depth,
    Events,
}

pub(super) struct ParsedMarkdown {
    pub blocks: Vec<Arc<MarkdownBlock>>,
    pub starts: Vec<usize>,
    pub event_starts: Vec<usize>,
    pub event_count: usize,
    pub needs_full_context: bool,
}

/// Alignment of table columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableAlignment {
    /// No explicit alignment.
    None,
    /// Left aligned.
    Left,
    /// Center aligned.
    Center,
    /// Right aligned.
    Right,
}

impl From<CmarkAlignment> for TableAlignment {
    fn from(value: CmarkAlignment) -> Self {
        match value {
            CmarkAlignment::None => Self::None,
            CmarkAlignment::Left => Self::Left,
            CmarkAlignment::Center => Self::Center,
            CmarkAlignment::Right => Self::Right,
        }
    }
}

/// A cell in a table row or header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableCell {
    /// Cell inline content.
    pub children: Vec<MarkdownInline>,
}

/// An item in an ordered or unordered list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListItem {
    /// Tasklist status if this item is a task checkbox: `Some(true)` for checked, `Some(false)` for unchecked.
    pub task: Option<bool>,
    /// Nested block content of this list item.
    pub children: Vec<MarkdownBlock>,
}

/// Block-level Markdown element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarkdownBlock {
    /// Paragraph of text and inline elements.
    Paragraph(Vec<MarkdownInline>),
    /// Section heading with level 1 through 6.
    Heading {
        /// Heading level (1..=6).
        level: u8,
        /// Heading children.
        children: Vec<MarkdownInline>,
    },
    /// Blockquote containing nested blocks.
    BlockQuote(Vec<MarkdownBlock>),
    /// Fenced or indented code block.
    CodeBlock {
        /// Specified language name or fence token.
        lang: String,
        /// Raw code content.
        code: String,
    },
    /// Ordered or unordered list.
    List {
        /// True if ordered list, false if bulleted.
        ordered: bool,
        /// Starting number for ordered lists.
        start: Option<u64>,
        /// List items.
        items: Vec<ListItem>,
    },
    /// Table with column alignments, headers, and rows.
    Table {
        /// Column alignments.
        alignments: Vec<TableAlignment>,
        /// Header row cells.
        headers: Vec<TableCell>,
        /// Body rows.
        rows: Vec<Vec<TableCell>>,
    },
    /// Thematic break / horizontal rule.
    Rule,
    /// Raw HTML block rendered strictly as inert text.
    HtmlRaw(String),
    /// Explicit safe preview when source or rendering complexity exceeds the GUI budget.
    Limited {
        /// Prefix ending at a UTF-8 character boundary; never executable markup.
        preview: String,
        /// Original source byte count.
        source_bytes: usize,
        /// Stable local limit category.
        reason: MarkdownLimit,
    },
}

/// Inline Markdown element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarkdownInline {
    /// Plain text span.
    Text(String),
    /// Italic / emphasis span.
    Emphasis(Vec<MarkdownInline>),
    /// Bold / strong span.
    Strong(Vec<MarkdownInline>),
    /// Strikethrough span.
    Strikethrough(Vec<MarkdownInline>),
    /// Inline code literal.
    Code(String),
    /// Hyperlink with sanitized destination.
    Link {
        /// Sanitized destination URL.
        url: SafeUrl,
        /// Optional title attribute.
        title: Option<String>,
        /// Link anchor children.
        children: Vec<MarkdownInline>,
    },
    /// Image classified according to the zero-network remote image policy.
    Image(ImagePolicy),
    /// Explicit line break.
    LineBreak,
    /// Raw inline HTML rendered strictly as inert text.
    HtmlRaw(String),
}

/// Parser converting CommonMark text into a strongly typed AST.
pub fn parse_markdown(input: &str) -> Vec<MarkdownBlock> {
    parse_document(input)
        .blocks
        .into_iter()
        .map(Arc::unwrap_or_clone)
        .collect()
}

pub(super) fn limited_document(input: &str, reason: MarkdownLimit) -> ParsedMarkdown {
    let mut end = input.len().min(8 * 1024);
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    ParsedMarkdown {
        blocks: vec![Arc::new(MarkdownBlock::Limited {
            preview: input[..end].to_owned(),
            source_bytes: input.len(),
            reason,
        })],
        starts: vec![0],
        event_starts: vec![0],
        event_count: 0,
        needs_full_context: true,
    }
}

pub(super) fn parse_document(input: &str) -> ParsedMarkdown {
    if input.len() > MAX_MARKDOWN_BYTES {
        return limited_document(input, MarkdownLimit::Bytes);
    }
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(input, options);
    let mut needs_full_context = parser.reference_definitions().iter().next().is_some();
    let mut blocks = Vec::new();
    let mut block_stack: Vec<BlockBuilder> = Vec::new();
    let mut starts = Vec::new();
    let mut event_starts = Vec::new();
    let mut event_count = 0;
    let mut block_start = 0;
    let mut block_event_start = 0;

    for (event, range) in parser.into_offset_iter() {
        if block_stack.is_empty() {
            block_start = input[..range.start]
                .rfind('\n')
                .map_or(0, |offset| offset + 1);
            block_event_start = event_count;
        }
        event_count += 1;
        if event_count > MAX_MARKDOWN_EVENTS {
            return limited_document(input, MarkdownLimit::Events);
        }
        let previous_count = blocks.len();
        match event {
            Event::Start(tag) => match tag {
                Tag::Paragraph => {
                    block_stack.push(BlockBuilder::Paragraph(Vec::new()));
                }
                Tag::Heading { level, .. } => {
                    let lvl = match level {
                        HeadingLevel::H1 => 1,
                        HeadingLevel::H2 => 2,
                        HeadingLevel::H3 => 3,
                        HeadingLevel::H4 => 4,
                        HeadingLevel::H5 => 5,
                        HeadingLevel::H6 => 6,
                    };
                    block_stack.push(BlockBuilder::Heading {
                        level: lvl,
                        children: Vec::new(),
                    });
                }
                Tag::BlockQuote(_) => {
                    block_stack.push(BlockBuilder::BlockQuote(Vec::new()));
                }
                Tag::CodeBlock(kind) => {
                    let lang = match kind {
                        pulldown_cmark::CodeBlockKind::Fenced(l) => l.to_string(),
                        pulldown_cmark::CodeBlockKind::Indented => String::new(),
                    };
                    block_stack.push(BlockBuilder::CodeBlock {
                        lang,
                        code: String::new(),
                    });
                }
                Tag::List(first_num) => {
                    block_stack.push(BlockBuilder::List {
                        ordered: first_num.is_some(),
                        start: first_num,
                        items: Vec::new(),
                    });
                }
                Tag::Item => {
                    block_stack.push(BlockBuilder::ListItem {
                        task: None,
                        children: Vec::new(),
                    });
                }
                Tag::Table(aligns) => {
                    block_stack.push(BlockBuilder::Table {
                        alignments: aligns.into_iter().map(TableAlignment::from).collect(),
                        headers: Vec::new(),
                        rows: Vec::new(),
                    });
                }
                Tag::TableHead => {
                    block_stack.push(BlockBuilder::TableHead(Vec::new()));
                }
                Tag::TableRow => {
                    block_stack.push(BlockBuilder::TableRow(Vec::new()));
                }
                Tag::TableCell => {
                    block_stack.push(BlockBuilder::TableCell(Vec::new()));
                }
                Tag::Emphasis => {
                    push_inline_container(&mut block_stack, InlineContainer::Emphasis(Vec::new()));
                }
                Tag::Strong => {
                    push_inline_container(&mut block_stack, InlineContainer::Strong(Vec::new()));
                }
                Tag::Strikethrough => {
                    push_inline_container(
                        &mut block_stack,
                        InlineContainer::Strikethrough(Vec::new()),
                    );
                }
                Tag::Link {
                    dest_url, title, ..
                } => {
                    let safe = SafeUrl::parse(&dest_url);
                    let title_opt = if title.is_empty() {
                        None
                    } else {
                        Some(title.to_string())
                    };
                    push_inline_container(
                        &mut block_stack,
                        InlineContainer::Link {
                            url: safe,
                            title: title_opt,
                            children: Vec::new(),
                        },
                    );
                }
                Tag::Image {
                    dest_url, title, ..
                } => {
                    let title_opt = if title.is_empty() {
                        None
                    } else {
                        Some(title.to_string())
                    };
                    push_inline_container(
                        &mut block_stack,
                        InlineContainer::Image {
                            src: dest_url.to_string(),
                            title: title_opt,
                            alt: String::new(),
                        },
                    );
                }
                _ => {}
            },
            Event::End(tag_end) => match tag_end {
                TagEnd::Paragraph => {
                    if let Some(BlockBuilder::Paragraph(inlines)) = block_stack.pop() {
                        commit_block(
                            &mut block_stack,
                            &mut blocks,
                            MarkdownBlock::Paragraph(inlines),
                        );
                    }
                }
                TagEnd::Heading(_) => {
                    if let Some(BlockBuilder::Heading { level, children }) = block_stack.pop() {
                        commit_block(
                            &mut block_stack,
                            &mut blocks,
                            MarkdownBlock::Heading { level, children },
                        );
                    }
                }
                TagEnd::BlockQuote(_) => {
                    if let Some(BlockBuilder::BlockQuote(children)) = block_stack.pop() {
                        commit_block(
                            &mut block_stack,
                            &mut blocks,
                            MarkdownBlock::BlockQuote(children),
                        );
                    }
                }
                TagEnd::CodeBlock => {
                    if let Some(BlockBuilder::CodeBlock { lang, code }) = block_stack.pop() {
                        commit_block(
                            &mut block_stack,
                            &mut blocks,
                            MarkdownBlock::CodeBlock { lang, code },
                        );
                    }
                }
                TagEnd::List(_) => {
                    if let Some(BlockBuilder::List {
                        ordered,
                        start,
                        items,
                    }) = block_stack.pop()
                    {
                        commit_block(
                            &mut block_stack,
                            &mut blocks,
                            MarkdownBlock::List {
                                ordered,
                                start,
                                items,
                            },
                        );
                    }
                }
                TagEnd::Item => {
                    let popped = block_stack.pop();
                    if let (
                        Some(BlockBuilder::ListItem { task, children }),
                        Some(BlockBuilder::List { items, .. }),
                    ) = (popped, block_stack.last_mut())
                    {
                        items.push(ListItem { task, children });
                    }
                }
                TagEnd::Table => {
                    if let Some(BlockBuilder::Table {
                        alignments,
                        headers,
                        rows,
                    }) = block_stack.pop()
                    {
                        commit_block(
                            &mut block_stack,
                            &mut blocks,
                            MarkdownBlock::Table {
                                alignments,
                                headers,
                                rows,
                            },
                        );
                    }
                }
                TagEnd::TableHead => {
                    let popped = block_stack.pop();
                    if let (
                        Some(BlockBuilder::TableHead(cells)),
                        Some(BlockBuilder::Table { headers, .. }),
                    ) = (popped, block_stack.last_mut())
                    {
                        *headers = cells;
                    }
                }
                TagEnd::TableRow => {
                    let popped = block_stack.pop();
                    if let (
                        Some(BlockBuilder::TableRow(cells)),
                        Some(BlockBuilder::Table { rows, .. }),
                    ) = (popped, block_stack.last_mut())
                    {
                        rows.push(cells);
                    }
                }
                TagEnd::TableCell => {
                    if let Some(BlockBuilder::TableCell(inlines)) = block_stack.pop() {
                        match block_stack.last_mut() {
                            Some(BlockBuilder::TableHead(cells)) => {
                                cells.push(TableCell { children: inlines });
                            }
                            Some(BlockBuilder::TableRow(cells)) => {
                                cells.push(TableCell { children: inlines });
                            }
                            _ => {}
                        }
                    }
                }
                TagEnd::Emphasis => {
                    pop_inline_container(&mut block_stack, |children| {
                        MarkdownInline::Emphasis(children)
                    });
                }
                TagEnd::Strong => {
                    pop_inline_container(&mut block_stack, |children| {
                        MarkdownInline::Strong(children)
                    });
                }
                TagEnd::Strikethrough => {
                    pop_inline_container(&mut block_stack, |children| {
                        MarkdownInline::Strikethrough(children)
                    });
                }
                TagEnd::Link => {
                    pop_link_container(&mut block_stack);
                }
                TagEnd::Image => {
                    pop_image_container(&mut block_stack);
                }
                _ => {}
            },
            Event::Text(t) => {
                if t.contains('[')
                    && !matches!(block_stack.last(), Some(BlockBuilder::CodeBlock { .. }))
                {
                    needs_full_context = true;
                }
                push_text(&mut block_stack, t.as_ref());
            }
            Event::Code(c) => {
                push_inline(&mut block_stack, MarkdownInline::Code(c.into_string()));
            }
            Event::Html(h) => {
                needs_full_context = true;
                // Strictly treat raw HTML as plain inert text!
                if block_stack.is_empty() {
                    blocks.push(MarkdownBlock::HtmlRaw(h.into_string()));
                } else {
                    push_inline(&mut block_stack, MarkdownInline::HtmlRaw(h.into_string()));
                }
            }
            Event::InlineHtml(h) => {
                // Strictly treat inline HTML as plain inert text!
                push_inline(&mut block_stack, MarkdownInline::HtmlRaw(h.into_string()));
            }
            Event::SoftBreak => {
                push_text(&mut block_stack, " ");
            }
            Event::HardBreak => {
                push_inline(&mut block_stack, MarkdownInline::LineBreak);
            }
            Event::Rule => {
                commit_block(&mut block_stack, &mut blocks, MarkdownBlock::Rule);
            }
            Event::TaskListMarker(checked) => {
                if let Some(BlockBuilder::ListItem { task, .. }) = block_stack.last_mut() {
                    *task = Some(checked);
                }
            }
            _ => {}
        }
        if block_stack.len() > MAX_MARKDOWN_DEPTH {
            return limited_document(input, MarkdownLimit::Depth);
        }
        for _ in previous_count..blocks.len() {
            starts.push(block_start);
            event_starts.push(block_event_start);
        }
    }

    // Flush any unclosed blocks caused by incomplete streaming input.
    while let Some(top) = block_stack.pop() {
        match top {
            BlockBuilder::Paragraph(inlines) => {
                if !inlines.is_empty() {
                    blocks.push(MarkdownBlock::Paragraph(inlines));
                }
            }
            BlockBuilder::Heading { level, children } => {
                blocks.push(MarkdownBlock::Heading { level, children });
            }
            BlockBuilder::BlockQuote(children) => {
                blocks.push(MarkdownBlock::BlockQuote(children));
            }
            BlockBuilder::CodeBlock { lang, code } => {
                blocks.push(MarkdownBlock::CodeBlock { lang, code });
            }
            BlockBuilder::List {
                ordered,
                start,
                items,
            } => {
                blocks.push(MarkdownBlock::List {
                    ordered,
                    start,
                    items,
                });
            }
            BlockBuilder::Table {
                alignments,
                headers,
                rows,
            } => {
                blocks.push(MarkdownBlock::Table {
                    alignments,
                    headers,
                    rows,
                });
            }
            _ => {}
        }
    }

    starts.resize(blocks.len(), block_start);
    event_starts.resize(blocks.len(), block_event_start);
    if starts.windows(2).any(|pair| pair[0] >= pair[1]) {
        needs_full_context = true;
    }
    ParsedMarkdown {
        blocks: blocks.into_iter().map(Arc::new).collect(),
        starts,
        event_starts,
        event_count,
        needs_full_context,
    }
}

#[derive(Debug)]
enum BlockBuilder {
    Paragraph(Vec<MarkdownInline>),
    Heading {
        level: u8,
        children: Vec<MarkdownInline>,
    },
    BlockQuote(Vec<MarkdownBlock>),
    CodeBlock {
        lang: String,
        code: String,
    },
    List {
        ordered: bool,
        start: Option<u64>,
        items: Vec<ListItem>,
    },
    ListItem {
        task: Option<bool>,
        children: Vec<MarkdownBlock>,
    },
    Table {
        alignments: Vec<TableAlignment>,
        headers: Vec<TableCell>,
        rows: Vec<Vec<TableCell>>,
    },
    TableHead(Vec<TableCell>),
    TableRow(Vec<TableCell>),
    TableCell(Vec<MarkdownInline>),
    Inline(InlineContainer),
}

#[derive(Debug)]
enum InlineContainer {
    Emphasis(Vec<MarkdownInline>),
    Strong(Vec<MarkdownInline>),
    Strikethrough(Vec<MarkdownInline>),
    Link {
        url: SafeUrl,
        title: Option<String>,
        children: Vec<MarkdownInline>,
    },
    Image {
        src: String,
        title: Option<String>,
        alt: String,
    },
}

fn commit_block(
    stack: &mut [BlockBuilder],
    root_blocks: &mut Vec<MarkdownBlock>,
    block: MarkdownBlock,
) {
    if let Some(top) = stack.last_mut() {
        match top {
            BlockBuilder::BlockQuote(children) => children.push(block),
            BlockBuilder::ListItem { children, .. } => children.push(block),
            _ => root_blocks.push(block),
        }
    } else {
        root_blocks.push(block);
    }
}

fn push_inline(stack: &mut [BlockBuilder], inline: MarkdownInline) {
    if let Some(top) = stack.last_mut() {
        match top {
            BlockBuilder::Paragraph(inlines) => inlines.push(inline),
            BlockBuilder::Heading { children, .. } => children.push(inline),
            BlockBuilder::TableCell(inlines) => inlines.push(inline),
            BlockBuilder::Inline(container) => match container {
                InlineContainer::Emphasis(children)
                | InlineContainer::Strong(children)
                | InlineContainer::Strikethrough(children)
                | InlineContainer::Link { children, .. } => children.push(inline),
                InlineContainer::Image { alt, .. } => {
                    // Collect plain text alt for images.
                    if let MarkdownInline::Text(t) = inline {
                        alt.push_str(&t);
                    }
                }
            },
            BlockBuilder::ListItem { children, .. } => {
                // If text arrives directly in a list item without paragraph, wrap in paragraph.
                if let Some(MarkdownBlock::Paragraph(inlines)) = children.last_mut() {
                    inlines.push(inline);
                } else {
                    children.push(MarkdownBlock::Paragraph(vec![inline]));
                }
            }
            _ => {}
        }
    }
}

fn push_text(stack: &mut [BlockBuilder], text: &str) {
    if let Some(top) = stack.last_mut() {
        match top {
            BlockBuilder::CodeBlock { code, .. } => {
                code.push_str(text);
                return;
            }
            BlockBuilder::Inline(InlineContainer::Image { alt, .. }) => {
                alt.push_str(text);
                return;
            }
            _ => {}
        }
    }

    push_inline(stack, MarkdownInline::Text(text.to_owned()));
}

fn push_inline_container(stack: &mut Vec<BlockBuilder>, container: InlineContainer) {
    stack.push(BlockBuilder::Inline(container));
}

fn pop_inline_container<F>(stack: &mut Vec<BlockBuilder>, wrap: F)
where
    F: FnOnce(Vec<MarkdownInline>) -> MarkdownInline,
{
    if let Some(BlockBuilder::Inline(container)) = stack.pop() {
        let children = match container {
            InlineContainer::Emphasis(c)
            | InlineContainer::Strong(c)
            | InlineContainer::Strikethrough(c) => c,
            _ => Vec::new(),
        };
        push_inline(stack, wrap(children));
    }
}

fn pop_link_container(stack: &mut Vec<BlockBuilder>) {
    if let Some(BlockBuilder::Inline(InlineContainer::Link {
        url,
        title,
        children,
    })) = stack.pop()
    {
        push_inline(
            stack,
            MarkdownInline::Link {
                url,
                title,
                children,
            },
        );
    }
}

fn pop_image_container(stack: &mut Vec<BlockBuilder>) {
    if let Some(BlockBuilder::Inline(InlineContainer::Image { src, title, alt })) = stack.pop() {
        let policy = ImagePolicy::classify(&src, &alt, title.as_deref());
        push_inline(stack, MarkdownInline::Image(policy));
    }
}
