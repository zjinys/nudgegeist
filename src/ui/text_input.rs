use std::ops::Range;

use gpui::{
    App, Bounds, ClipboardItem, Context, CursorStyle, ElementId, ElementInputHandler, Entity,
    EntityInputHandler, FocusHandle, Focusable, GlobalElementId, KeyBinding, LayoutId, MouseButton,
    MouseDownEvent, MouseMoveEvent, MouseUpEvent, PaintQuad, Pixels, Point, ShapedLine,
    SharedString, Style, TextRun, UTF16Selection, UnderlineStyle, Window, actions, div, fill,
    hsla, point, prelude::*, px, relative, rgba, size,
};
use unicode_segmentation::UnicodeSegmentation;

actions!(
    watchdog_input,
    [
        InputBackspace,
        InputDelete,
        InputLeft,
        InputRight,
        InputUp,
        InputDown,
        InputSelectLeft,
        InputSelectRight,
        InputSelectAll,
        InputHome,
        InputEnd,
        InputEnter,
        InputPaste,
        InputCut,
        InputCopy,
    ]
);

pub fn bind_input_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("backspace", InputBackspace, Some("WatchdogInput")),
        KeyBinding::new("delete", InputDelete, Some("WatchdogInput")),
        KeyBinding::new("left", InputLeft, Some("WatchdogInput")),
        KeyBinding::new("right", InputRight, Some("WatchdogInput")),
        KeyBinding::new("up", InputUp, Some("WatchdogInput")),
        KeyBinding::new("down", InputDown, Some("WatchdogInput")),
        KeyBinding::new("shift-left", InputSelectLeft, Some("WatchdogInput")),
        KeyBinding::new("shift-right", InputSelectRight, Some("WatchdogInput")),
        KeyBinding::new("ctrl-a", InputSelectAll, Some("WatchdogInput")),
        KeyBinding::new("cmd-a", InputSelectAll, Some("WatchdogInput")),
        KeyBinding::new("ctrl-v", InputPaste, Some("WatchdogInput")),
        KeyBinding::new("cmd-v", InputPaste, Some("WatchdogInput")),
        KeyBinding::new("ctrl-c", InputCopy, Some("WatchdogInput")),
        KeyBinding::new("cmd-c", InputCopy, Some("WatchdogInput")),
        KeyBinding::new("ctrl-x", InputCut, Some("WatchdogInput")),
        KeyBinding::new("cmd-x", InputCut, Some("WatchdogInput")),
        KeyBinding::new("home", InputHome, Some("WatchdogInput")),
        KeyBinding::new("end", InputEnd, Some("WatchdogInput")),
        KeyBinding::new("enter", InputEnter, Some("WatchdogInput")),
    ]);
}

#[derive(Clone)]
struct LineRange {
    byte_range: Range<usize>,
    shaped: ShapedLine,
}

pub struct TextInput {
    pub focus_handle: FocusHandle,
    pub content: SharedString,
    pub placeholder: SharedString,
    pub multiline: bool,
    pub monospace: bool,
    pub min_lines: usize,
    pub max_lines: usize,
    selected_range: Range<usize>,
    selection_reversed: bool,
    marked_range: Option<Range<usize>>,
    last_lines: Vec<LineRange>,
    last_bounds: Option<Bounds<Pixels>>,
    last_line_height: Pixels,
    is_selecting: bool,
}

impl TextInput {
    pub fn new(
        cx: &mut Context<Self>,
        placeholder: impl Into<SharedString>,
        initial: impl Into<SharedString>,
        multiline: bool,
    ) -> Self {
        let initial: SharedString = initial.into();
        let len = initial.len();
        Self {
            focus_handle: cx.focus_handle(),
            content: initial,
            placeholder: placeholder.into(),
            multiline,
            monospace: false,
            min_lines: if multiline { 4 } else { 1 },
            max_lines: if multiline { 14 } else { 1 },
            selected_range: len..len,
            selection_reversed: false,
            marked_range: None,
            last_lines: Vec::new(),
            last_bounds: None,
            last_line_height: px(20.),
            is_selecting: false,
        }
    }

    pub fn with_monospace(mut self, mono: bool) -> Self {
        self.monospace = mono;
        self
    }

    pub fn with_line_limits(mut self, min_lines: usize, max_lines: usize) -> Self {
        self.min_lines = min_lines.max(1);
        self.max_lines = max_lines.max(self.min_lines);
        self
    }

    pub fn text(&self) -> String {
        self.content.to_string()
    }

    pub fn set_text(&mut self, text: impl Into<String>, cx: &mut Context<Self>) {
        let s: String = text.into();
        let len = s.len();
        self.content = s.into();
        self.selected_range = len..len;
        self.selection_reversed = false;
        self.marked_range = None;
        cx.notify();
    }

    fn left(&mut self, _: &InputLeft, _: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.move_to(self.previous_boundary(self.cursor_offset()), cx);
        } else {
            self.move_to(self.selected_range.start, cx);
        }
    }

    fn right(&mut self, _: &InputRight, _: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.move_to(self.next_boundary(self.selected_range.end), cx);
        } else {
            self.move_to(self.selected_range.end, cx);
        }
    }

    fn up(&mut self, _: &InputUp, _: &mut Window, cx: &mut Context<Self>) {
        if !self.multiline {
            return;
        }
        let cur = self.cursor_offset();
        let line_ranges = self.compute_line_byte_ranges();
        let Some(cur_line_idx) = line_ranges
            .iter()
            .position(|r| cur >= r.start && cur <= r.end)
        else {
            return;
        };
        if cur_line_idx == 0 {
            self.move_to(0, cx);
        } else {
            let col = self.content[line_ranges[cur_line_idx].start..cur].chars().count();
            let prev = &line_ranges[cur_line_idx - 1];
            let target = prev.start
                + self.content[prev.clone()]
                    .char_indices()
                    .nth(col)
                    .map(|(i, _)| i)
                    .unwrap_or(prev.len());
            self.move_to(target, cx);
        }
    }

    fn down(&mut self, _: &InputDown, _: &mut Window, cx: &mut Context<Self>) {
        if !self.multiline {
            return;
        }
        let cur = self.cursor_offset();
        let line_ranges = self.compute_line_byte_ranges();
        let Some(cur_line_idx) = line_ranges
            .iter()
            .position(|r| cur >= r.start && cur <= r.end)
        else {
            return;
        };
        if cur_line_idx + 1 >= line_ranges.len() {
            self.move_to(self.content.len(), cx);
        } else {
            let col = self.content[line_ranges[cur_line_idx].start..cur].chars().count();
            let next = &line_ranges[cur_line_idx + 1];
            let target = next.start
                + self.content[next.clone()]
                    .char_indices()
                    .nth(col)
                    .map(|(i, _)| i)
                    .unwrap_or(next.len());
            self.move_to(target, cx);
        }
    }

    fn select_left(&mut self, _: &InputSelectLeft, _: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.previous_boundary(self.cursor_offset()), cx);
    }

    fn select_right(&mut self, _: &InputSelectRight, _: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.next_boundary(self.cursor_offset()), cx);
    }

    fn select_all(&mut self, _: &InputSelectAll, _: &mut Window, cx: &mut Context<Self>) {
        self.move_to(0, cx);
        self.select_to(self.content.len(), cx);
    }

    fn home(&mut self, _: &InputHome, _: &mut Window, cx: &mut Context<Self>) {
        if !self.multiline {
            self.move_to(0, cx);
            return;
        }
        let cur = self.cursor_offset();
        let line_start = self.content[..cur]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        self.move_to(line_start, cx);
    }

    fn end(&mut self, _: &InputEnd, _: &mut Window, cx: &mut Context<Self>) {
        if !self.multiline {
            self.move_to(self.content.len(), cx);
            return;
        }
        let cur = self.cursor_offset();
        let line_end = self.content[cur..]
            .find('\n')
            .map(|i| cur + i)
            .unwrap_or(self.content.len());
        self.move_to(line_end, cx);
    }

    fn enter(&mut self, _: &InputEnter, window: &mut Window, cx: &mut Context<Self>) {
        if self.multiline {
            self.replace_text_in_range(None, "\n", window, cx);
        }
    }

    fn backspace(&mut self, _: &InputBackspace, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.select_to(self.previous_boundary(self.cursor_offset()), cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn delete(&mut self, _: &InputDelete, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.select_to(self.next_boundary(self.cursor_offset()), cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn paste(&mut self, _: &InputPaste, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
            let cleaned = if self.multiline {
                text.replace("\r\n", "\n")
            } else {
                text.replace("\r\n", " ").replace('\n', " ")
            };
            self.replace_text_in_range(None, &cleaned, window, cx);
        }
    }

    fn copy(&mut self, _: &InputCopy, _: &mut Window, cx: &mut Context<Self>) {
        if !self.selected_range.is_empty() {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.content[self.selected_range.clone()].to_string(),
            ));
        }
    }

    fn cut(&mut self, _: &InputCut, window: &mut Window, cx: &mut Context<Self>) {
        if !self.selected_range.is_empty() {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.content[self.selected_range.clone()].to_string(),
            ));
            self.replace_text_in_range(None, "", window, cx);
        }
    }

    fn on_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        window.focus(&self.focus_handle);
        self.is_selecting = true;
        let idx = self.index_for_mouse_position(event.position);
        if event.modifiers.shift {
            self.select_to(idx, cx);
        } else {
            self.move_to(idx, cx);
        }
    }

    fn on_mouse_up(&mut self, _: &MouseUpEvent, _window: &mut Window, _: &mut Context<Self>) {
        self.is_selecting = false;
    }

    fn on_mouse_move(&mut self, event: &MouseMoveEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.is_selecting {
            self.select_to(self.index_for_mouse_position(event.position), cx);
        }
    }

    fn move_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        let clamped = offset.min(self.content.len());
        self.selected_range = clamped..clamped;
        self.selection_reversed = false;
        cx.notify();
    }

    fn select_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        let offset = offset.min(self.content.len());
        if self.selection_reversed {
            self.selected_range.start = offset;
        } else {
            self.selected_range.end = offset;
        }
        if self.selected_range.end < self.selected_range.start {
            self.selection_reversed = !self.selection_reversed;
            self.selected_range = self.selected_range.end..self.selected_range.start;
        }
        cx.notify();
    }

    fn cursor_offset(&self) -> usize {
        if self.selection_reversed {
            self.selected_range.start
        } else {
            self.selected_range.end
        }
    }

    fn index_for_mouse_position(&self, position: Point<Pixels>) -> usize {
        if self.content.is_empty() {
            return 0;
        }
        let Some(bounds) = self.last_bounds.as_ref() else {
            return 0;
        };
        if self.last_lines.is_empty() {
            return 0;
        }
        if position.y < bounds.top() {
            return 0;
        }
        let lh = self.last_line_height.max(px(1.));
        let rel_y = position.y - bounds.top();
        let line_idx = ((rel_y / lh).floor().max(0.0) as usize).min(self.last_lines.len() - 1);
        let lr = &self.last_lines[line_idx];
        let local_idx = lr.shaped.closest_index_for_x(position.x - bounds.left());
        let clamped_local = local_idx.min(lr.byte_range.len());
        lr.byte_range.start + clamped_local
    }

    fn compute_line_byte_ranges(&self) -> Vec<Range<usize>> {
        let text = self.content.as_ref();
        if !self.multiline {
            return vec![0..text.len()];
        }
        let mut ranges = Vec::new();
        let mut start = 0;
        for (idx, ch) in text.char_indices() {
            if ch == '\n' {
                ranges.push(start..idx);
                start = idx + 1;
            }
        }
        ranges.push(start..text.len());
        ranges
    }

    fn offset_from_utf16(&self, offset: usize) -> usize {
        let mut utf8_offset = 0;
        let mut utf16_count = 0;
        for ch in self.content.chars() {
            if utf16_count >= offset {
                break;
            }
            utf16_count += ch.len_utf16();
            utf8_offset += ch.len_utf8();
        }
        utf8_offset
    }

    fn offset_to_utf16(&self, offset: usize) -> usize {
        let mut utf16_offset = 0;
        let mut utf8_count = 0;
        for ch in self.content.chars() {
            if utf8_count >= offset {
                break;
            }
            utf8_count += ch.len_utf8();
            utf16_offset += ch.len_utf16();
        }
        utf16_offset
    }

    fn range_to_utf16(&self, range: &Range<usize>) -> Range<usize> {
        self.offset_to_utf16(range.start)..self.offset_to_utf16(range.end)
    }

    fn range_from_utf16(&self, range_utf16: &Range<usize>) -> Range<usize> {
        self.offset_from_utf16(range_utf16.start)..self.offset_from_utf16(range_utf16.end)
    }

    fn previous_boundary(&self, offset: usize) -> usize {
        self.content
            .grapheme_indices(true)
            .rev()
            .find_map(|(idx, _)| (idx < offset).then_some(idx))
            .unwrap_or(0)
    }

    fn next_boundary(&self, offset: usize) -> usize {
        self.content
            .grapheme_indices(true)
            .find_map(|(idx, _)| (idx > offset).then_some(idx))
            .unwrap_or(self.content.len())
    }
}

impl EntityInputHandler for TextInput {
    fn text_for_range(
        &mut self,
        range_utf16: Range<usize>,
        actual_range: &mut Option<Range<usize>>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<String> {
        let range = self.range_from_utf16(&range_utf16);
        actual_range.replace(self.range_to_utf16(&range));
        Some(self.content[range].to_string())
    }

    fn selected_text_range(
        &mut self,
        _ignore_disabled_input: bool,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        Some(UTF16Selection {
            range: self.range_to_utf16(&self.selected_range),
            reversed: self.selection_reversed,
        })
    }

    fn marked_text_range(
        &self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Range<usize>> {
        self.marked_range
            .as_ref()
            .map(|range| self.range_to_utf16(range))
    }

    fn unmark_text(&mut self, _window: &mut Window, _cx: &mut Context<Self>) {
        self.marked_range = None;
    }

    fn replace_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_utf16
            .as_ref()
            .map(|r| self.range_from_utf16(r))
            .or(self.marked_range.clone())
            .unwrap_or(self.selected_range.clone());
        let start = range.start.min(self.content.len());
        let end = range.end.min(self.content.len());

        let inserted = if self.multiline {
            new_text.replace("\r\n", "\n")
        } else {
            new_text.replace("\r\n", " ").replace('\n', " ")
        };

        self.content =
            (self.content[0..start].to_owned() + &inserted + &self.content[end..]).into();
        let new_pos = start + inserted.len();
        self.selected_range = new_pos..new_pos;
        self.selection_reversed = false;
        self.marked_range.take();
        cx.notify();
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        new_selected_range_utf16: Option<Range<usize>>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_utf16
            .as_ref()
            .map(|r| self.range_from_utf16(r))
            .or(self.marked_range.clone())
            .unwrap_or(self.selected_range.clone());
        let start = range.start.min(self.content.len());
        let end = range.end.min(self.content.len());

        self.content =
            (self.content[0..start].to_owned() + new_text + &self.content[end..]).into();
        if !new_text.is_empty() {
            self.marked_range = Some(start..start + new_text.len());
        } else {
            self.marked_range = None;
        }
        self.selected_range = new_selected_range_utf16
            .as_ref()
            .map(|r| self.range_from_utf16(r))
            .map(|nr| (start + nr.start).min(self.content.len())..(start + nr.end).min(self.content.len()))
            .unwrap_or_else(|| start + new_text.len()..start + new_text.len());
        cx.notify();
    }

    fn bounds_for_range(
        &mut self,
        range_utf16: Range<usize>,
        bounds: Bounds<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        let range = self.range_from_utf16(&range_utf16);
        let lr = self
            .last_lines
            .iter()
            .find(|l| range.start >= l.byte_range.start && range.start <= l.byte_range.end)
            .or_else(|| self.last_lines.first())?;
        let line_idx = self
            .last_lines
            .iter()
            .position(|l| l.byte_range == lr.byte_range)
            .unwrap_or(0);
        let top = bounds.top() + self.last_line_height * line_idx as f32;
        let s_idx = range.start.saturating_sub(lr.byte_range.start).min(lr.byte_range.len());
        let e_idx = range.end.saturating_sub(lr.byte_range.start).min(lr.byte_range.len());
        Some(Bounds::from_corners(
            point(bounds.left() + lr.shaped.x_for_index(s_idx), top),
            point(bounds.left() + lr.shaped.x_for_index(e_idx), top + self.last_line_height),
        ))
    }

    fn character_index_for_point(
        &mut self,
        pt: Point<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<usize> {
        let idx = self.index_for_mouse_position(pt);
        Some(self.offset_to_utf16(idx))
    }
}

struct TextElement {
    input: Entity<TextInput>,
}

struct PrepaintState {
    lines: Vec<LineRange>,
    cursor: Option<PaintQuad>,
    selections: Vec<PaintQuad>,
    line_height: Pixels,
    is_placeholder: bool,
}

impl IntoElement for TextElement {
    type Element = Self;
    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for TextElement {
    type RequestLayoutState = ();
    type PrepaintState = PrepaintState;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let input = self.input.read(cx);
        let line_count = if input.multiline {
            input
                .compute_line_byte_ranges()
                .len()
                .clamp(input.min_lines, input.max_lines)
        } else {
            1
        };
        let mut style = Style::default();
        style.size.width = relative(1.).into();
        style.size.height = (window.line_height() * line_count as f32).into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        let input = self.input.read(cx);
        let content = input.content.clone();
        let selected_range = input.selected_range.clone();
        let cursor_off = input.cursor_offset();
        let marked_range = input.marked_range.clone();
        let line_ranges = input.compute_line_byte_ranges();
        let style = window.text_style();
        let font_size = style.font_size.to_pixels(window.rem_size());
        let lh = window.line_height();

        if content.is_empty() {
            let placeholder = input.placeholder.clone();
            let run = TextRun {
                len: placeholder.len(),
                font: style.font(),
                color: hsla(0., 0., 0.55, 0.7),
                background_color: None,
                underline: None,
                strikethrough: None,
            };
            let shaped = window
                .text_system()
                .shape_line(placeholder, font_size, &[run], None);
            let cursor = Some(fill(
                Bounds::new(bounds.origin, size(px(2.), lh)),
                gpui::rgb(0x60a5fa),
            ));
            return PrepaintState {
                lines: vec![LineRange {
                    byte_range: 0..0,
                    shaped,
                }],
                cursor,
                selections: Vec::new(),
                line_height: lh,
                is_placeholder: true,
            };
        }

        let mut shaped_lines = Vec::with_capacity(line_ranges.len());
        let mut selections = Vec::new();
        let mut cursor = None;

        for (line_idx, br) in line_ranges.iter().enumerate() {
            let line_str: SharedString = content[br.clone()].to_string().into();
            let mut runs = Vec::new();
            if line_str.is_empty() {
                runs.push(TextRun {
                    len: 0,
                    font: style.font(),
                    color: style.color,
                    background_color: None,
                    underline: None,
                    strikethrough: None,
                });
            } else if let Some(mr) = marked_range.as_ref()
                && mr.start < br.end
                && mr.end > br.start
            {
                let ms = mr.start.max(br.start) - br.start;
                let me = mr.end.min(br.end) - br.start;
                if ms > 0 {
                    runs.push(TextRun {
                        len: ms,
                        font: style.font(),
                        color: style.color,
                        background_color: None,
                        underline: None,
                        strikethrough: None,
                    });
                }
                if me > ms {
                    runs.push(TextRun {
                        len: me - ms,
                        font: style.font(),
                        color: style.color,
                        background_color: None,
                        underline: Some(UnderlineStyle {
                            color: Some(style.color),
                            thickness: px(1.),
                            wavy: false,
                        }),
                        strikethrough: None,
                    });
                }
                if me < line_str.len() {
                    runs.push(TextRun {
                        len: line_str.len() - me,
                        font: style.font(),
                        color: style.color,
                        background_color: None,
                        underline: None,
                        strikethrough: None,
                    });
                }
            } else {
                runs.push(TextRun {
                    len: line_str.len(),
                    font: style.font(),
                    color: style.color,
                    background_color: None,
                    underline: None,
                    strikethrough: None,
                });
            }

            let shaped = window
                .text_system()
                .shape_line(line_str, font_size, &runs, None);
            let y_top = bounds.top() + lh * line_idx as f32;
            let y_bot = y_top + lh;

            if !selected_range.is_empty()
                && selected_range.start <= br.end
                && selected_range.end >= br.start
            {
                let s_local = selected_range.start.saturating_sub(br.start).min(br.len());
                let e_local = selected_range.end.saturating_sub(br.start).min(br.len());
                if e_local > s_local || (selected_range.end > br.end && s_local == br.len()) {
                    let x1 = bounds.left() + shaped.x_for_index(s_local);
                    let x2 = if selected_range.end > br.end {
                        bounds.left() + shaped.x_for_index(br.len()) + px(6.)
                    } else {
                        bounds.left() + shaped.x_for_index(e_local)
                    };
                    selections.push(fill(
                        Bounds::from_corners(point(x1, y_top), point(x2, y_bot)),
                        rgba(0x3b82f644),
                    ));
                }
            } else if selected_range.is_empty()
                && cursor_off >= br.start
                && cursor_off <= br.end
                && cursor.is_none()
            {
                let c_local = (cursor_off - br.start).min(br.len());
                let x = bounds.left() + shaped.x_for_index(c_local);
                cursor = Some(fill(
                    Bounds::new(point(x, y_top), size(px(2.), lh)),
                    gpui::rgb(0x60a5fa),
                ));
            }

            shaped_lines.push(LineRange {
                byte_range: br.clone(),
                shaped,
            });
        }

        PrepaintState {
            lines: shaped_lines,
            cursor,
            selections,
            line_height: lh,
            is_placeholder: false,
        }
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        let focus_handle = self.input.read(cx).focus_handle.clone();
        window.handle_input(
            &focus_handle,
            ElementInputHandler::new(bounds, self.input.clone()),
            cx,
        );

        for sel in prepaint.selections.drain(..) {
            window.paint_quad(sel);
        }

        let lh = prepaint.line_height;
        for (idx, lr) in prepaint.lines.iter().enumerate() {
            let origin = point(bounds.left(), bounds.top() + lh * idx as f32);
            if origin.y + lh <= bounds.bottom() + lh {
                let _ = lr.shaped.paint(origin, lh, window, cx);
            }
        }

        if focus_handle.is_focused(window)
            && let Some(cursor) = prepaint.cursor.take()
        {
            window.paint_quad(cursor);
        }

        let stored_lines = if prepaint.is_placeholder {
            Vec::new()
        } else {
            prepaint.lines.clone()
        };

        self.input.update(cx, |input, _cx| {
            input.last_lines = stored_lines;
            input.last_bounds = Some(bounds);
            input.last_line_height = lh;
        });
    }
}

impl Render for TextInput {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.focus_handle.is_focused(window);
        let border_col = if focused {
            gpui::rgb(0x3b82f6)
        } else {
            gpui::rgb(0x334155)
        };

        let mut container = div()
            .flex()
            .w_full()
            .key_context("WatchdogInput")
            .track_focus(&self.focus_handle(cx))
            .cursor(CursorStyle::IBeam)
            .on_action(cx.listener(Self::backspace))
            .on_action(cx.listener(Self::delete))
            .on_action(cx.listener(Self::left))
            .on_action(cx.listener(Self::right))
            .on_action(cx.listener(Self::up))
            .on_action(cx.listener(Self::down))
            .on_action(cx.listener(Self::select_left))
            .on_action(cx.listener(Self::select_right))
            .on_action(cx.listener(Self::select_all))
            .on_action(cx.listener(Self::home))
            .on_action(cx.listener(Self::end))
            .on_action(cx.listener(Self::enter))
            .on_action(cx.listener(Self::paste))
            .on_action(cx.listener(Self::cut))
            .on_action(cx.listener(Self::copy))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_up_out(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .bg(gpui::rgb(0x0f172a))
            .border_1()
            .border_color(border_col)
            .rounded_md()
            .px_2()
            .py_1()
            .text_sm()
            .line_height(px(20.))
            .text_color(gpui::rgb(0xe2e8f0));

        if self.monospace {
            container = container.font_family("monospace");
        }

        if self.multiline {
            container = container.overflow_hidden();
        }

        container.child(TextElement { input: cx.entity() })
    }
}

impl Focusable for TextInput {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}
