#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LineSpan<'a> {
    pub(crate) content: &'a str,
    pub(crate) full: &'a str,
}

pub(crate) struct LineSpans<'a> {
    input: &'a str,
    pos: usize,
}

pub(crate) fn line_spans(input: &str) -> LineSpans<'_> {
    LineSpans { input, pos: 0 }
}

impl<'a> Iterator for LineSpans<'a> {
    type Item = LineSpan<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.input.len() {
            return None;
        }

        let bytes = self.input.as_bytes();
        let start = self.pos;
        let mut idx = self.pos;
        while idx < bytes.len() && !matches!(bytes[idx], b'\n' | b'\r') {
            idx += 1;
        }

        if idx >= bytes.len() {
            self.pos = idx;
            return Some(LineSpan {
                content: &self.input[start..idx],
                full: &self.input[start..idx],
            });
        }

        let mut end = idx + 1;
        if bytes[idx] == b'\r' && bytes.get(idx + 1) == Some(&b'\n') {
            end += 1;
        }
        self.pos = end;
        Some(LineSpan {
            content: &self.input[start..idx],
            full: &self.input[start..end],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{LineSpan, line_spans};

    fn collect(input: &str) -> Vec<LineSpan<'_>> {
        line_spans(input).collect()
    }

    #[test]
    fn line_spans_support_lf_cr_and_crlf() {
        assert_eq!(
            collect("a\nb\rc\r\nd"),
            vec![
                LineSpan {
                    content: "a",
                    full: "a\n",
                },
                LineSpan {
                    content: "b",
                    full: "b\r",
                },
                LineSpan {
                    content: "c",
                    full: "c\r\n",
                },
                LineSpan {
                    content: "d",
                    full: "d",
                },
            ]
        );
    }

    #[test]
    fn line_spans_do_not_emit_empty_trailing_line() {
        assert_eq!(
            collect("a\r\n"),
            vec![LineSpan {
                content: "a",
                full: "a\r\n",
            }]
        );
        assert!(collect("").is_empty());
    }
}
