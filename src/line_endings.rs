#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LineSpan {
    pub(crate) content_end: usize,
    pub(crate) full_end: usize,
}

pub(crate) struct LineSpans<'a> {
    input: &'a str,
    cursor: usize,
}

pub(crate) fn line_spans(input: &str) -> LineSpans<'_> {
    LineSpans { input, cursor: 0 }
}

impl<'a> Iterator for LineSpans<'a> {
    type Item = LineSpan;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.input.len() {
            return None;
        }

        let start = self.cursor;
        let bytes = self.input.as_bytes();
        let mut idx = start;
        while idx < bytes.len() {
            match bytes[idx] {
                b'\n' => {
                    self.cursor = idx + 1;
                    return Some(LineSpan {
                        content_end: idx,
                        full_end: idx + 1,
                    });
                }
                b'\r' => {
                    let full_end = if bytes.get(idx + 1) == Some(&b'\n') {
                        idx + 2
                    } else {
                        idx + 1
                    };
                    self.cursor = full_end;
                    return Some(LineSpan {
                        content_end: idx,
                        full_end,
                    });
                }
                _ => idx += 1,
            }
        }

        self.cursor = bytes.len();
        Some(LineSpan {
            content_end: bytes.len(),
            full_end: bytes.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(input: &str) -> Vec<(&str, &str)> {
        line_spans(input)
            .scan(0usize, |start, span| {
                let content = &input[*start..span.content_end];
                let full = &input[*start..span.full_end];
                *start = span.full_end;
                Some((content, full))
            })
            .collect()
    }

    #[test]
    fn line_spans_supports_lf_cr_and_crlf() {
        assert_eq!(
            collect("alpha\nbeta"),
            vec![("alpha", "alpha\n"), ("beta", "beta")]
        );
        assert_eq!(
            collect("alpha\rbeta"),
            vec![("alpha", "alpha\r"), ("beta", "beta")]
        );
        assert_eq!(
            collect("alpha\r\nbeta"),
            vec![("alpha", "alpha\r\n"), ("beta", "beta")]
        );
    }

    #[test]
    fn line_spans_preserve_empty_lines() {
        assert_eq!(
            collect("\n\r\r\n"),
            vec![("", "\n"), ("", "\r"), ("", "\r\n")]
        );
    }
}
