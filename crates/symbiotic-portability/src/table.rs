use crate::{Error, Limits};

/// A parsed table is strings plus columns, not inferred business records. Mapping,
/// currencies, dates, row identity and validation remain with the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}
/// Presentation output exposes transformations so it cannot be mistaken for a
/// reversible editable representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
    pub bytes: Vec<u8>,
    pub losses: Vec<String>,
}

fn validate_table(t: &Table, limits: Limits) -> Result<(), Error> {
    if t.columns.is_empty() || t.columns.iter().any(|v| v.trim().is_empty()) {
        return Err(Error::InvalidValue);
    }
    let unique: std::collections::BTreeSet<_> = t.columns.iter().collect();
    if unique.len() != t.columns.len() {
        return Err(Error::DuplicateIdentity);
    }
    if t.columns
        .len()
        .saturating_mul(t.rows.len().saturating_add(1))
        > limits.max_table_cells
    {
        return Err(Error::LimitExceeded);
    }
    if t.rows.iter().any(|r| r.len() != t.columns.len()) {
        return Err(Error::InvalidValue);
    }
    if t.columns
        .iter()
        .chain(t.rows.iter().flatten())
        .map(String::len)
        .sum::<usize>()
        > limits.max_input_bytes
    {
        return Err(Error::LimitExceeded);
    }
    Ok(())
}
/// Parse UTF-8 CSV with unique headers and fixed row width. Never infer deletion
/// from missing rows, types from text, or an editable schema from headers.
pub fn parse_csv(bytes: &[u8], limits: Limits) -> Result<Table, Error> {
    if bytes.len() > limits.max_input_bytes {
        return Err(Error::LimitExceeded);
    }
    std::str::from_utf8(bytes).map_err(|_| Error::InvalidValue)?;
    let mut reader = csv::ReaderBuilder::new().from_reader(bytes);
    let columns = reader
        .headers()
        .map_err(|_| Error::InvalidValue)?
        .iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut rows = Vec::new();
    for row in reader.records() {
        rows.push(
            row.map_err(|_| Error::InvalidValue)?
                .iter()
                .map(str::to_owned)
                .collect(),
        );
        if columns.len().saturating_mul(rows.len() + 1) > limits.max_table_cells {
            return Err(Error::LimitExceeded);
        }
    }
    let table = Table { columns, rows };
    validate_table(&table, limits)?;
    Ok(table)
}
fn spreadsheet_text(value: &str) -> String {
    if value.trim_start().starts_with(['=', '+', '-', '@']) || value.starts_with(['\t', '\r', '\n'])
    {
        format!("'{value}")
    } else {
        value.into()
    }
}
/// Spreadsheet-safe CSV presentation. Formula-like cells gain a quote prefix;
/// the output reports that loss and is never a controlled edit schema.
pub fn render_csv(table: &Table, limits: Limits) -> Result<Presentation, Error> {
    validate_table(table, limits)?;
    let mut writer = csv::Writer::from_writer(Vec::new());
    let mut changed = false;
    for row in std::iter::once(&table.columns).chain(table.rows.iter()) {
        let safe = row
            .iter()
            .map(|v| {
                let s = spreadsheet_text(v);
                changed |= s != *v;
                s
            })
            .collect::<Vec<_>>();
        writer.write_record(safe).map_err(|_| Error::InvalidValue)?;
    }
    let bytes = writer.into_inner().map_err(|_| Error::InvalidValue)?;
    if bytes.len() > limits.max_input_bytes {
        return Err(Error::LimitExceeded);
    }
    Ok(Presentation {
        bytes,
        losses: if changed {
            vec![
                "Formula-like cells were prefixed with an apostrophe for spreadsheet presentation."
                    .into(),
            ]
        } else {
            Vec::new()
        },
    })
}
/// Markdown table presentation only. Newlines become HTML breaks and Markdown
/// punctuation is escaped; typed JSON and original bytes remain authoritative.
pub fn render_markdown(table: &Table, limits: Limits) -> Result<Presentation, Error> {
    validate_table(table, limits)?;
    let escape = |v: &str| {
        v.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\\', "\\\\")
            .replace('|', "\\|")
            .replace('*', "\\*")
            .replace('_', "\\_")
            .replace('`', "\\`")
            .replace('[', "\\[")
            .replace(']', "\\]")
            .replace('\r', "")
            .replace('\n', "<br>")
    };
    let row = |values: &[String]| {
        format!(
            "| {} |\n",
            values
                .iter()
                .map(|v| escape(v))
                .collect::<Vec<_>>()
                .join(" | ")
        )
    };
    let mut text = row(&table.columns);
    text.push_str(&row(&vec!["---".into(); table.columns.len()]));
    for r in &table.rows {
        text.push_str(&row(r));
    }
    if text.len() > limits.max_input_bytes {
        return Err(Error::LimitExceeded);
    }
    Ok(Presentation{bytes:text.into_bytes(),losses:vec!["Markdown table presentation carries string cells only; newlines and markup are escaped.".into()]})
}
