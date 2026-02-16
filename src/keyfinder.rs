use serde::Deserializer;
use std::marker::PhantomData;

use serde_json::de::SliceRead;
use serde_json::value::RawValue;

#[derive(Debug, PartialEq, Eq)]
pub struct Position<'a> {
    // Includes the quotes (because we need them for verification)
    pub key_start_quote: usize,
    pub key_end_quote: usize,
    // Also includes quote or brackets, unless its a number or bool.
    pub value_start: usize,
    pub value_end: usize,

    pub key: &'a str,
    pub value: &'a str,
}
struct RawPosition<'data> {
    key: &'data str,
    value: &'data RawValue,
}

/// Only searches in the upper-most layer, doesn't go into sub-objects.
pub fn find_key_jsonbytes<'a, 'k>(
    data: &'a [u8],
    key: &'k str,
) -> serde_json::Result<Option<Position<'a>>> {
    let mut deserializer = serde_json::Deserializer::new(SliceRead::new(data));
    let raw = deserializer.deserialize_map(KeyFinderVisitor { key })?;
    deserializer.end()?;

    // Make sure the lifetime of raw_pos is actually dependent on data and not Deserializer.
    drop(deserializer);

    let Some(raw) = raw else { return Ok(None) };

    let key = raw.key;
    let value = raw.value.get();

    // Convert the references to an offset. This works because we know serde_json must have given us
    // a slice into our own data (due to lifetimes) and that data could not have been moved.
    let key_start_quote = raw.key.as_ptr() as usize - data.as_ptr() as usize - 1;
    assert!(key_start_quote > 0); // Minimum json map starts with `{"`
    assert!(key_start_quote < data.len());

    let key_end_quote = key_start_quote + key.len() + 2;
    assert!(key_end_quote > 0);
    assert!(key_end_quote < data.len());
    assert!(key_end_quote > key_start_quote);

    let value_start = value.as_ptr() as usize - data.as_ptr() as usize;
    assert!(value_start > 0);
    assert!(value_start < data.len());
    assert!(value_start > key_end_quote);

    let value_end = value_start + value.len();
    assert!(value_end > 0);
    assert!(value_end < data.len());
    assert!(value_end > value_start); // Kind of redundant.

    let pos = Position {
        key_start_quote,
        key_end_quote,
        value_start,
        value_end,
        key,
        value,
    };

    Ok(Some(pos))
}

struct KeyFinderVisitor<'data> {
    key: &'data str,
}

impl<'de> serde::de::Visitor<'de> for KeyFinderVisitor<'_> {
    type Value = Option<RawPosition<'de>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A map/object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut pos = None;
        while let Some(key) = map.next_key::<&str>()? {
            let value = map.next_value()?;
            if key == self.key {
                pos = Some(RawPosition { key, value });
            }
        }
        Ok(pos)
    }
}

#[cfg(test)]
mod test {
    use super::find_key_jsonbytes;

    #[track_caller]
    fn run(data: &[u8], key: &str, value: &str, surround_value_with_quotes: bool) {
        let pos = find_key_jsonbytes(data, key)
            .expect("invalid json")
            .expect("not found");

        let key = format!("\"{key}\"");
        assert_eq!(
            &data[pos.key_start_quote..pos.key_end_quote],
            key.as_bytes()
        );

        if surround_value_with_quotes {
            let value = format!("\"{value}\"");
            assert_eq!(&data[pos.value_start..pos.value_end], value.as_bytes());
        } else {
            assert_eq!(&data[pos.value_start..pos.value_end], value.as_bytes());
        }
    }

    #[track_caller]
    fn run_expect_none(data: &[u8], key: &str) {
        let pos = find_key_jsonbytes(data, key).expect("invalid json");
        assert_eq!(pos, None)
    }

    #[test]
    fn minimized() {
        let data = br#"{"foo":"bar","truck":"long vehicle","fat":1234,"o":{"foo":"nope","inner":"garbage"},"a":[1,2,3,4],"false":true,"true":"false","last":"lost"}"#;

        run(data, "foo", "bar", true);
        run(data, "truck", "long vehicle", true);
        run(data, "last", "lost", true);
        run_expect_none(data, "bar");
        run_expect_none(data, "gobbledygook");
        run(data, "fat", "1234", false);
        run(data, "false", "true", false);
        run(data, "true", "false", true);
        run(data, "o", r#"{"foo":"nope","inner":"garbage"}"#, false);
        run(data, "a", "[1,2,3,4]", false);
        run_expect_none(data, "inner");
    }

    #[test]
    fn pretty() {
        let data = br#"{
  "foo": "bar",
  "truck": "long vehicle",
  "fat": 1234,
  "o": {
    "foo": "nope",
    "inner": "garbage"
  },
  "a": [
    1,
    2,
    3,
    4
  ],
  "false": true,
  "true": "false",
  "last": "lost"
}"#;

        let o = r#"{
    "foo": "nope",
    "inner": "garbage"
  }"#;

        let a = r#"[
    1,
    2,
    3,
    4
  ]"#;

        run(data, "foo", "bar", true);
        run(data, "truck", "long vehicle", true);
        run(data, "last", "lost", true);
        run_expect_none(data, "bar");
        run_expect_none(data, "gobbledygook");
        run(data, "fat", "1234", false);
        run(data, "false", "true", false);
        run(data, "true", "false", true);
        run(data, "o", o, false);
        run(data, "a", a, false);
        run_expect_none(data, "inner");
    }

    #[test]
    fn unusual_whitespace() {
        // Newlines and Tabs within strings must be escaped according to json.
        // The quote is also escaped, just looks a bit weird because of the double escape.
        let data = b"{  \t\n     \"foo\"   \t\n:\n  \t   \" \\nb\\\"a\\tr \"\t  \n}";
        run(data, "foo", r#" \nb\"a\tr "#, true);
    }
}
