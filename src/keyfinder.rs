use serde::de::Visitor;
use serde::{Deserialize, Deserializer};

use serde_json::de::{SliceRead, StrRead};
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

    let pos = compute_position_from_slices(raw.key, raw.value.get(), data);
    Ok(Some(pos))
}

/// The returned value (and its indicies) DO NOT contain the quotes (contrary to
/// [`find_key_jsonbytes`]). This is because we know for sure that it is a string, so there is no
/// need to support arbitrary values (and thus output raw json).
pub fn find_array_entry_by_str_value<'a, 'k>(
    data: &'a [u8],
    key: &'k str,
    value_to_find: &'k str,
) -> serde_json::Result<Option<Position<'a>>> {
    // Find the key (and get the array slice).
    // Doing this in two steps isn't the most efficient, but we aren't in a hot loop
    // (proof+witness gen is way slower).
    let mut deserializer = serde_json::Deserializer::new(SliceRead::new(data));
    let raw = deserializer.deserialize_map(KeyFinderVisitor { key })?;
    deserializer.end()?;
    drop(deserializer);

    let Some(raw) = raw else { return Ok(None) };

    let mut deserializer = serde_json::Deserializer::new(StrRead::new(raw.value.get()));
    let value = deserializer.deserialize_seq(StrValueFinderVisitor {
        value: value_to_find,
    })?;
    deserializer.end()?;
    drop(deserializer);

    let Some(value) = value else {
        return Ok(None);
    };

    let mut pos = compute_position_from_slices(raw.key, value, data);
    Ok(Some(pos))
}

pub fn find_array_follower_by_str_value<'a, 'k>(
    data: &'a [u8],
    value_to_find: &'k str,
) -> serde_json::Result<Option<Position<'a>>> {
    dbg!(value_to_find);
    let mut deserializer = serde_json::Deserializer::new(SliceRead::new(data));
    let raw = deserializer.deserialize_seq(StrValueSiblingFinderVisitor {
        value: value_to_find,
    })?;
    deserializer.end()?;
    drop(deserializer);

    let Some(raw) = raw else { return Ok(None) };

    let pos = compute_position_from_slices(raw.key, raw.value.get(), data);
    Ok(Some(pos))
}

// key and value must be slices of data. This function will panic (assert) if they are not.
fn compute_position_from_slices<'a>(key: &'a str, value: &'a str, data: &'a [u8]) -> Position<'a> {
    // Convert the references to an offset. This works because we know serde_json must have given us
    // a slice into our own data (due to lifetimes) and that data could not have been moved.
    let key_start_quote = key.as_ptr() as usize - data.as_ptr() as usize - 1;
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

    Position {
        key_start_quote,
        key_end_quote,
        value_start,
        value_end,
        key,
        value,
    }
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

struct StrValueFinderVisitor<'data> {
    value: &'data str,
}

impl<'de> serde::de::Visitor<'de> for StrValueFinderVisitor<'_> {
    type Value = Option<&'de str>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an array of strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut pos = None;
        while let Some(value) = seq.next_element::<&str>()? {
            if value == self.value {
                pos = Some(value); // Important: This must be from the data, not from self.
            }
        }
        Ok(pos)
    }
}

struct StrValueSiblingFinderVisitor<'data> {
    value: &'data str,
}

impl<'de> serde::de::Visitor<'de> for StrValueSiblingFinderVisitor<'_> {
    type Value = Option<RawPosition<'de>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an array")
    }
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        // Find the key (skipping other entries)
        let mut key = None;
        // We can't serialize into serde_json::Value because that creates an owned string.
        // We can't serialize into &str because it can have other types.
        // We can't really serialize into RawValue because that makes comparison hard.
        // Instead we serialize into a custom type (easiest).
        while let Some(value) = seq.next_element::<MaybeStr>()? {
            if let Some(value) = value.0 {
                if value == self.value {
                    key = Some(value);
                    break;
                }
            }
        }
        let Some(key) = key else {
            return Ok(None);
        };

        // The next entry (sibling) is the value
        let value = seq.next_element::<&RawValue>()?;
        let Some(value) = value else {
            return Ok(None);
        };

        // Consume the rest
        while let Some(value) = seq.next_element::<&RawValue>()? {}

        Ok(Some(RawPosition { key, value }))
    }
}

#[derive(Debug)]
struct MaybeStr<'a>(Option<&'a str>);

impl<'de> Deserialize<'de> for MaybeStr<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(MaybeStrVisitor)
    }
}

struct MaybeStrVisitor;

impl<'de> Visitor<'de> for MaybeStrVisitor {
    type Value = MaybeStr<'de>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(Some(v)))
    }

    // We cannot do it for this more generic one, since we want the lifetime dependency.
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(None))
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(None))
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(None))
    }

    fn visit_i128<E>(self, _: i128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(None))
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(None))
    }

    fn visit_u128<E>(self, _: u128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(None))
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(None))
    }

    fn visit_bytes<E>(self, _: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(None))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(None))
    }

    fn visit_some<D>(self, _: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(MaybeStr(None))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(MaybeStr(None))
    }

    fn visit_newtype_struct<D>(self, _: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(MaybeStr(None))
    }

    fn visit_seq<A>(self, mut visitor: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        while let Some(_) = visitor.next_element::<&RawValue>()? {}
        Ok(MaybeStr(None))
    }

    fn visit_map<A>(self, mut visitor: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        while let Some(_) = visitor.next_entry::<&RawValue, &RawValue>()? {}
        Ok(MaybeStr(None))
    }

    fn visit_enum<A>(self, _: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::EnumAccess<'de>,
    {
        Ok(MaybeStr(None))
    }
}

#[cfg(test)]
mod test {
    use super::{
        find_array_entry_by_str_value, find_array_follower_by_str_value, find_key_jsonbytes,
    };

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

    #[track_caller]
    fn run_arr(data: &[u8], key: &str, value: &str) {
        let pos = find_array_entry_by_str_value(data, key, value)
            .expect("invalid json")
            .expect("not found");

        let key = format!("\"{key}\"");
        assert_eq!(
            &data[pos.key_start_quote..pos.key_end_quote],
            key.as_bytes()
        );

        assert_eq!(&data[pos.value_start..pos.value_end], value.as_bytes());
    }

    #[track_caller]
    fn run_arr_expect_none(data: &[u8], key: &str, value: &str) {
        let pos = find_array_entry_by_str_value(data, key, value).expect("invalid json");
        assert_eq!(pos, None)
    }
    #[track_caller]
    fn run_arr_expect_err(data: &[u8], key: &str, value: &str) {
        find_array_entry_by_str_value(data, key, value).expect_err("did not return error");
    }

    #[test]
    fn arr_minimized() {
        let data =
            br#"{"foo":["alpha","beta","gamma"],"foo2":"nope","foo3":{"xxx":["yyy","zzz"]}}"#;

        run_arr(data, "foo", "alpha");
        run_arr(data, "foo", "beta");
        run_arr(data, "foo", "gamma");
        // We don't have to distinguish here, but the intent is that we consider the json to be
        // malformatted if "key" is not a list, so returning an error makes sense.
        run_arr_expect_none(data, "foo", "foo");
        run_arr_expect_none(data, "foo", "yyy");
        run_arr_expect_none(data, "xxx", "yyy");
        run_arr_expect_none(data, "xxx", "alpha");
        run_arr_expect_none(data, "fuzz", "alpha");
        run_arr_expect_err(data, "foo2", "nope");
        run_arr_expect_err(data, "foo3", "xxx");
        run_arr_expect_err(data, "foo3", "yyy");
    }

    #[track_caller]
    fn run_follower(data: &[u8], key: &str, value: &str) {
        let pos = find_array_follower_by_str_value(data, key)
            .expect("invalid json")
            .expect("not found");

        let key = format!("\"{key}\"");
        assert_eq!(
            &data[pos.key_start_quote..pos.key_end_quote],
            key.as_bytes()
        );

        assert_eq!(&data[pos.value_start..pos.value_end], value.as_bytes());
    }
    #[track_caller]
    fn run_follower_expect_none(data: &[u8], key: &str) {
        let pos = find_array_follower_by_str_value(data, key).expect("invalid json");
        assert_eq!(pos, None)
    }

    #[test]
    fn follower_minimized() {
        let data = br#"["foo","bar",["hello","world"],"fate",true,"baz",{"claim":"valid"},"end"]"#;

        run_follower(data, "foo", r#""bar""#);
        run_follower(data, "bar", r#"["hello","world"]"#);
        run_follower(data, "fate", "true");
        run_follower(data, "baz", r#"{"claim":"valid"}"#);
        run_follower_expect_none(data, "hello");
        run_follower_expect_none(data, "world");
        run_follower_expect_none(data, "true");
        run_follower_expect_none(data, "claim");
        run_follower_expect_none(data, "valid");
        run_follower_expect_none(data, "end");
        run_follower_expect_none(data, "garbage");
    }

    #[test]
    fn follower_numbers() {
        let data = br#"["foo","bar",1,"baz",[2,3],"fate",{"4":5},"fuzz",true]"#;

        run_follower(data, "foo", r#""bar""#);
        run_follower(data, "bar", "1");
        run_follower(data, "baz", "[2,3]");
        run_follower(data, "fate", r#"{"4":5}"#);
        run_follower(data, "fuzz", "true");
        run_follower_expect_none(data, "garbage");
    }
}
