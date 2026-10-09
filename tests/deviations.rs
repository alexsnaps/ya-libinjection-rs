//! Where the port departs from libinjection on purpose: the bugs it fixes
//! that upstream, as vendored, still has. The differential tests build the C
//! library with the same fixes, `FIXES` in `tests/common`, so that the two
//! still have to agree on every input.

/// A 0xFF byte is a byte like any other. Where `char` is signed, upstream's
/// tokenizer takes one for the end of the input where an attribute's name or
/// value would start, and misses whatever comes after it:
/// <https://github.com/libinjection/libinjection/issues/92>.
#[test]
fn a_0xff_byte_does_not_end_a_tag() {
    let attacks: [&[u8]; 4] = [
        // Before an attribute name,
        b"<img \xff onerror=alert(1)>",
        b"<input \xff onfocus=alert(1) autofocus>",
        // after one,
        b"<img alt \xff onerror=alert(1)>",
        // and before an attribute value.
        b"<img alt= \xffx onerror=alert(1)>",
    ];
    let missed: Vec<String> = attacks
        .iter()
        .filter(|attack| !libperfusion::xss(attack))
        .map(|attack| attack.escape_ascii().to_string())
        .collect();
    assert!(missed.is_empty(), "not detected: {missed:?}");
}
