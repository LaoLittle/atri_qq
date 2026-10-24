use bytes::Bytes;
use jce::JceStruct;

#[derive(JceStruct)]
struct EncodedLen {
    str: String,
    bytes: Bytes,
    int: i32,
    alpha: Alpha,
    #[jce(tag = "129")]
    tag_129: Alpha,
}

#[derive(JceStruct)]
struct Alpha {
    f: i64,
    ba: Vec<i32>,
    str: String,
}

#[test]
fn encoded_len() {
    let encoded = EncodedLen {
        str: "114514".into(),
        bytes: Bytes::from_static(&[114, 51, 4]),
        int: 321,
        alpha: Alpha {
            f: 3331,
            ba: vec![],
            str: "1⃣️1⃣️4⃣️5⃣️1⃣️4⃣️".into(),
        },
        tag_129: Alpha {
            f: 123313,
            ba: vec![114, 514, 1919, 810],
            str: "🦀️💊🔥".into(),
        },
    };

    let mut buf = vec![0u8; 0];

    encoded.encode(&mut buf).unwrap();

    assert_eq!(encoded.encoded_len(), buf.len());
}
