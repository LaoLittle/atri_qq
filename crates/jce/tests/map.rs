use bytes::BytesMut;
use jce::JceStruct;
use std::collections::HashMap;

#[derive(JceStruct, Debug)]
struct M {
    map: HashMap<String, i16>,
}

#[test]
fn map() {
    let decoded =
        M::decode([8, 0, 2, 6, 2, 49, 50, 17, 1, 66, 6, 2, 49, 52, 17, 1, 66].as_ref()).unwrap();
    assert_eq!(
        decoded.map,
        HashMap::from([("12".into(), 322), ("14".into(), 322)])
    );

    let mut enc = BytesMut::new();
    let original = M {
        map: {
            let mut map = HashMap::new();
            map.insert("123".into(), 114);
            map.insert("456".into(), 514);
            map
        },
    };
    original.encode(&mut enc).unwrap();
    assert_eq!(original.encoded_len(), enc.len());
    assert_eq!(M::decode(&*enc).unwrap().map, original.map);
}
