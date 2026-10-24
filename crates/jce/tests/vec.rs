use bytes::Bytes;
use jce::JceStruct;

#[derive(JceStruct, Debug, PartialEq)]
struct V {
    a: Vec<i8>,
    b: B,
}

#[derive(JceStruct, Debug, PartialEq)]
struct B {
    b: Bytes,
    ca: i32,
    cbb: Vec<i32>,
}

#[test]
fn vec() {
    let v = V {
        a: vec![114, 127],
        b: B {
            b: Bytes::from_static(&[114, 5, 14]),
            ca: 114514,
            cbb: vec![114514, 1919810],
        },
    };

    let mut bytes: Vec<u8> = Vec::new();
    v.encode(&mut bytes).unwrap();

    assert_eq!(V::decode(&*bytes).unwrap(), v);
}
