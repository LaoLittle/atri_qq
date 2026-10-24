use bytes::BytesMut;
use jce::JceStruct;

#[derive(JceStruct, Debug)]
struct A {
    #[jce(tag = "1")]
    field1: i8,
    // tag = 2
    field2: u8,
}

#[test]
fn skip_field() {
    // {
    //    0: "232",
    //    1: 12,
    //    2: 253,
    //    3: Struct { 1: 23 },
    //    4: [1, 22, 3214, "124"],
    // 	  12: Map {
    // 	 	   "12": 233,
    // 	       "235": 11424,
    // 		   8890: [122, "141", {}, [112]]
    //    }
    // }
    let a = A::decode(
        [
            6, 3, 50, 51, 50, 16, 12, 32, 253, 58, 16, 23, 11, 73, 0, 4, 0, 1, 0, 22, 1, 12, 142,
            6, 3, 49, 50, 52, 200, 0, 3, 6, 2, 49, 50, 17, 0, 233, 6, 3, 50, 51, 53, 17, 44, 160,
            6, 4, 56, 56, 57, 48, 25, 0, 4, 0, 122, 6, 3, 49, 52, 49, 8, 12, 9, 0, 1, 0, 112,
        ]
        .as_ref(),
    )
    .unwrap();
    assert_eq!(a.field1, 12);
    assert_eq!(a.field2, 253);

    let mut byte = BytesMut::new();
    A::encode(&a, &mut byte).unwrap();

    let decoded = A::decode(&*byte).unwrap();
    assert_eq!(decoded.field1, 12);
    assert_eq!(decoded.field2, 253);
}
