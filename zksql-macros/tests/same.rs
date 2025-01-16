// use zksql_macros::same;

// #[test]
// fn test() {
//     let a = Dummy {
//         property1: 1,
//         property2: 2,
//     };

//     let b = Dummy {
//         property1: 1,
//         property2: 2,
//     };

//     let c = Dummy {
//         property1: 1,
//         property2: 2,
//     };

//     let d = Dummy {
//         property1: 1,
//         property2: 2,
//     };

//     test_func1(a, b, c, d);
// }

// #[same(property1(a, b, c), property2(a, b, d), property1(a, b))]
// fn test_func1(a: Dummy, b: Dummy, c: Dummy, d: Dummy) {}

// struct Dummy {
//     property1: usize,
//     property2: usize,
// }

// impl Dummy {
//     pub fn property1(&self) -> usize {
//         self.property1
//     }

//     pub fn property2(&self) -> usize {
//         self.property2
//     }
// }
