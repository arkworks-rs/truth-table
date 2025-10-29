macro_rules! end_to_end_tests {
    ($tables:expr => [$($name:ident => $sql:expr),+ $(,)?]) => {
        $(
            #[tokio::test]
            async fn $name() {
                exec::test_utils::prove_and_verify_query($sql, $tables, None)
                    .await
                    .expect(concat!("end-to-end: ", $sql));
            }
        )+
    };
}

pub(crate) use end_to_end_tests;
