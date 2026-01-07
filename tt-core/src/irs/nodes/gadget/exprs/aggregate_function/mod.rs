pub fn input_label(i: usize) -> String {
    format!("__input_{}__", i)
}
pub const OUTPUT_LABEL: &str = "__output__";
pub const INPUT_RLC_LABEL: &str = "__input-rlc__";
pub const OUTPUT_RLC_LABEL: &str = "__output-rlc__";
pub mod count;
pub mod sum;
