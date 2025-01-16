// use proc_macro::{Literal, TokenStream};
// use quote::{ToTokens, quote};
// use syn::{
//     Attribute, Expr, Ident, ItemFn, LitStr, Meta, MetaList, parse::Parse, parse_macro_input,
//     punctuated::Punctuated,
// };

// #[derive(Debug)]
// struct SameCheck {
//     f_name: Ident,
//     f_args: Vec<Ident>,
// }

// impl Parse for SameCheck {
//     fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
//         let meta: Meta = input.parse()?;
//         let meta_list = meta.require_list()?;
//         let f_name = meta_list.path.get_ident().unwrap();
//         let mut f_args = Vec::new();
//         meta_list.parse_nested_meta(|meta| {
//             f_args.push(meta.path.get_ident().unwrap().clone());
//             Ok(())
//         })?;

//         Ok(SameCheck {
//             f_name: f_name.clone(),
//             f_args,
//         })
//     }
// }

// #[proc_macro_attribute]
// pub fn same(attr: TokenStream, item: TokenStream) -> TokenStream {
//     // Parse the function that we’re annotating
//     let mut function = parse_macro_input!(item as ItemFn);

//     // Generate a list of `assert!` statements based on the attribute arguments
//     let checks = generate_checks(attr);

//     // Insert those `assert!` statements at the start of the function body
//     let original_body = &function.block;
//     function.block = syn::parse_quote!({
//         checks
//         #original_body
//     });

//     // Convert the modified function back to a TokenStream
//     let output = quote! {
//         #function
//     };
//     output.into()
// }

// fn generate_checks(attr: TokenStream) -> TokenStream {
//     let mut output_token_stream = TokenStream::new();
//     let mut same_checks = Vec::new();

//     let args = parse_macro_input!(attr with Punctuated::<Meta, syn::Token![,]>::parse_terminated);
//     for pair in args.pairs() {
//         let meta_list = pair.into_value().require_list().unwrap();
//         let meta_tokens: TokenStream = meta_list.to_token_stream().into();
//         let same_arg = parse_macro_input!(meta_tokens as SameCheck);
//         same_checks.push(same_arg);
//     }

//     for same_check in same_checks {
//         let ref_prop_str = format!("ref_{}",same_check.f_name.to_string());
//         let current_checks = quote! {
//             let #ref_prop_str = #(same_check.f_args[0]).#(same_check.f_name)();
//             for arg in [#(same_check.f_args)*].iter() {
//                 assert_eq!(#ref_prop_str, arg.#(same_check.f_name)());
//             }
//         };
//         output_token_stream.extend(current_checks);
//     }
//     todo!()
// }
