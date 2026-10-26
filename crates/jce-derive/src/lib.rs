use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Expr, Fields, Lit, Meta, Token, punctuated::Punctuated};

#[proc_macro_derive(JceStruct, attributes(jce))]
pub fn jce(input: TokenStream) -> TokenStream {
    match syn::parse::<DeriveInput>(input).and_then(try_jce) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

fn try_jce(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    &input,
                    "JceStruct requires named fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                &input,
                "JceStruct requires a struct",
            ))
        }
    };
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let mut defaults = Vec::new();
    let mut lengths = Vec::new();
    let mut encodes = Vec::new();
    let mut matches = Vec::new();
    let mut seen_declarations = Vec::new();
    let mut requirements = Vec::new();
    let mut tags = std::collections::HashSet::new();
    let mut next_tag: u16 = 0;

    for (index, field) in fields.iter().enumerate() {
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new_spanned(field, "expected field name"))?;
        let mut explicit_tag = None;
        let mut required = false;
        let mut default = None;
        for attr in field.attrs.iter().filter(|attr| attr.path().is_ident("jce")) {
            let list = match &attr.meta {
                Meta::List(list) => list,
                _ => {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "expected #[jce(tag = \"0\", required)]",
                    ))
                }
            };
            for nested in list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)? {
                match nested {
                    Meta::NameValue(value) if value.path.is_ident("tag") => {
                        if explicit_tag.is_some() {
                            return Err(syn::Error::new_spanned(value, "duplicate tag attribute"));
                        }
                        let literal = match &value.value {
                            Expr::Lit(value) => &value.lit,
                            _ => {
                                return Err(syn::Error::new_spanned(
                                    &value.value,
                                    "expected a tag from 0 to 255",
                                ))
                            }
                        };
                        let tag = match literal {
                            Lit::Str(value) => value
                                .value()
                                .parse::<u8>()
                                .map_err(|error| syn::Error::new_spanned(value, error))?,
                            Lit::Int(value) => value.base10_parse::<u8>()?,
                            _ => {
                                return Err(syn::Error::new_spanned(
                                    value,
                                    "expected a tag from 0 to 255",
                                ))
                            }
                        };
                        explicit_tag = Some(tag);
                    }
                    Meta::NameValue(value) if value.path.is_ident("default") => {
                        if default.is_some() {
                            return Err(syn::Error::new_spanned(value, "duplicate default attribute"));
                        }
                        default = Some(value.value);
                    }
                    Meta::Path(path) if path.is_ident("required") => {
                        required = true;
                    }
                    other => {
                        return Err(syn::Error::new_spanned(
                            other,
                            "unknown JCE field attribute",
                        ))
                    }
                }
            }
        }
        let tag = match explicit_tag {
            Some(tag) => tag,
            None => u8::try_from(next_tag)
                .map_err(|_| syn::Error::new_spanned(field, "JCE tag exceeds 255"))?,
        };
        if !tags.insert(tag) {
            return Err(syn::Error::new_spanned(field, "duplicate JCE field tag"));
        }
        next_tag = u16::from(tag) + 1;
        let header_len = if tag < 15 { 1usize } else { 2usize };
        defaults.push(match default {
            Some(value) => quote!(#ident: #value),
            None => quote!(#ident: ::core::default::Default::default()),
        });
        lengths.push(quote!(#header_len + ::jce::types::JceType::write_len(&self.#ident)));
        encodes.push(quote!(::jce::types::JceType::write(&self.#ident, buf, #tag);));
        let mark_seen = if required {
            let seen = format_ident!("__jce_seen_{}", index);
            seen_declarations.push(quote!(let mut #seen = false;));
            requirements.push(quote! {
                if !#seen {
                    return Err(::jce::error::DecodeError::MissingField {
                        struct_name: STRUCT_NAME, field: stringify!(#ident),
                    });
                }
            });
            quote!(#seen = true;)
        } else {
            quote!()
        };
        matches.push(quote! {
            #tag => {
                val.#ident = ::jce::types::JceType::read(buf, t, STRUCT_NAME, stringify!(#ident))?;
                #mark_seen
            }
        });
    }

    Ok(quote! {
        impl #impl_generics ::jce::JceStruct for #name #ty_generics #where_clause {
            fn encode_raw<B: ::jce::bytes::BufMut>(&self, buf: &mut B) {
                #(#encodes)*
            }

            fn encoded_len(&self) -> usize {
                0usize #(+ (#lengths))*
            }

            fn decode_raw<B: ::jce::bytes::Buf>(buf: &mut B, to_end: bool) -> ::jce::error::DecodeResult<Self> {
                const STRUCT_NAME: &str = stringify!(#name);
                let _depth = ::jce::de::enter_depth()?;
                let mut val = Self::default();
                #(#seen_declarations)*
                let mut ended = false;
                while buf.remaining() > 0 {
                    let header = ::jce::de::read_header(buf)?;
                    let t = header.value_type();
                    if t == ::jce::types::STRUCT_END {
                        if to_end || header.tag() != 0 {
                            return Err(::jce::error::DecodeError::InvalidType);
                        }
                        ended = true;
                        break;
                    }
                    match header.tag() {
                        #(#matches,)*
                        _ => ::jce::types::skip_field(buf, t)?,
                    }
                }
                if !to_end && !ended {
                    return Err(::jce::error::DecodeError::Eof);
                }
                #(#requirements)*
                Ok(val)
            }
        }

        impl #impl_generics ::core::default::Default for #name #ty_generics #where_clause {
            fn default() -> Self {
                Self { #(#defaults,)* }
            }
        }
    })
}
