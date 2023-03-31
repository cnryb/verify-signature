#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;


#[napi]
pub fn verify_signature(pem: String, data: String, signature: String) -> bool {
    verify_signature::verify(pem.as_str(), data.as_str(), signature.as_str())
}
