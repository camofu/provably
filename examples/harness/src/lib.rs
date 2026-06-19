//! The example seller's harness — the *specific* product this demo reseller sells.
//!
//! The framework crates (`provably-*`) are payment- and computation-agnostic. This crate
//! is the opposite: it pins down ONE concrete harness. Today that's "call the LLM, then
//! emit `1` if the answer starts with yes, else `0`." It lives in the examples universe
//! because it's seller-specific, not framework.
//!
//! Both demo peers reference it: the reseller (to compute the verdict and commit its
//! digest) and the buyer (to re-run it and verify). [`starts_with_yes`] is the toy
//! stand-in for a real interior proof — instead of shipping a zk/TEE proof that it ran
//! this, the seller commits the output digest and the buyer re-runs this exact function
//! over the notarized leg bytes. The manifest the buyer pins is what fixes *which*
//! harness (and therefore which transform) it will accept.

/// Manifest id the reseller advertises and the buyer pins.
pub const MANIFEST_ID: &str = "starts-with-yes-v1";

/// `fn_id` of the interior transform, named in the receipt's `verdict` node.
pub const VERDICT_FN_ID: &str = "starts_with_yes";

/// Run the public transform named by `fn_id` over a node's inputs (the outputs of its
/// `inputs` edges, in order). Returns `None` for an unknown id, so a verifier reports the
/// node as un-re-verified rather than silently trusting it.
pub fn recompute(fn_id: &str, inputs: &[&[u8]]) -> Option<Vec<u8>> {
    match fn_id {
        VERDICT_FN_ID => Some(starts_with_yes(inputs.first().copied().unwrap_or(&[]))),
        _ => None,
    }
}

/// `b"1"` if the upstream answer's text begins with "yes" (case-insensitive, leading
/// whitespace ignored), else `b"0"`. The input is a raw Anthropic `/v1/messages`
/// response body; a non-JSON or text-less body yields `b"0"`.
pub fn starts_with_yes(answer: &[u8]) -> Vec<u8> {
    let yes = serde_json::from_slice::<serde_json::Value>(answer)
        .ok()
        .and_then(|v| v["content"][0]["text"].as_str().map(str::to_owned))
        .map(|t| t.trim_start().to_ascii_lowercase().starts_with("yes"))
        .unwrap_or(false);
    if yes {
        b"1".to_vec()
    } else {
        b"0".to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(text: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "content": [{ "type": "text", "text": text }] }))
            .unwrap()
    }

    #[test]
    fn starts_with_yes_classifies_the_answer() {
        assert_eq!(starts_with_yes(&answer("Yes, absolutely.")), b"1");
        assert_eq!(starts_with_yes(&answer("  yes — definitely")), b"1");
        assert_eq!(starts_with_yes(&answer("No, it isn't.")), b"0");
        assert_eq!(starts_with_yes(&answer("Probably yes")), b"0");
        assert_eq!(starts_with_yes(b"not json"), b"0");
    }

    #[test]
    fn recompute_dispatches_known_ids_only() {
        assert_eq!(
            recompute(VERDICT_FN_ID, &[&answer("Yes")]).as_deref(),
            Some(b"1".as_slice())
        );
        assert_eq!(recompute("nope", &[b"x"]), None);
    }
}
