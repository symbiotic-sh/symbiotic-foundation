//! Shared default and override behavior for every directly constructed HTTP adapter.
use symbiotic_model::{
    AnthropicChatProvider, DEFAULT_MAX_REQUEST_BYTES, DEFAULT_MAX_RESPONSE_BYTES,
    GeminiEmbeddingProvider, JevClassifierProvider, ModelProvider, OpenAiCompatibleChatProvider,
};

#[test]
fn adapters_default_byte_limits_and_preserve_explicit_values() {
    let endpoint = "http://127.0.0.1:9/v1";
    let defaults: Vec<Box<dyn ModelProvider>> = vec![
        Box::new(OpenAiCompatibleChatProvider::new(
            "fixture", "model", endpoint, "",
        )),
        Box::new(AnthropicChatProvider::new("fixture", "model", endpoint, "")),
        Box::new(GeminiEmbeddingProvider::new("fixture", "model", "", 2)),
        Box::new(JevClassifierProvider::new("fixture", "model", endpoint, "")),
    ];
    for provider in defaults {
        provider
            .validate_configuration()
            .expect("default limits must validate");
        assert_eq!(
            provider.descriptor().metadata["max_request_bytes"],
            DEFAULT_MAX_REQUEST_BYTES
        );
        assert_eq!(
            provider.descriptor().metadata["max_response_bytes"],
            DEFAULT_MAX_RESPONSE_BYTES
        );
    }
    for (request, response) in [(123, 456), (0, 456), (123, 0)] {
        let providers: Vec<Box<dyn ModelProvider>> = vec![
            Box::new(
                OpenAiCompatibleChatProvider::new("fixture", "model", endpoint, "")
                    .with_request_limit(request)
                    .with_response_limit(response),
            ),
            Box::new(
                AnthropicChatProvider::new("fixture", "model", endpoint, "")
                    .with_request_limit(request)
                    .with_response_limit(response),
            ),
            Box::new(
                GeminiEmbeddingProvider::new("fixture", "model", "", 2)
                    .with_request_limit(request)
                    .with_response_limit(response),
            ),
            Box::new(
                JevClassifierProvider::new("fixture", "model", endpoint, "")
                    .with_request_limit(request)
                    .with_response_limit(response),
            ),
        ];
        for provider in providers {
            assert_eq!(provider.descriptor().metadata["max_request_bytes"], request);
            assert_eq!(
                provider.descriptor().metadata["max_response_bytes"],
                response
            );
            assert_eq!(
                provider.validate_configuration().is_ok(),
                request > 0 && response > 0
            );
        }
    }
}
