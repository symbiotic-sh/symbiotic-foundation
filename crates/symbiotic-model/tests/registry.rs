//! Registry invariants; these fixtures configure no real provider credentials.
use serde_json::{Value, json};
use symbiotic_core::{ProviderPrincipalId, TenantId};
use symbiotic_model::{ModelQueueConfig, ModelRegistry};

fn config() -> Value {
    let mut config: Value =
        serde_json::from_str(include_str!("../../../examples/model-registry.json")).unwrap();
    config["accounts"] = json!([{ "id": "policy", "policy": ModelQueueConfig::default() }]);
    config["bindings"] = json!([{
        "identity": {"tenant": "a", "provider": "chat", "revision": "1", "account": "account"},
        "model": "example-chat-alias", "endpoint": "http://127.0.0.1:9/v1", "secret_ref": null,
        "account_policy": "policy", "account_sharing_key": null,
        "limits": {"max_request_bytes": 65536, "max_response_bytes": 65536, "max_output_tokens": 1024},
        "settings": {"thinking": null, "reasoning_effort": null, "dimensions": null, "served_model": null}
    }]);
    config
}
fn load(config: &Value) -> Result<ModelRegistry, symbiotic_model::ModelError> {
    ModelRegistry::from_json(&serde_json::to_vec(config).unwrap())
}

#[test]
fn aliases_resolve_to_one_model_and_metadata() {
    let registry = load(&config()).unwrap();
    assert!(std::ptr::eq(
        registry.model("example-chat").unwrap(),
        registry.model("example-chat-alias").unwrap()
    ));
    let bound = registry
        .binding(&TenantId("a".into()), &ProviderPrincipalId("chat".into()))
        .unwrap();
    assert_eq!(bound.model.identity.model.0, "example-model");
    assert!(bound.model.capabilities.structured_output);
    assert!(
        registry
            .binding(&TenantId("b".into()), &ProviderPrincipalId("chat".into()))
            .is_err()
    );
}
#[test]
fn example_catalogue_configures_no_implicit_provider() {
    let registry =
        ModelRegistry::from_json(include_bytes!("../../../examples/model-registry.json")).unwrap();
    assert!(registry.config().bindings.is_empty());
    assert!(registry.config().accounts.is_empty());
    assert!(
        registry
            .binding(&TenantId("a".into()), &ProviderPrincipalId("chat".into()))
            .is_err()
    );
}
#[test]
fn invalid_configuration_is_refused_as_a_whole() {
    let cases = [
        ("/version", json!(0)),
        ("/models/0/aliases", json!(["example-chat"])),
        ("/models/0/operations", json!(["vision"])),
        ("/models/0/identity/operation", json!("rerank")),
        ("/models/0/capabilities/context_window", json!(0)),
        ("/bindings/0/model", json!("missing")),
        ("/bindings/0/account_policy", json!("missing")),
        ("/bindings/0/identity/tenant", json!("")),
        ("/bindings/0/identity/revision", json!("")),
        ("/bindings/0/limits/max_response_bytes", json!(0)),
        ("/bindings/0/limits/max_request_bytes", json!(0)),
        ("/bindings/0/limits/max_output_tokens", json!(0)),
        (
            "/bindings/0/endpoint",
            json!("https://user:password@example.com"),
        ),
        ("/bindings/0/settings/dimensions", json!(3)),
        ("/bindings/0/settings/reasoning_effort", json!("")),
        ("/bindings/0/secret_ref", json!("")),
        ("/accounts/0/policy/max_in_flight", json!(0)),
        ("/accounts/0/policy/request_timeout_seconds", Value::Null),
        ("/accounts/0/policy/requests_per_minute", json!(0)),
        ("/accounts/0/policy/input_units_per_minute", json!(0)),
        ("/accounts/0/policy/logical_retry_attempts", json!(0)),
    ];
    for (path, value) in cases {
        let mut config = config();
        *config.pointer_mut(path).unwrap() = value;
        assert!(load(&config).is_err(), "{path}");
    }
    let mut config = config();
    config["accounts"][0]["policy"]["misspelled_setting"] = json!(1);
    assert!(load(&config).is_err());
}
#[test]
fn tenant_separation_and_account_sharing_are_explicit() {
    let mut config = config();
    let mut binding = config["bindings"][0].clone();
    binding["identity"]["tenant"] = json!("b");
    binding["account_policy"] = json!("other");
    config["bindings"].as_array_mut().unwrap().push(binding);
    let mut account = config["accounts"][0].clone();
    account["id"] = json!("other");
    account["policy"]["max_in_flight"] = json!(2);
    config["accounts"].as_array_mut().unwrap().push(account);
    assert!(
        load(&config).is_ok(),
        "independent tenants configure different limits"
    );
    config["bindings"][0]["account_sharing_key"] = json!("shared");
    config["bindings"][1]["account_sharing_key"] = json!("shared");
    assert!(load(&config).is_err(), "shared account policies must agree");
    config["accounts"][1]["policy"] = config["accounts"][0]["policy"].clone();
    assert!(
        load(&config).is_ok(),
        "identical policies explicitly share accounts"
    );
}
#[test]
fn unsupported_settings_and_unattributed_prices_are_refused() {
    let mut config = config();
    config["bindings"][0]["settings"]["thinking"] = json!("disabled");
    config["bindings"][0]["settings"]["reasoning_effort"] = json!("high");
    assert!(load(&config).is_err());
    config["bindings"][0]["settings"]["reasoning_effort"] = Value::Null;
    config["models"][0]["capabilities"]["pricing"] =
        json!({"input_micro_usd_per_million_tokens": 1, "output_micro_usd_per_million_tokens": 1});
    assert!(load(&config).is_err());
    config["models"][0]["pricing_provenance"] =
        json!({"source": "synthetic tariff", "date": "2026-10-02"});
    assert!(load(&config).is_ok());
}
