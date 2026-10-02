use symbiotic_egress::*;

#[test]
fn v3_refusal_has_the_documented_wire_shape() {
    let response = Response {
        version: PROTOCOL_VERSION,
        result: Err(EgressError::PermitRefused),
    };
    assert_eq!(
        serde_json::to_string(&response).unwrap(),
        r#"{"version":3,"result":{"Err":"permit_refused"}}"#
    );
    let decoded: Response =
        serde_json::from_str(r#"{"version":3,"result":{"Err":"permit_refused"}}"#).unwrap();
    assert!(matches!(decoded.result, Err(EgressError::PermitRefused)));
}

#[test]
fn invalidated_status_has_a_distinct_wire_state() {
    let json = serde_json::to_string(&AttemptStatus::Invalidated).unwrap();
    assert_eq!(json, r#"{"state":"invalidated"}"#);
    assert!(matches!(
        serde_json::from_str::<AttemptStatus>(&json).unwrap(),
        AttemptStatus::Invalidated
    ));
}

#[tokio::test]
async fn memory_can_use_a_trait_object_test_double_without_the_credential_process() {
    struct Double;
    #[async_trait::async_trait]
    impl EgressClient for Double {
        async fn exchange(&self, _: Request) -> Result<Response, EgressError> {
            Err(EgressError::Transport)
        }
    }
    let client: Box<dyn EgressClient> = Box::new(Double);
    let signed = AdmissionKey::new(vec![42; 32])
        .unwrap()
        .sign_grant_revision(GrantRevision {
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            revision: 11,
        })
        .unwrap();
    assert!(matches!(
        client
            .exchange(Request {
                version: PROTOCOL_VERSION,
                operation: Operation::PublishGrantRevision(signed)
            })
            .await,
        Err(EgressError::Transport)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn frame_limit_is_checked_without_waiting_for_or_allocating_the_declared_body() {
    use tokio::io::AsyncWriteExt;
    let (mut client, mut server) = tokio::io::duplex(4);
    client.write_u32(u32::MAX).await.unwrap();
    let response = socket::read_frame::<Response>(&mut server, 4096).await;
    assert!(matches!(response, Err(EgressError::LimitExceeded)));
}

#[tokio::test]
async fn recovery_status_method_uses_v3_and_rejects_old_replies() {
    struct Double(u16);
    #[async_trait::async_trait]
    impl EgressClient for Double {
        async fn exchange(&self, request: Request) -> Result<Response, EgressError> {
            assert_eq!(request.version, 3);
            let Operation::AttemptStatus(signed) = request.operation else {
                panic!("wrong operation");
            };
            AdmissionKey::new(vec![42; 32])
                .unwrap()
                .verify_attempt_id(&signed)
                .unwrap();
            Ok(Response {
                version: self.0,
                result: Ok(Reply::AttemptStatus(AttemptStatus::NotIssued)),
            })
        }
    }
    let signed = AdmissionKey::new(vec![42; 32])
        .unwrap()
        .sign_attempt_id(AttemptId {
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            invocation_id: "invocation".into(),
            attempt_ordinal: 1,
        })
        .unwrap();
    let client: Box<dyn EgressClient> = Box::new(Double(3));
    assert!(matches!(
        client.attempt_status(signed.clone()).await.unwrap(),
        AttemptStatus::NotIssued
    ));
    assert!(matches!(
        Double(1).attempt_status(signed).await,
        Err(EgressError::Version)
    ));
}

#[test]
fn retrieval_output_decimals_survive_tagged_json_round_trips() {
    for json in [
        r#"{"kind":"embedding","vectors":[[0.125,-0.5]],"dimensions":2}"#,
        r#"{"kind":"rerank","hits":[{"index":0,"score":0.75}]}"#,
    ] {
        let output: ProviderOutput = serde_json::from_str(json).unwrap();
        match &output {
            ProviderOutput::Embedding {
                vectors,
                dimensions,
            } => {
                assert_eq!(vectors, &vec![vec![0.125, -0.5]]);
                assert_eq!(*dimensions, 2);
            }
            ProviderOutput::Rerank { hits } => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].index, 0);
                assert_eq!(hits[0].score, 0.75);
            }
            _ => panic!("wrong output"),
        }
        let encoded = serde_json::to_string(&output).unwrap();
        let recovered: ProviderOutput = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(output).unwrap(),
            serde_json::to_value(recovered).unwrap()
        );
    }
}

#[test]
fn accepted_receipt_identity_and_reference_round_trip_without_consumer_spend_fields() {
    let receipt = DispatchReceipt {
        attempt_digest: "a".repeat(64),
        attempt_id: AttemptId {
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            invocation_id: "invocation".into(),
            attempt_ordinal: 1,
        },
        reference: SpendReceiptRef("egress:accepted-attempt".into()),
        status: DispatchStatus::ProviderFailed,
        usage: Default::default(),
        spend_state: SpendState::Unknown,
    };
    let response = Response {
        version: PROTOCOL_VERSION,
        result: Ok(Reply::AttemptStatus(AttemptStatus::Dispatched { receipt })),
    };
    let bytes = serde_json::to_vec(&response).unwrap();
    let decoded: Response = serde_json::from_slice(&bytes).unwrap();
    let Reply::AttemptStatus(AttemptStatus::Dispatched { receipt }) = decoded.result.unwrap()
    else {
        panic!("missing accepted receipt");
    };
    assert_eq!(receipt.attempt_id.invocation_id, "invocation");
    assert_eq!(
        receipt.reference,
        SpendReceiptRef("egress:accepted-attempt".into())
    );
    assert_eq!(receipt.spend_state, SpendState::Unknown);
    let value = serde_json::to_value(receipt).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 6);
}

#[test]
fn admissions_reject_removed_consumer_spend_and_marking_fields() {
    let attempt = serde_json::json!({
        "tenant": "tenant", "incarnation": "incarnation", "invocation_id": "invocation",
        "attempt_ordinal": 1, "record_sequence": 1, "recorded_at": 100, "expires_at": 200,
        "recovery_expires_at": 300, "caller_binding": "caller", "route": "provider",
        "destination": "https://example.test", "model": "model", "method": "POST",
        "secret_ref": "secret", "manifest_ref": "manifest",
        "input_manifest_digest": "a".repeat(64), "input_digest": "b".repeat(64),
        "grant_revision": 10,
    });
    serde_json::from_value::<DurableAttempt>(attempt.clone()).unwrap();
    for (field, value) in [
        (
            "reserved_budget",
            serde_json::json!({"unit": "provider_requests", "amount": 1, "invocation_limit": 1}),
        ),
        ("markings", serde_json::json!([])),
        ("max_attempts", serde_json::json!(3)),
    ] {
        let mut obsolete = attempt.clone();
        obsolete[field] = value;
        assert!(
            serde_json::from_value::<DurableAttempt>(obsolete).is_err(),
            "accepted {field}"
        );
    }
}
