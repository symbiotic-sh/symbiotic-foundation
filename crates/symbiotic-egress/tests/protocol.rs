use symbiotic_egress::*;

#[test]
fn v2_refusal_has_the_documented_wire_shape() {
    let response = Response {
        version: PROTOCOL_VERSION,
        result: Err(EgressError::PermitRefused),
    };
    assert_eq!(
        serde_json::to_string(&response).unwrap(),
        r#"{"version":2,"result":{"Err":"permit_refused"}}"#
    );
    let decoded: Response =
        serde_json::from_str(r#"{"version":2,"result":{"Err":"permit_refused"}}"#).unwrap();
    assert!(matches!(decoded.result, Err(EgressError::PermitRefused)));
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
        .sign_revocation(RouteRevocation {
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            route: "route".into(),
            record_sequence: 11,
        })
        .unwrap();
    assert!(matches!(
        client
            .exchange(Request {
                version: PROTOCOL_VERSION,
                operation: Operation::RevokeRoute(signed)
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
async fn recovery_status_method_uses_v2_and_rejects_old_replies() {
    struct Double(u16);
    #[async_trait::async_trait]
    impl EgressClient for Double {
        async fn exchange(&self, request: Request) -> Result<Response, EgressError> {
            assert_eq!(request.version, 2);
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
    let client: Box<dyn EgressClient> = Box::new(Double(2));
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
