use symbiotic_egress::*;

#[test]
fn v1_refusal_has_the_documented_wire_shape() {
    let response = Response {
        version: PROTOCOL_VERSION,
        result: Err(EgressError::PermitRefused),
    };
    assert_eq!(
        serde_json::to_string(&response).unwrap(),
        r#"{"version":1,"result":{"Err":"permit_refused"}}"#
    );
    let decoded: Response =
        serde_json::from_str(r#"{"version":1,"result":{"Err":"permit_refused"}}"#).unwrap();
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
                version: 1,
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
