use serde_json::{json, Value};
use xray_config::{parse_xray_json, StreamTransport, XhttpSettings};

fn config(stream: Value) -> String {
    json!({"outbounds":[{"protocol":"vless","settings":{"vnext":[{
        "address":"127.0.0.1","port":443,"users":[{
            "id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"
        }]}]},"streamSettings":stream}]})
    .to_string()
}

fn settings(stream: Value) -> Box<XhttpSettings> {
    let parsed = parse_xray_json(&config(stream)).unwrap();
    let StreamTransport::Xhttp(settings) = parsed.config.outbounds[0].stream.transport.clone()
    else {
        panic!("XHTTP")
    };
    settings
}

#[test]
fn optional_window_accepts_only_bounded_integer_bytes() {
    for key in ["xhttpSettings", "splithttpSettings"] {
        for value in [
            json!(null),
            json!(65535),
            json!(1048576),
            json!(4194304),
            json!(16777216),
        ] {
            let stream = json!({"network":"xhttp", key:{"h2StreamReceiveWindow":value}});
            assert_eq!(
                settings(stream).h2_stream_receive_window,
                value.as_u64().map(|n| n as u32)
            );
        }
        for value in [
            json!(0),
            json!(-1),
            json!(65534),
            json!(16777217),
            json!(u64::MAX),
            json!(65535.5),
            json!("4194304"),
            json!("65535-4194304"),
            json!(true),
            json!([]),
            json!({}),
        ] {
            let error = parse_xray_json(&config(
                json!({"network":"xhttp", key:{"h2StreamReceiveWindow":value}}),
            ))
            .unwrap_err();
            let expected = format!("$.outbounds[0].streamSettings.{key}.h2StreamReceiveWindow");
            assert!(
                error
                    .diagnostics
                    .iter()
                    .any(|d| d.path.as_deref() == Some(&expected)),
                "{value}: {error:?}"
            );
        }
    }
    for stream in [
        json!({"network":"xhttp"}),
        json!({"network":"xhttp","xhttpSettings":{}}),
    ] {
        assert_eq!(settings(stream).h2_stream_receive_window, None);
    }
}

#[test]
fn window_follows_alias_priority_extra_replacement_and_download_ownership() {
    let up = settings(json!({"network":"xhttp",
    "splithttpSettings":{"h2StreamReceiveWindow":65535},
    "xhttpSettings":{"h2StreamReceiveWindow":1048576,"extra":{
        "h2StreamReceiveWindow":8388608,
        "downloadSettings":{"address":"127.0.0.1","port":8443,"network":"xhttp",
            "xhttpSettings":{"h2StreamReceiveWindow":65535}}
    }}}));
    assert_eq!(up.h2_stream_receive_window, Some(8388608));
    let StreamTransport::Xhttp(down) = &up.download.unwrap().stream.transport else {
        panic!("XHTTP")
    };
    assert_eq!(down.h2_stream_receive_window, Some(65535));
    for extra in [json!({}), json!(null)] {
        assert_eq!(
            settings(json!({"network":"xhttp","xhttpSettings":{
                "h2StreamReceiveWindow":1048576,"extra":extra
            }}))
            .h2_stream_receive_window,
            None
        );
    }
    let invalid = config(json!({"network":"xhttp","xhttpSettings":{"extra":{
        "downloadSettings":{"address":"127.0.0.1","port":8443,"network":"xhttp",
            "xhttpSettings":{"h2StreamReceiveWindow":0}}
    }}}));
    let error = parse_xray_json(&invalid).unwrap_err();
    assert!(error.diagnostics.iter().any(|d| d.path.as_deref()==Some(
        "$.outbounds[0].streamSettings.xhttpSettings.extra.downloadSettings.xhttpSettings.h2StreamReceiveWindow"
    )), "{error:?}");
}
