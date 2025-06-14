use crate::true_gear::def::{IntensityMode, TrueGearWsMessage};
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use futures_util::{SinkExt, TryStreamExt};
use once_cell::sync::Lazy;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub mod def;

static TRUE_GEAR_SERVER: &str = "ws://localhost:18233/v1/tact/";

pub static TRUE_GEAR_SHAKE_FRONT: Lazy<Vec<i32>> = Lazy::new(|| {
    vec![
        0, 1, 2, 3, // line 1
        4, 5, 6, 7, // line 2
        8, 9, 10, 11, // line 3
        12, 13, 14, 15, // line4
        16, 17, 18, 19, // line 5
    ]
});

pub static TRUE_GEAR_SHAKE_BACK: Lazy<Vec<i32>> = Lazy::new(|| {
    vec![
        100, 101, 102, 103, // line 1
        104, 105, 106, 107, // line 2
        108, 109, 110, 111, // line 3
        112, 113, 114, 115, // line 4
        116, 117, 118, 119, // line 5
    ]
});

pub struct TrueGearClient {
    writer: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    is_connected: bool,
}

impl TrueGearClient {
    fn new(p0: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>) -> TrueGearClient {
        TrueGearClient {
            writer: p0,
            is_connected: false,
        }
    }

    pub(crate) async fn close(&mut self) -> anyhow::Result<()> {
        self.is_connected = false;
        self.writer.close().await?;
        Ok(())
    }

    pub(crate) async fn test_all(&mut self) -> anyhow::Result<()> {
        let mut all_vec = Vec::from(TRUE_GEAR_SHAKE_FRONT.clone());
        all_vec.append(&mut Vec::from(TRUE_GEAR_SHAKE_BACK.clone()));
        let message =
            TrueGearWsMessage::new_no_registered(vec![def::TrackObject::new_shake_duration(
                Some(100),
                Some(100),
                Some(100),
                Some(IntensityMode::Const),
                all_vec,
            )]);
        let message_data = def::TrueGearWsMessageContainer::new_no_registered(message).to_json();
        self.writer.send(Message::text(message_data)).await?;
        Ok(())
    }

    pub async fn send_shake(&mut self, p0: Vec<def::TrackObject>) -> anyhow::Result<()> {
        let message = def::TrueGearWsMessageContainer::new_no_registered(
            TrueGearWsMessage::new_no_registered(p0),
        );
        let message_data = message.to_json();
        self.writer.send(Message::text(message_data)).await?;
        Ok(())
    }
}

pub(crate) async fn connect() -> anyhow::Result<TrueGearClient> {
    let (c, r) = tokio_tungstenite::connect_async(TRUE_GEAR_SERVER).await?;
    if r.status() != StatusCode::SWITCHING_PROTOCOLS {
        println!("Failed to connect to True Gear: {}", r.status());
    }
    let (w, r) = c.split();

    tokio::spawn(_listen_loop(r));

    let c = TrueGearClient::new(w);
    Ok(c)
}

async fn _listen_loop(
    mut r: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
) -> anyhow::Result<()> {
    let mut has_connected = false;
    while let Some(item) = r.try_next().await? {
        let message = def::Response::from_message(item);
        if message.is_ok() {
            if !has_connected {
                has_connected = true;
                println!("Connected!");
            }
            // println!("[TrueGear] {:?}", message?);
        }
    }
    Ok(())
}

pub(crate) fn get_shake_level_index(p0: i32) -> Vec<i32> {
    match p0 {
        0 => vec![0, 1, 2, 3, 100, 101, 102, 103],
        1 => vec![4, 5, 6, 7, 104, 105, 106, 107],
        2 => vec![8, 9, 10, 11, 108, 109, 110, 111],
        3 => vec![12, 13, 14, 15, 112, 113, 114, 115],
        4 => vec![16, 17, 18, 19, 116, 117, 118, 119],
        _ => vec![],
    }
}
