use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum TrueGearBool {
    True,
    False,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum ActionType {
    Shake,      // 震动
    Electrical, // 电刺激
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum IntensityMode {
    Const,        // 常量
    Fade,         // 淡入或淡出
    FadeInAndOut, // 淡入再淡出或淡出再淡入
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct TrackObject {
    pub start_time: i32,               // 起始时间
    pub end_time: i32,                 // 结束时间
    pub stop_name: String,             // ?
    pub start_intensity: i32,          // 起始强度
    pub end_intensity: i32,            // 终止强度（当强度模式是FadeInAndOut时，为峰顶或谷底强度）
    pub intensity_mode: IntensityMode, // 强度模式
    pub action_type: ActionType,       // 动作类型
    pub once: TrueGearBool,            // 是否单次（只有在电刺激使用）
    pub interval: i32,                 // 间隔（只有在电刺激使用）
    pub index: Vec<i32>,               // 电机或电刺激的作用id
}

impl TrackObject {
    pub fn new(
        action_type: Option<ActionType>,
        intensity_mode: Option<IntensityMode>,
        once: Option<TrueGearBool>,
        interval: Option<i32>,
        start_time: Option<i32>,
        end_time: Option<i32>,
        stop_name: Option<String>,
        start_intensity: Option<i32>,
        end_intensity: Option<i32>,
        index: Vec<i32>,
    ) -> TrackObject {
        TrackObject {
            action_type: action_type.unwrap_or(ActionType::Shake),
            intensity_mode: intensity_mode.unwrap_or(IntensityMode::Const),
            once: once.unwrap_or(TrueGearBool::False),
            interval: interval.unwrap_or(0),
            start_time: start_time.unwrap_or(0),
            end_time: end_time.unwrap_or(100),
            stop_name: stop_name.unwrap_or("".to_string()),
            start_intensity: start_intensity.unwrap_or(0),
            end_intensity: end_intensity.unwrap_or(100),
            index,
        }
    }

    pub fn new_shake_duration(
        duration: Option<i32>,
        start_intensity: Option<i32>,
        end_intensity: Option<i32>,
        intensity_mode: Option<IntensityMode>,
        index: Vec<i32>,
    ) -> TrackObject {
        TrackObject {
            action_type: ActionType::Shake,
            intensity_mode: intensity_mode.unwrap_or(IntensityMode::Const),
            once: TrueGearBool::False,
            interval: 0,
            start_time: 0,
            end_time: duration.unwrap_or(100),
            stop_name: "".to_string(),
            start_intensity: start_intensity.unwrap_or(0),
            end_intensity: end_intensity.unwrap_or(100),
            index,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct TrueGearWsMessage {
    pub name: String,             // 消息名称
    pub uuid: String,             // 消息唯一标识符
    pub keep: TrueGearBool,       // 是否保留
    pub priority: i32,            // 优先级
    pub tracks: Vec<TrackObject>, // TrackObject 数组
}

impl TrueGearWsMessage {
    pub fn new_no_registered(tracks: Vec<TrackObject>) -> TrueGearWsMessage {
        TrueGearWsMessage {
            name: "LeftHandPickupItem".to_string(),
            uuid: "LeftHandPickupItem".to_string(),
            keep: TrueGearBool::False,
            priority: 0,
            tracks,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct TrueGearWsMessageContainer {
    method: String,
    body: String,
}

impl TrueGearWsMessageContainer {
    pub fn new_no_registered(message: TrueGearWsMessage) -> TrueGearWsMessageContainer {
        let message_json = serde_json::to_string(&message).unwrap();
        // println!("message body == {}", message_json);
        TrueGearWsMessageContainer {
            method: "play_no_registered".to_string(),
            body: BASE64_STANDARD.encode(message_json),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Response {
    method: String,
    result: String,
}

impl Response {
    pub(crate) fn from_message(m: Message) -> anyhow::Result<Response> {
        let message = m.to_text()?;
        let r: Response = serde_json::from_str(&message)?;
        let new_result = BASE64_STANDARD.decode(r.result)?;
        Ok(Response {
            method: r.method,
            result: String::from_utf8(new_result).unwrap_or("".to_string()),
        })
    }
}
