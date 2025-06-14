use std::{ffi::CString, mem, ptr::null_mut, sync::Once};

use once_cell::sync::{Lazy, OnceCell};
use tokio::runtime::Runtime;
use winapi::{
    shared::minwindef::{BOOL, DWORD, FALSE, HINSTANCE, LPVOID, TRUE},
    um::{
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::VirtualProtect,
        winnt::PAGE_EXECUTE_READWRITE,
    },
};

// 全局状态
static INIT: Once = Once::new();

// 震动事件计数器（用于限制日志输出）
static VIBRATION_LOG_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
const MAX_VIBRATION_LOGS: u32 = 100;

// XInput震动结构体
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct XInputVibration {
    left_motor_speed: u16,
    right_motor_speed: u16,
}

// 原始函数指针类型
type XInputSetStateType = unsafe extern "stdcall" fn(u32, *const XInputVibration) -> u32;

// 存储原始函数指针和Hook信息
static mut ORIGINAL_BYTES: [u8; 12] = [0; 12]; // 保存原始字节
static mut ORIGINAL_FUNC_ADDR: *mut u8 = std::ptr::null_mut(); // 原始函数地址
static mut HOOK_INSTALLED: bool = false;
static mut IN_HOOK: bool = false; // 防止递归调用

mod true_gear;

// 全局tokio运行时和TrueGear客户端
static TOKIO_RUNTIME: Lazy<Runtime> =
    Lazy::new(|| Runtime::new().expect("Failed to create tokio runtime"));

static TRUE_GEAR_CLIENT: OnceCell<tokio::sync::Mutex<Option<true_gear::TrueGearClient>>> =
    OnceCell::new();

// 日志文件常量
const LOG_FILE_NAME: &str = "truegear_xinput_hook_debug.txt";

// 异步写入日志消息
async fn log_message_async(message: &str) {
    use tokio::fs::OpenOptions;
    use tokio::io::AsyncWriteExt;

    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f");
    let log_entry = format!("[{}] {}\n", timestamp, message);

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE_NAME)
        .await
    {
        let _ = file.write_all(log_entry.as_bytes()).await;
        let _ = file.flush().await;
    }
}

// 异步删除旧日志文件
async fn remove_old_log_file() {
    if let Err(_) = tokio::fs::remove_file(LOG_FILE_NAME).await {
        // 文件不存在或删除失败，忽略错误
    }
}

// 同步日志函数（用于非异步上下文）
fn log_message(message: &str) {
    let message = message.to_string();
    TOKIO_RUNTIME.spawn(async move {
        log_message_async(&message).await;
    });
}

// 初始化TrueGear客户端
async fn init_true_gear_client() -> anyhow::Result<()> {
    log_message("正在初始化TrueGear ...");

    match true_gear::connect().await {
        Ok(mut client) => {
            client.test_all().await?;
            log_message("TrueGear 连接成功 ...");
            // 初始化全局客户端存储
            let client_mutex = tokio::sync::Mutex::new(Some(client));
            if TRUE_GEAR_CLIENT.set(client_mutex).is_err() {
                log_message("警告: TRUE_GEAR_CLIENT.set(client_mutex).is_err");
            }
            Ok(())
        }
        Err(e) => {
            log_message(&format!("TrueGear客户端连接失败: {}", e));
            Err(e)
        }
    }
}

// 安装内存Hook
unsafe fn install_memory_hook() -> bool {
    // 删除旧的日志文件
    TOKIO_RUNTIME.spawn(async {
        remove_old_log_file().await;
    });

    let xinput_libs = ["xinput1_4.dll", "xinput1_3.dll", "xinput9_1_0.dll"];

    for lib_name in &xinput_libs {
        let lib_cstr = CString::new(*lib_name).unwrap();
        let module = GetModuleHandleA(lib_cstr.as_ptr());

        if module != null_mut() {
            let func_name = CString::new("XInputSetState").unwrap();
            let original_func = GetProcAddress(module, func_name.as_ptr());
            if original_func != null_mut() {
                log_message(&format!(
                    "找到 XInputSetState 函数在 {} at {:p}",
                    lib_name, original_func
                ));

                // 保存原始函数地址
                ORIGINAL_FUNC_ADDR = original_func as *mut u8; // 尝试安装内存Hook
                if install_jump_hook(
                    original_func as *mut u8,
                    hooked_xinput_set_state as *const u8,
                ) {
                    log_message("内存Hook安装成功");

                    // 在Hook成功后初始化TrueGear客户端
                    TOKIO_RUNTIME.spawn(async {
                        if let Err(e) = init_true_gear_client().await {
                            log_message(&format!("TrueGear客户端初始化失败: {}", e));
                        }
                    });

                    HOOK_INSTALLED = true;
                    return true;
                } else {
                    log_message("内存Hook安装失败");
                    return false;
                }
            }
        }
    }

    false
}

// 安装跳转Hook
unsafe fn install_jump_hook(target: *mut u8, hook_func: *const u8) -> bool {
    let mut old_protect = 0;

    // 修改内存保护
    if VirtualProtect(
        target as *mut _,
        12,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    ) == FALSE
    {
        log_message("修改内存保护失败");
        return false;
    }

    // 保存原始字节
    for i in 0..12 {
        ORIGINAL_BYTES[i] = *target.add(i);
    }

    // 创建跳转指令 (x64: mov rax, address; jmp rax)
    let hook_addr = hook_func as u64;
    let jump_code: [u8; 12] = [
        0x48,
        0xB8,                     // mov rax,
        (hook_addr & 0xFF) as u8, // address低字节
        (hook_addr >> 8 & 0xFF) as u8,
        (hook_addr >> 16 & 0xFF) as u8,
        (hook_addr >> 24 & 0xFF) as u8,
        (hook_addr >> 32 & 0xFF) as u8,
        (hook_addr >> 40 & 0xFF) as u8,
        (hook_addr >> 48 & 0xFF) as u8,
        (hook_addr >> 56 & 0xFF) as u8, // address高字节
        0xFF,
        0xE0, // jmp rax
    ];

    // 写入跳转代码
    for i in 0..12 {
        *target.add(i) = jump_code[i];
    }    // 恢复内存保护
    VirtualProtect(target as *mut _, 12, old_protect, &mut old_protect);

    true
}

// Hook后的XInputSetState函数
unsafe extern "stdcall" fn hooked_xinput_set_state(
    user_index: u32,
    vibration: *const XInputVibration,
) -> u32 {
    // 防止递归调用
    if IN_HOOK {
        return 0;
    }

    IN_HOOK = true;

    // 记录震动事件
    if !vibration.is_null() {
        let vib = *vibration;
        if vib.left_motor_speed > 0 || vib.right_motor_speed > 0 {
            on_vibration_event(user_index, vib.left_motor_speed, vib.right_motor_speed);
        }
    }

    // 临时恢复原始字节来调用原始函数
    let result = call_original_function(user_index, vibration);

    IN_HOOK = false;
    result
}

// 安全地调用原始函数
unsafe fn call_original_function(user_index: u32, vibration: *const XInputVibration) -> u32 {
    if ORIGINAL_FUNC_ADDR.is_null() {
        return 0;
    }

    let target = ORIGINAL_FUNC_ADDR;
    let mut old_protect = 0;

    // 临时恢复原始字节
    if VirtualProtect(
        target as *mut _,
        12,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    ) != FALSE
    {
        // 恢复原始字节
        for i in 0..12 {
            *target.add(i) = ORIGINAL_BYTES[i];
        }

        // 恢复内存保护
        VirtualProtect(target as *mut _, 12, old_protect, &mut old_protect);

        // 调用原始函数
        let original_func: XInputSetStateType = mem::transmute(target);
        let result = original_func(user_index, vibration);

        // 重新安装Hook
        if VirtualProtect(
            target as *mut _,
            12,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) != FALSE
        {
            // 重新写入跳转代码
            let hook_addr = hooked_xinput_set_state as *const u8 as u64;
            let jump_code: [u8; 12] = [
                0x48,
                0xB8, // mov rax,
                (hook_addr & 0xFF) as u8,
                (hook_addr >> 8 & 0xFF) as u8,
                (hook_addr >> 16 & 0xFF) as u8,
                (hook_addr >> 24 & 0xFF) as u8,
                (hook_addr >> 32 & 0xFF) as u8,
                (hook_addr >> 40 & 0xFF) as u8,
                (hook_addr >> 48 & 0xFF) as u8,
                (hook_addr >> 56 & 0xFF) as u8,
                0xFF,
                0xE0, // jmp rax
            ];

            for i in 0..12 {
                *target.add(i) = jump_code[i];
            }

            VirtualProtect(target as *mut _, 12, old_protect, &mut old_protect);
        }

        result
    } else {
        0
    }
}

// 记录震动事件
fn on_vibration_event(controller: u32, left: u16, right: u16) {
    // 检查是否已超过最大日志数量限制
    let current_count = VIBRATION_LOG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    
    if current_count < MAX_VIBRATION_LOGS {
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let vibration_log = format!(
            "[{}] 🎮 震动检测! 控制器: {}, 左马达: {} ({}%), 右马达: {} ({}%)",
            timestamp,
            controller,
            left,
            (left as f32 / 65535.0 * 100.0) as u32,
            right,
            (right as f32 / 65535.0 * 100.0) as u32
        );
        // 异步写入调试日志
        log_message(&vibration_log);
    } else if current_count == MAX_VIBRATION_LOGS {
        // 到达限制时记录一条消息
        log_message(&format!("震动日志已达到最大数量 ({}), 后续震动事件将不再记录到日志", MAX_VIBRATION_LOGS));
    }
    
    // 无论是否记录日志，都继续发送震动到TrueGear
    send_vibration_to_truegear(controller, left, right);
}

// DLL入口点
#[no_mangle]
pub unsafe extern "stdcall" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    _lpv_reserved: LPVOID,
) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;

    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            INIT.call_once(|| {
                log_message("XInput Hook DLL 已加载到进程中");
                // 安装Hook
                if install_memory_hook() {
                    log_message("XInput Hook 安装成功");
                    let _ = tokio::task::block_in_place(|| async {
                        let _ = init_true_gear_client().await;
                    });
                } else {
                    log_message("XInput Hook 安装失败");
                }
            });

            TRUE
        }
        _ => TRUE,
    }
}

// 导出函数：模拟震动事件（用于测试）
#[no_mangle]
pub extern "stdcall" fn simulate_vibration(controller: u32, left: u16, right: u16) {
    on_vibration_event(controller, left, right);
}

// 导出函数：检查Hook状态
#[no_mangle]
pub extern "stdcall" fn is_hook_active() -> bool {
    unsafe { HOOK_INSTALLED }
}

// 添加一个简单的测试函数来验证Hook是否工作
#[no_mangle]
pub extern "stdcall" fn test_hook() {
    log_message("测试Hook函数被调用");
    // 模拟一个震动事件来测试日志系统
    on_vibration_event(0, 32768, 16384);
}

// 安全地发送震动到TrueGear
fn send_vibration_to_truegear(controller: u32, left: u16, right: u16) {
    // 在后台任务中异步发送震动
    TOKIO_RUNTIME.spawn(async move {
        send_vibration_to_truegear_async(controller, left, right).await;
    });
}

// 异步发送震动到TrueGear
async fn send_vibration_to_truegear_async(_: u32, left: u16, right: u16) {
    if let Some(client_mutex) = TRUE_GEAR_CLIENT.get() {
        let mut guard = client_mutex.lock().await;
        if let Some(ref mut client) = *guard {
            // 将震动强度转换为 0-100 的范围
            let left_intensity = (left as f32 / 65535.0 * 100.0) as i32;
            let right_intensity = (right as f32 / 65535.0 * 100.0) as i32;

            let mut tracks = Vec::new();

            // 处理左侧震动
            if left_intensity > 0 {
                let left_zones = get_left_vibration_zones(left_intensity);
                if !left_zones.is_empty() {
                    let left_track = true_gear::def::TrackObject::new_shake_duration(
                        Some(200), // 震动持续时间 200ms
                        Some(left_intensity),
                        Some(left_intensity),
                        Some(true_gear::def::IntensityMode::Const),
                        left_zones,
                    );
                    tracks.push(left_track);
                }
            }

            // 处理右侧震动
            if right_intensity > 0 {
                let right_zones = get_right_vibration_zones(right_intensity);
                if !right_zones.is_empty() {
                    let right_track = true_gear::def::TrackObject::new_shake_duration(
                        Some(200), // 震动持续时间 200ms
                        Some(right_intensity),
                        Some(right_intensity),
                        Some(true_gear::def::IntensityMode::Const),
                        right_zones,
                    );
                    tracks.push(right_track);
                }
            }

            // 发送震动命令
            if !tracks.is_empty() {
                if let Err(e) = client.send_shake(tracks).await {
                    log_message_async(&format!("发送TrueGear震动失败: {}", e)).await;
                }
            }
        } else {
            log_message_async("Error: TrueGear客户端未初始化").await;
        }
    } else {
        log_message_async("Error: TrueGear客户端未初始化或不可用").await;
    }
}

// 震动区域类型枚举
#[derive(Debug, Clone, Copy)]
enum VibrationSide {
    Left,
    Right,
}

// 获取震动区域（根据强度和侧边决定激活范围）
fn get_vibration_zones(intensity_percent: i32, side: VibrationSide) -> Vec<i32> {
    let mut zones = Vec::new();

    // 根据强度百分比决定激活的区域数量
    let zone_count = match intensity_percent {
        0..=20 => 1,  // 低强度：只激活最外侧
        21..=40 => 2, // 中低强度：激活外侧两列
        41..=60 => 3, // 中等强度：激活外侧三列
        61..=80 => 4, // 中高强度：激活外侧四列
        _ => 5,       // 高强度：激活所有列
    };

    // 根据侧边决定激活顺序
    for line in 0..5 {
        for col in 0..zone_count.min(4) {
            let front_index = match side {
                VibrationSide::Left => line * 4 + col,        // 左侧：从最左边开始激活
                VibrationSide::Right => line * 4 + (3 - col), // 右侧：从最右边开始激活
            };

            if front_index < true_gear::TRUE_GEAR_SHAKE_FRONT.len() {
                zones.push(true_gear::TRUE_GEAR_SHAKE_FRONT[front_index]);
                zones.push(true_gear::TRUE_GEAR_SHAKE_BACK[front_index]);
            }
        }
    }

    zones
}

// 获取左侧震动区域（兼容性保持函数）
fn get_left_vibration_zones(intensity_percent: i32) -> Vec<i32> {
    get_vibration_zones(intensity_percent, VibrationSide::Left)
}

// 获取右侧震动区域（兼容性保持函数）
fn get_right_vibration_zones(intensity_percent: i32) -> Vec<i32> {
    get_vibration_zones(intensity_percent, VibrationSide::Right)
}
