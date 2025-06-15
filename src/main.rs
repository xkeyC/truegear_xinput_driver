use std::{
    ffi::{CString, OsString},
    io::{self, Write},
    mem,
    os::windows::ffi::OsStringExt,
    ptr::null_mut,
    thread,
    time::Duration,
};

use log::{error, info};
use winapi::{
    shared::{
        minwindef::{FALSE, TRUE},
        ntdef::HANDLE,
    },um::{
        errhandlingapi::GetLastError,
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        libloaderapi::{GetProcAddress, LoadLibraryA},
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        processthreadsapi::{CreateRemoteThread, OpenProcess},
        psapi::{GetModuleBaseNameW, GetModuleFileNameExW},
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
        },
        winnt::{PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        synchapi::WaitForSingleObject,
        winbase::INFINITE,
        wincon::SetConsoleTitleA,
    },
};

// 内存分配常量
const MEM_COMMIT: u32 = 0x1000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// 游戏进程信息
#[derive(Debug, Clone)]
struct GameProcess {
    pid: u32,
    name: String,
}


fn main() {
    // 初始化日志
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    setup_console();
    
    info!("🚀 TrueGear XInput Driver v0.0.2");
    info!("开发者：xkeyC 3334969096@qq.com");
    info!("本项目使用GPL协议开源于 GitHub: https://github.com/xkeyC/truegear_xinput_driver");
    info!("在选择游戏前，请确保 Truegear_Player 正在运行，请谨慎在带有反作弊的游戏中使用此程序 ...");
    info!("正在扫描运行中的游戏进程...");
    
    // 设置Ctrl+C处理
    ctrlc::set_handler(move || {
        info!("收到退出信号，正在清理资源...");
        std::process::exit(0);
    }).expect("设置Ctrl+C处理器失败");    // 主循环：扫描进程并让用户选择
    loop {
        println!("\n🔍 正在扫描游戏进程...");
        let processes = scan_game_processes();
        
        // 显示进程列表并获取用户选择
        if let Some(selected_index) = display_and_select_processes(&processes) {
            let selected_process = &processes[selected_index];
            
            println!("\n✅ 已选择进程: {} (PID: {})", selected_process.name, selected_process.pid);
            
            // 尝试注入DLL
            println!("🔧 正在注入 Hook DLL...");
            match inject_xinput_hook(selected_process) {
                Ok(()) => {
                    println!("✅ 注入成功！本软件可安全关闭。");
                    println!("💡 如需停止体感服 ，请手动重启游戏，直接关闭 TrauGear_Player 可能会导致游戏异常！！");
                    // 开始监控震动
                    start_vibration_monitoring(selected_process);
                }
                Err(e) => {
                    println!("❌ 进程注入失败: {}", e);
                    println!("💡 请确保:");
                    println!("  • 尝试以管理员权限运行此程序");
                    println!("  • 目标游戏正在运行");
                    println!("  • 防病毒软件没有阻止DLL注入");
                    
                    wait_for_user_input("修复问题后可以重新尝试");
                }
            }
        } else {
            // 用户没有选择有效进程，重新扫描
            wait_for_user_input("按 Enter 键重新扫描游戏进程");
        }
    }
}


// 检查进程是否为游戏进程
fn is_game_process(process_name: &str, process_path: &str) -> bool {
    let lower_name = process_name.to_lowercase();
    let lower_path = process_path.to_lowercase();
    
    // 检查文件名是否以 Win64-Shipping.exe 结尾（UE游戏）
    if lower_name.ends_with("win64-shipping.exe") {
        return true;
    }
    
    // 检查路径是否包含 steamapps\common（Steam游戏）
    if lower_path.contains("steamapps\\common") {
        return true;
    }

    // Xbox PC 游戏
    if lower_path.contains("xboxgames") {
        return true;
    }
    
    false
}

// 获取进程完整路径
fn get_process_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if handle == null_mut() {
            return None;
        }

        let mut path_buffer = [0u16; 1024];
        let result = GetModuleFileNameExW(
            handle,
            null_mut(),
            path_buffer.as_mut_ptr(),
            path_buffer.len() as u32,
        );

        CloseHandle(handle);

        if result > 0 {
            let path = OsString::from_wide(&path_buffer[..result as usize]);
            Some(path.to_string_lossy().to_string())
        } else {
            None
        }
    }
}

// 获取进程名称
fn get_process_name(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if handle == null_mut() {
            return None;
        }

        let mut name_buffer = [0u16; 260];
        let result = GetModuleBaseNameW(
            handle,
            null_mut(),
            name_buffer.as_mut_ptr(),
            name_buffer.len() as u32,
        );

        CloseHandle(handle);

        if result > 0 {
            let name = OsString::from_wide(&name_buffer[..result as usize]);
            Some(name.to_string_lossy().to_string())
        } else {
            None
        }
    }
}

// 扫描所有进程并找到游戏进程
fn scan_game_processes() -> Vec<GameProcess> {
    let mut processes = Vec::new();
    
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            error!("Failed to create process snapshot");
            return processes;
        }

        let mut process_entry: PROCESSENTRY32 = mem::zeroed();
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;        if Process32First(snapshot, &mut process_entry) == TRUE {
            loop {
                let pid = process_entry.th32ProcessID;
                if let Some(name) = get_process_name(pid) {
                    if let Some(path) = get_process_path(pid) {
                        if is_game_process(&name, &path) {
                            // info!("Found game process: {} (PID: {})", name, pid);
                            // info!("Process path: {}", path);
                            processes.push(GameProcess {
                                pid,
                                name,
                            });
                        }
                    }
                }

                if Process32Next(snapshot, &mut process_entry) == FALSE {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }    processes
}

// 在目标进程中注入Hook代码
fn inject_xinput_hook(process: &GameProcess) -> Result<(), String> {
    unsafe {
        // 打开进程句柄
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
        if process_handle == null_mut() {
            return Err(format!("无法打开进程 PID: {}", process.pid));
        }
        
        // 获取当前DLL的路径
        let dll_path = get_dll_path()?;
        info!("DLL路径: {}", dll_path);
        
        // DLL注入
        let result = inject_dll_into_process(process_handle, &dll_path);
        
        // 关闭进程句柄
        CloseHandle(process_handle);
        
        result?;
        info!("成功注入DLL到进程: {} (PID: {})", process.name, process.pid);
        Ok(())
    }
}

// 获取当前DLL的路径
fn get_dll_path() -> Result<String, String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("无法获取当前执行文件路径: {}", e))?;
    
    let exe_dir = exe_path.parent()
        .ok_or("无法获取执行文件目录")?;
    
    let dll_path = exe_dir.join("xinput_hook.dll");
    
    if !dll_path.exists() {
        return Err(format!(
            "DLL文件不存在: {}。请先编译DLL库。", 
            dll_path.display()
        ));
    }
    
    Ok(dll_path.to_string_lossy().to_string())
}

// 使用经典的DLL注入技术
fn inject_dll_into_process(process_handle: HANDLE, dll_path: &str) -> Result<(), String> {
    unsafe {
        let kernel32 = LoadLibraryA(CString::new("kernel32.dll").unwrap().as_ptr());
        if kernel32 == null_mut() {
            return Err("无法加载kernel32.dll".to_string());
        }

        let load_library_addr = GetProcAddress(
            kernel32, 
            CString::new("LoadLibraryA").unwrap().as_ptr()
        );
        if load_library_addr == null_mut() {
            return Err("无法找到LoadLibraryA函数".to_string());
        }

        // 在目标进程中分配内存
        let dll_path_bytes = dll_path.as_bytes();
        let mem_size = dll_path_bytes.len() + 1; // +1 for null terminator
        
        let allocated_mem = VirtualAllocEx(
            process_handle,
            null_mut(),
            mem_size,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        
        if allocated_mem == null_mut() {
            return Err(format!("VirtualAllocEx失败，错误代码: {}", GetLastError()));
        }

        // 写入DLL路径
        let mut bytes_written = 0;
        let write_result = WriteProcessMemory(
            process_handle,
            allocated_mem,
            dll_path_bytes.as_ptr() as *const _,
            dll_path_bytes.len(),
            &mut bytes_written,
        );

        if write_result == FALSE {
            VirtualFreeEx(process_handle, allocated_mem, 0, MEM_RELEASE);
            return Err(format!("WriteProcessMemory失败，错误代码: {}", GetLastError()));
        }

        // 写入null终止符
        let null_byte: u8 = 0;
        WriteProcessMemory(
            process_handle,
            (allocated_mem as usize + dll_path_bytes.len()) as *mut _,
            &null_byte as *const _ as *const _,
            1,
            &mut bytes_written,
        );

        // 创建远程线程执行LoadLibraryA
        let thread_handle = CreateRemoteThread(
            process_handle,
            null_mut(),
            0,
            Some(std::mem::transmute(load_library_addr)),
            allocated_mem,
            0,
            null_mut(),
        );

        if thread_handle == null_mut() {
            VirtualFreeEx(process_handle, allocated_mem, 0, MEM_RELEASE);
            return Err(format!("CreateRemoteThread失败，错误代码: {}", GetLastError()));
        }        // 等待线程完成
        WaitForSingleObject(thread_handle, INFINITE);
        
        // 清理
        CloseHandle(thread_handle);
        VirtualFreeEx(process_handle, allocated_mem, 0, MEM_RELEASE);

        Ok(())
    }
}

// 显示进程列表并让用户选择
fn display_and_select_processes(processes: &[GameProcess]) -> Option<usize> {
    if processes.is_empty() {
        println!("❌ 未检测到任何游戏进程");
        println!("\n支持的游戏类型:");
        println!("  • Unreal Engine (UE4/UE5) 游戏");
        println!("  • Unity 游戏");
        println!("  • 其他使用XInput的游戏");
        return None;
    }

    println!("\n🎮 检测到以下游戏进程:");
    println!("{:-<60}", "");
    println!("{:<4} {:<8} {:<30}", "编号", "PID", "进程名称");
    println!("{:-<60}", "");
    
    for (index, process) in processes.iter().enumerate() {
        println!("{:<4} {:<8} {:<30}", 
                 index + 1, 
                 process.pid, 
                 process.name);
    }
    
    println!("{:-<60}", "");
    println!("💡 提示: 输入进程编号开始注入，输入 0 退出程序");
    print!("\n请选择要注入的进程编号: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            match input.trim().parse::<usize>() {
                Ok(0) => {
                    println!("👋 程序已退出");
                    std::process::exit(0);
                }
                Ok(num) if num > 0 && num <= processes.len() => {
                    Some(num - 1)
                }
                _ => {
                    println!("❌ 无效的选择，请输入有效的编号");
                    None
                }
            }
        }
        Err(_) => {
            println!("❌ 读取输入失败");
            None
        }
    }
}

// 等待用户按键继续
fn wait_for_user_input(message: &str) {
    println!("\n{}", message);
    print!("按 Enter 键继续...");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
}

// 持续监控震动的循环
fn start_vibration_monitoring(process: &GameProcess) {
    println!("\n🚀 开始监控进程: {} (PID: {})", process.name, process.pid);
    println!("💡 提示: 按 Ctrl+C 停止监控并退出程序");
    
    // 监控循环
    let mut last_check = std::time::Instant::now();
    loop {
        // 每5秒检查一次进程是否还存在
        if last_check.elapsed() >= Duration::from_secs(5) {
            unsafe {
                let handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process.pid);
                if handle == null_mut() {
                    println!("\n❌ 目标进程已结束: {} (PID: {})", process.name, process.pid);
                    println!("程序将退出...");
                    std::process::exit(1);
                }
                
                let mut exit_code = 0;
                let still_running = winapi::um::processthreadsapi::GetExitCodeProcess(
                    handle, 
                    &mut exit_code
                ) == TRUE && exit_code == 259; // STILL_ACTIVE = 259
                
                CloseHandle(handle);
                
                if !still_running {
                    println!("\n❌ 目标进程已结束: {} (PID: {})", process.name, process.pid);
                    println!("程序将退出...");
                    std::process::exit(1);
                }
            }
            
            last_check = std::time::Instant::now();
        }
        
        thread::sleep(Duration::from_millis(100));
    }
}

// 设置控制台标题和样式
fn setup_console() {
    unsafe {
        let title = CString::new("TrueGear XInput Driver").unwrap();
        SetConsoleTitleA(title.as_ptr());
    }
}
