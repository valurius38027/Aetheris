use aetheris_ffi::*;
use std::ffi::CString;

fn main() {
    println!("Testing Aetheris Backend...");
    
    let db_path = "test_vault_cli";
    let c_db_path = CString::new(db_path).unwrap();
    
    println!("Starting node at {}...", db_path);
    let res = aetheris_start_node(10005, c_db_path.as_ptr());
    println!("aetheris_start_node result: {}", res);
    
    let initialized = aetheris_is_initialized();
    println!("Wallet initialized: {}", initialized);
    
    if !initialized {
        println!("Creating new wallet...");
        let created = aetheris_create_wallet();
        println!("Wallet created: {}", created);
    }
    
    println!("Getting node status...");
    let status_bin = aetheris_get_node_status_bin();
    if status_bin.len > 0 {
        let json_data = unsafe {
            let slice = std::slice::from_raw_parts(status_bin.ptr, status_bin.len);
            String::from_utf8_lossy(slice).to_string()
        };
        println!("Node Status: {}", json_data);
    }
    
    println!("Backend test completed successfully!");
}
