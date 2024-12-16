# rustlualoader


Blog post: [Embedding Lua into Rust](https://www.synercomm.com/blog/evading-defender-by-embedding-lua-into-rust/)


## Usage:
1. [XOR encrypt](https://github.com/djackreuter/shellcode-encryption) your shellcode and place the raw shellcode file into src/sc.bin.
2. Update `local key` on line 77 with your decryption key.
3. Compile with `cargo build -r`
4. ???
5. Profit
