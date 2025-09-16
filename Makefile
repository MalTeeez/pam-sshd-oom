all:
	cargo build --release
	gcc ./cstuffs/main.c -L./target/release -lpam_sshd_oom -Wl,-rpath=./target/release -o main