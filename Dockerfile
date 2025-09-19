FROM debian:bookworm

COPY ./target/release/libpam_sshd_oom.so /usr/local/lib/x86_64-linux-gnu/security/pam_sshd_oom.so
COPY ./target/release/libpam_sshd_oom.so /usr/lib/x86_64-linux-gnu/security/pam_sshd_oom.so

RUN apt update && apt install -y openssh-server

RUN echo "session optional        pam_sshd_oom.so   999" >> /etc/pam.d/common-session

ENTRYPOINT [ "/usr/bin/bash" ]