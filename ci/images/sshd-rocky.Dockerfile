# Integration-test sshd: bash as /bin/sh, GNU coreutils, RHEL sshd + PAM.
# Built by scripts/integration.sh; host keys are generated at container start.
# Without a login session manager pam_loginuid fails the session in a
# container, so it is made optional (the standard container fix).
FROM rockylinux/rockylinux:10.2@sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834
RUN dnf -y install openssh-server shadow-utils && dnf clean all \
 && rm -f /etc/ssh/ssh_host_* \
 && sed -i 's/^session[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd
