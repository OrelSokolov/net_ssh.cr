#!/usr/bin/env bash
# Поднять localhost sshd для live-кейсов net_ssh.cr БЕЗ root:
#   oracle/live_sshd.sh            # sshd на 127.0.0.1:2222 ( foreground )
#   SSH_ORACLE_LIVE=1 SSH_ORACLE_PORT=2222 crystal spec spec/live_spec.cr
#
# Как: apt-get download openssh-server (без root) → dpkg -x → патчим
# зашитые абсолютные пути /usr/lib/openssh/{sshd-session,sshd-auth} на
# /tmp/.lssh (система root-only, пишем туда нельзя) → sshd работает
# unprivileged (как в регресс-тестах самого OpenSSH). authorized_keys —
# публичные ключи фикстур oracle/fixtures.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=.live_sshd
PORT="${SSH_ORACLE_PORT:-2222}"
mkdir -p "$WORK" /tmp/.lssh
cd "$WORK"

if [ ! -x root/usr/sbin/sshd ]; then
  apt-get download openssh-server
  dpkg -x openssh-server_*.deb root
fi

cp root/usr/lib/openssh/sshd-session root/usr/lib/openssh/sshd-auth /tmp/.lssh/
python3 - <<'EOF'
for src in ["root/usr/sbin/sshd", "/tmp/.lssh/sshd-session", "/tmp/.lssh/sshd-auth"]:
    data = open(src, "rb").read()
    for old, new in [(b"/usr/lib/openssh/sshd-session", b"/tmp/.lssh/sshd-session"),
                     (b"/usr/lib/openssh/sshd-auth",    b"/tmp/.lssh/sshd-auth")]:
        data = data.replace(old, new + b"\x00" * (len(old) - len(new)))
    open(src, "wb").write(data)
EOF
chmod +x root/usr/sbin/sshd /tmp/.lssh/sshd-session /tmp/.lssh/sshd-auth

[ -f hostkey ] || ssh-keygen -t ed25519 -f hostkey -N '' -q

D=$(pwd)
cat > sshd_config <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $D/hostkey
PidFile $D/sshd.pid
AuthorizedKeysFile /home/oleg/myshards/net_ssh.cr/oracle/fixtures/authorized_test
StrictModes no
UsePAM no
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
LogLevel INFO
Subsystem sftp internal-sftp
EOF

echo "sshd on 127.0.0.1:$PORT (user $(id -un), no root)"
exec "$D/root/usr/sbin/sshd" -D -e -f sshd_config
