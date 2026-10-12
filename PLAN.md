# net_ssh.cr — порт net-ssh (7.3) API на Crystal

> ⚠️ КАРКАС. Транспорт выбран, oracle-кейсы сняты с настоящего net-ssh,
> реализация — итерациями.

## Контекст

`~/qp2/website` использует `net-ssh 7.3` + `net-scp` + `sshkey` + `ed25519` +
`bcrypt_pbkdf` (~20 файлов в `app/services/vpn/*`: deploy/redeploy/verify
orchestrators, systemd_manager, health_checker). Нужен 1:1-совместимый слой,
чтобы порт сайта не переписывал call-сайты.

## Транспорт (выбор сделан)

**libssh2** через [spider-gazelle/ssh2.cr](https://github.com/spider-gazelle/ssh2.cr)
(1.8.0, собирается на Crystal 1.21):
- `SSH2::Session.connect/login_with_pubkey`, `Channel#command/read/exit_status`,
  SFTP-модуль — достаточно для net-ssh-совместимого слоя;
- заголовки и lib в системе (`/usr/include/libssh2.h`, `libssh2.so.1`).

Первоначально пробовали 84codes/ssh.cr (libssh) — **не собирается** на
Crystal 1.21 (`TCPSocket#wait_readable` удалён из API). Зафиксировано как
альтернатива на случай блокеров по libssh2.

## API 1:1 (net-ssh → net_ssh_cr)

- `Net::SSH.start(host, user, port: 22, keys: [...], password:, timeout:, ...)`
  → `SSH.open(...)`-сессия; блок-форма с auto-close
- `ssh.exec!("cmd")` → `(stdout, exit_status)` — как `SSH#exec!`
- `ssh.exec("cmd") { |bytes, is_stderr| }` — стриминговый
- `ssh.channel { |ch| ... }` — ch.exec/puts/eof!/wait/exit_status/on_data
- `Net::SCP` — `ssh.scp.upload!(local, remote)` / `download!` —
  через sftp-канал libssh (в ssh.cr есть SFTP? проверить; иначе libssh2-sftp
  из ssh2.cr или channel exec `cat > path`)
- `Net::SSH::KeyFactory.load(path)` — парсинг PEM/openssh-ключей
- `Net::SSH::Authentication::*` — не портируется отдельными сущностями:
  libssh сам делает auth (publickey/password) — флагами в start()

## Отдельные мелкие порты

- `SSHKey` (гем sshkey ~3.0): генерация ed25519/RSA-пар, fingerprints
  (MD5 `ssh-keygen -l`-формат), парсинг pub-строк — чистая логика, без libssh.
- `bcrypt_pbkdf` — нужен для зашифрованных ed25519-ключей (openssh
  private format); вариант: bcrypt-ядро из shard `bcrypt` + pbkdf2-обвязка
  (stdlib `Crypto`? нет —pbkdf2 вручную, ~30 строк HMAC-SHA256… но openssh
  использует pbkdf2 c bcrypt-PRF — нужна своя реализация).

## Oracle (AGENTS.md, oracle-first)

`oracle/cases.rb` гоняет настоящий `net-ssh 7.3` (стоит в rvm):
- **оффлайн-кейсы** (детерминированные, всегда): KeyFactory.load фикстурных
  ключей, fingerprints, pub-форматирование — `oracle/expected.yml` уже снят;
- **live-кейсы** (нужен localhost sshd + сгенерённый тестовый ключ,
  `SSH_ORACLE_LIVE=1`): exec round-trip, scp upload/download —
  в expected.yml не входят, гоняются port'ом против реального sshd.

## Статус

- [x] транспорт выбран, shard.yml
- [x] oracle оффлайн-кейсы + expected.yml (вкл. pbkdf-векторы и зашифрованный
      ed25519: 15 кейсов, 6/6 групп в spec)
- [x] `SSHKey`: fingerprints/pub-парсер + `load_private_key` (PEM RSA через
      собственный DER-парсер — `OpenSSL::PKey` из stdlib удалён; openssh-key-v1,
      вкл. зашифрованные: bcrypt_pbkdf + aes*-ctr/cbc)
- [x] обёртка Session (start/exec!/exec/channel, passphrase:, перебор ключей,
      .pub рядом с ключом опционален — pubkey выводится libssh2)
- [x] SCP/SFTP: `ssh.scp.upload!(local, remote)` / `download!(remote, local=nil
      → в память)` поверх libssh2 scp (файлы; каталоги не поддержаны — сайту
      не нужны), class-level `Net::SCP.upload!/download!`
- [x] live-интеграция против localhost sshd: userspace-sshd БЕЗ root
      (`oracle/live_sshd.sh`: apt-get download openssh-server → dpkg -x →
      патч зашитых путей sshd-session/sshd-auth на /tmp/.lssh → unprivileged
      sshd на 127.0.0.1:2222). Прогнано: ruby-oracle live (exec ×2, scp
      round-trip) + crystal live_spec (exec, scp upload/download ×2, auth
      зашифрованным ключом с passphrase) — все зелёные
- [x] bcrypt_pbkdf: порт OpenBSD blowfish.c + bcrypt_pbkdf.c
      (`src/net_ssh/blowfish_tables.cr` — таблицы сгенерированы из C,
      `src/net_ssh/bcrypt_pbkdf.cr`); векторы против гема bcrypt_pbkdf 1.1
      совпадают байт-в-байт (в expected.yml)

## Известные ограничения

- зашифрованные PEM RSA (Proc-Type: 4,ENCRYPTED) не читаются — openssh-формат
  поддержан, PEM нужен незашифрованный (как в фикстурах сайта);
- scp — только файлы (без рекурсии каталогов), sftp-подсистема — через
  `ssh2.sftp_session` при необходимости;
- `exec`-callback: stderr не стримится (is_stderr всегда false) — в call-сайтах
  сайта не используется.
