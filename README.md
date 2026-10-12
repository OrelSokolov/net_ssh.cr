# net_ssh.cr

A Crystal port of the **net-ssh 7.3** API over **libssh2**
([spider-gazelle/ssh2.cr](https://github.com/spider-gazelle/ssh2.cr)),
plus ports of the `sshkey` gem (key parsing/fingerprints) and OpenBSD's
`bcrypt_pbkdf` (for encrypted OpenSSH keys). The goal is a 1:1-compatible
layer so Ruby call-sites (`Net::SSH.start`, `ssh.exec!`, `ssh.scp`)
port without rewrites. Verified by an offline oracle against real
net-ssh 7.3 and by live integration tests against an unprivileged
localhost sshd.

> ⚠️ EXPERIMENTAL — DO NOT USE IN PRODUCTION YET.

## Installation

```yaml
dependencies:
  net_ssh_cr:
    github: OrelSokolov/net_ssh.cr
```

```sh
shards install
```

Requires libssh2 headers/library in the system
(`/usr/include/libssh2.h`, `libssh2.so.1`).

## Usage

```crystal
Net::SSH.start("host", "user", keys: ["~/.ssh/id_ed25519"]) do |ssh|
  stdout, exit_status = ssh.exec!("uptime")

  ssh.exec("tail -f log") do |bytes, is_stderr|
    print bytes
  end

  ssh.channel do |ch|
    ch.exec("ls -la")
    ch.puts "input"
    ch.eof!
    ch.wait
    ch.exit_status
  end
end

# SCP
ssh.scp.upload!("local.txt", "/remote/path.txt")
data = ssh.scp.download!("/remote/path.txt")   # in memory
Net::SCP.upload!("host", "user", "local", "/remote", keys: [...])

# Keys
key = Net::SSH::KeyFactory.load("~/.ssh/id_ed25519", passphrase: "secret")
key.fingerprint   # MD5 ssh-keygen -l format
```

## Feature comparison vs net-ssh 7.3 (+ net-scp, sshkey, bcrypt_pbkdf)

| Feature | Original (net-ssh) | Port (net_ssh_cr) | Status |
|---|---|---|---|
| `Net::SSH.start(host, user, port:, keys:, password:, timeout:, ...)` + block form with auto-close | ✅ | Session wrapper over libssh2; `passphrase:`, key-list iteration, optional adjacent `.pub` (pubkey comes from libssh2) | ✅ |
| `ssh.exec!("cmd")` → `(stdout, exit_status)` | ✅ | Same | ✅ |
| `ssh.exec("cmd") { \|bytes, is_stderr\| }` streaming | ✅ | stderr is not streamed (`is_stderr` always false — not used by the target call-sites) | 🔶 |
| `ssh.channel { \|ch\| }` — exec/puts/eof!/wait/exit_status/on_data | ✅ | Same | ✅ |
| Auth (publickey/password) | ✅ separate session entities | Handled by libssh2 itself — flags in `start()` | 🔶 |
| `Net::SCP` — `upload!` / `download!` | ✅ (files + directories) | Files only (no recursive directories) over libssh2 scp; class-level `Net::SCP.upload!/download!`; sftp subsystem available via `ssh2.sftp_session` | 🔶 |
| `Net::SSH::KeyFactory.load(path)` — PEM/OpenSSH keys | ✅ | Own DER parser for PEM RSA (stdlib `OpenSSL::PKey` is gone), openssh-key-v1 incl. **encrypted** keys (bcrypt_pbkdf + aes*-ctr/cbc) | ✅ |
| Encrypted PEM RSA (`Proc-Type: 4,ENCRYPTED`) | ✅ | Not readable — unencrypted PEM only (as the target site's fixtures use) | ❌ |
| `SSHKey` (gem sshkey ~3.0): ed25519/RSA pair generation, fingerprints (MD5 `-l` format), pub-string parsing | ✅ | Pure logic, no libssh | ✅ |
| `bcrypt_pbkdf` (gem 1.1) | ✅ | Port of OpenBSD blowfish.c + bcrypt_pbkdf.c; vectors match the gem byte-for-byte (in expected.yml) | ✅ |

## Deviations & notes

- Transport: libssh2 via ssh2.cr 1.8.0 (84codes/ssh.cr on libssh was
  tried first — does not build on Crystal 1.21, `TCPSocket#wait_readable`
  removed).
- Live testing without root: `oracle/live_sshd.sh` unpacks a userspace
  openssh-server (apt-get download + dpkg -x, paths patched to /tmp/.lssh)
  and runs an unprivileged sshd on 127.0.0.1:2222.

## Testing

```sh
crystal spec          # offline oracle cases (fixtures, pbkdf vectors)
SSH_ORACLE_LIVE=1 ... # live cases against localhost sshd (oracle/live_sshd.sh)
```

Oracle: offline deterministic cases (KeyFactory on fixture keys,
fingerprints, pub formatting) recorded with the real net-ssh 7.3 into
`oracle/expected.yml` — 15 cases, 6/6 spec groups. Live cases (exec
round-trip, scp upload/download, auth with an encrypted key + passphrase)
are run by `spec/live_spec.cr` against the unprivileged sshd and skip
when no server is available.
