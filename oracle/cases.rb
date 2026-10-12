#!/usr/bin/env ruby
# Oracle cases for net_ssh.cr — порт net-ssh 7.3.
#
# Оффлайн-кейсы (детерминированные, фикстурные ключи в oracle/fixtures):
#   ruby oracle/cases.rb > oracle/expected.yml
#
# Live-кейсы (нужен localhost sshd, ключ oracle/fixtures/id_ed25519 в
# authorized_keys): SSH_ORACLE_LIVE=1 [SSH_ORACLE_PORT=2222] — в expected.yml
# не входят, гоняются портом против реального sshd при наличии.

gem "net-ssh", "= 7.3.0"
gem "bcrypt_pbkdf", "= 1.1.1"
require "net/ssh"
require "bcrypt_pbkdf"
require "base64"
require "digest"

FIX = File.expand_path("fixtures", __dir__)

def case_run(id, value)
  puts "#{id}\t#{value}"
end

def fp_md5(pubkey)
  blob = Base64.decode64(pubkey.split[1])
  Digest::MD5.hexdigest(blob).scan(/../).join(":")
end

def fp_sha256(pubkey)
  blob = Base64.decode64(pubkey.split[1])
  [Digest::SHA256.digest(blob)].pack("m0").chomp
end

rsa_pub    = File.read(File.join(FIX, "id_rsa.pub")).strip
ed25519_pub = File.read(File.join(FIX, "id_ed25519.pub")).strip

# --- KeyFactory.load / fingerprints ----------------------------------------

rsa_key = Net::SSH::KeyFactory.load_private_key(File.join(FIX, "id_rsa"))
case_run "rsa_type", rsa_key.ssh_type
case_run "rsa_bits", rsa_key.n.num_bits

ed_key = Net::SSH::KeyFactory.load_private_key(File.join(FIX, "id_ed25519"))
case_run "ed25519_type", ed_key.ssh_type
case_run "ed25519_fp_md5", ed_key.public_key.fingerprint

# Зашифрованный ed25519 (openssh private format, kdf=bcrypt, aes256-ctr)
enc_key = Net::SSH::KeyFactory.load_private_key(
  File.join(FIX, "id_ed25519_enc"), "oracle-pass-123")
case_run "ed25519_enc_type", enc_key.ssh_type
case_run "ed25519_enc_fp_md5", enc_key.public_key.fingerprint

case_run "rsa_pub_type", rsa_pub.split[0]
case_run "rsa_fp_md5", fp_md5(rsa_pub)
case_run "rsa_fp_sha256", fp_sha256(rsa_pub)
case_run "ed25519_pub_type", ed25519_pub.split[0]
case_run "ed25519_fp_md5", fp_md5(ed25519_pub)
case_run "ed25519_fp_sha256", fp_sha256(ed25519_pub)

# ssh-keygen -l формат
case_run "ed25519_ssh_keygen_l", "256 SHA256:#{fp_sha256(ed25519_pub)} oracle@test"

# --- bcrypt_pbkdf (векторы против гема bcrypt_pbkdf 1.1 = OpenBSD) ----------

case_run "pbkdf_v1", BCryptPbkdf.key("password", "salt", 32, 16).unpack1("H*")
case_run "pbkdf_v2", BCryptPbkdf.key("троллейбус", "соль1234" * 3, 48, 8).unpack1("H*")
case_run "pbkdf_v3", BCryptPbkdf.key("a", "0123456789abcdef0123456789abcdef", 64, 16).unpack1("H*")

# --- Live (sshd) ------------------------------------------------------------
if ENV["SSH_ORACLE_LIVE"]
  port = (ENV["SSH_ORACLE_PORT"] || "22").to_i
  keys = [File.join(FIX, "id_ed25519")]
  Net::SSH.start("localhost", ENV["USER"], port: port, keys: keys) do |ssh|
    case_run "live_exec", ssh.exec!("echo ok").strip
    case_run "live_exec2", ssh.exec!("printf '%s-%s' a b")
  end

  # scp round-trip (net-scp 4.x, тот же API, что порт net_ssh/scp.cr)
  require "net/scp"
  Net::SSH.start("localhost", ENV["USER"], port: port, keys: keys) do |ssh|
    local = File.join(FIX, "id_rsa.pub")
    remote = "/tmp/netssh_oracle_#{Process.pid}.pub"
    ssh.scp.upload!(local, remote)
    case_run "live_scp_roundtrip", ssh.scp.download!(remote) == File.read(local) ? "ok" : "mismatch"
    ssh.exec!("rm -f #{remote}")
  end
end
