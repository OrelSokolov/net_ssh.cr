# Oracle spec: оффлайн-кейсы net-ssh 7.3 + bcrypt_pbkdf (см. oracle/cases.rb).
# Live-кейсы — spec/live_spec.cr (SSH_ORACLE_LIVE=1).

require "spec"
require "../src/net_ssh_cr"

EXPECTED = begin
  hash = {} of String => String
  File.read("#{__DIR__}/../oracle/expected.yml").each_line do |line|
    if line.includes?('\t')
      id, value = line.split('\t', 2)
      hash[id] = value.chomp
    end
  end
  hash
end

def check(id, value)
  (EXPECTED[id]? || "MISSING #{id}").should eq value.to_s
end

FIX = "#{__DIR__}/../oracle/fixtures"

describe "net_ssh oracle (оффлайн)" do
  it "rsa pub fingerprints" do
    key = Net::SSH::SSHKey.load_public_key("#{FIX}/id_rsa.pub")
    check "rsa_pub_type", key.ssh_type
    check "rsa_fp_md5", key.fingerprint_md5
    check "rsa_fp_sha256", key.fingerprint_sha256
    check "rsa_bits", key.bits
  end

  it "ed25519 pub fingerprints" do
    key = Net::SSH::SSHKey.load_public_key("#{FIX}/id_ed25519.pub")
    check "ed25519_pub_type", key.ssh_type
    check "ed25519_fp_md5", key.fingerprint_md5
    check "ed25519_fp_sha256", key.fingerprint_sha256
    check "ed25519_ssh_keygen_l", key.ssh_keygen_l
  end

  it "rsa private (PEM PKCS#1)" do
    key = Net::SSH::SSHKey.load_private_key("#{FIX}/id_rsa")
    check "rsa_type", key.ssh_type
    check "rsa_bits", key.bits
    check "rsa_fp_md5", key.fingerprint_md5
  end

  it "ed25519 private (openssh-key-v1, без шифрования)" do
    key = Net::SSH::SSHKey.load_private_key("#{FIX}/id_ed25519")
    check "ed25519_type", key.ssh_type
    check "ed25519_fp_md5", key.fingerprint_md5
  end

  it "ed25519 private зашифрованный (bcrypt_pbkdf + aes256-ctr)" do
    key = Net::SSH::SSHKey.load_private_key("#{FIX}/id_ed25519_enc", "oracle-pass-123")
    check "ed25519_enc_type", key.ssh_type
    check "ed25519_enc_fp_md5", key.fingerprint_md5
    # fingerprint приватного совпадает с fingerprint соответствующего .pub
    pub = Net::SSH::SSHKey.load_public_key("#{FIX}/id_ed25519_enc.pub")
    key.fingerprint_md5.should eq pub.fingerprint_md5
    # неверный пароль / отсутствие пароля — ArgumentError
    expect_raises ArgumentError do
      Net::SSH::SSHKey.load_private_key("#{FIX}/id_ed25519_enc", "wrong")
    end
    expect_raises ArgumentError do
      Net::SSH::SSHKey.load_private_key("#{FIX}/id_ed25519_enc")
    end
  end

  it "bcrypt_pbkdf векторы (гем bcrypt_pbkdf 1.1 = OpenBSD)" do
    check "pbkdf_v1", Net::SSH::BCryptPbkdf.pbkdf2("password", "salt", 32, 16).hexstring
    check "pbkdf_v2", Net::SSH::BCryptPbkdf.pbkdf2("троллейбус", "соль1234" * 3, 48, 8).hexstring
    check "pbkdf_v3", Net::SSH::BCryptPbkdf.pbkdf2("a", "0123456789abcdef0123456789abcdef", 64, 16).hexstring
  end
end
