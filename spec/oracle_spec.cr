# Oracle spec: оффлайн-кейсы net-ssh 7.3 (см. oracle/cases.rb). Live-кейсы
# (SSH_ORACLE_LIVE=1) — когда поднимем localhost sshd.

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
end
