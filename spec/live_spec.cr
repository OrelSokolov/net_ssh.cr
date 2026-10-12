# Live spec: round-trip против реального localhost sshd.
# Запуск: нужен sshd на порту SSH_ORACLE_PORT (default 22) и ключ
# oracle/fixtures/id_ed25519 в authorized_keys — тогда
#   SSH_ORACLE_LIVE=1 [SSH_ORACLE_PORT=2222] crystal spec spec/live_spec.cr
# Живые значения не входят в oracle/expected.yml: ожидания фиксированы
# (echo ok → "ok"), scp проверяется round-trip'ом.

require "spec"
require "../src/net_ssh_cr"

live = ENV["SSH_ORACLE_LIVE"]?
port = (ENV["SSH_ORACLE_PORT"]? || "22").to_i
FIXDIR = "#{__DIR__}/../oracle/fixtures"

if live
  describe "net_ssh live (localhost sshd :#{port})" do
    it "exec round-trip" do
      Net::SSH.start("localhost", ENV["USER"]? || "oleg",
        port: port, keys: ["#{FIXDIR}/id_ed25519"]) do |ssh|
        out, status = ssh.exec!("echo ok")
        out.strip.should eq "ok"
        status.should eq 0
        out2, _st = ssh.exec!("printf '%s-%s' a b")
        out2.should eq "a-b"
      end
    end

    it "scp upload!/download! round-trip" do
      Net::SSH.start("localhost", ENV["USER"]? || "oleg",
        port: port, keys: ["#{FIXDIR}/id_ed25519"]) do |ssh|
        local = "#{FIXDIR}/id_rsa.pub"
        remote = "/tmp/netssh_live_#{Process.pid}.pub"
        ssh.scp.upload!(local, remote)
        # скачивание в память
        ssh.scp.download!(remote).should eq File.read(local)
        # скачивание в файл
        tmp = "/tmp/netssh_live_#{Process.pid}.down"
        ssh.scp.download!(remote, tmp)
        File.read(tmp).should eq File.read(local)
        File.delete(tmp)
        ssh.exec!("rm -f #{remote}")
      end
    end

    it "auth зашифрованным ключом (passphrase)" do
      Net::SSH.start("localhost", ENV["USER"]? || "oleg",
        port: port, keys: ["#{FIXDIR}/id_ed25519_enc"],
        passphrase: "oracle-pass-123") do |ssh|
        out, _st = ssh.exec!("echo enc-ok")
        out.strip.should eq "enc-ok"
      end
    end
  end
end
