# net_ssh_cr — порт net-ssh (7.3) API поверх libssh2.
#
# 1:1 к call-сайтам ~/qp2/website (app/services/vpn/*):
#   Net::SSH.start(host, user, port: 22, keys: [...]) do |ssh|
#     out = ssh.exec!("cmd")
#     ssh.exec("cmd") { |bytes, is_stderr| ... }
#     ssh.channel { |ch| ch.command("..."); ... }
#   end
#
# Аутентификацию выполняет libssh2 (publickey/password).

require "ssh2"
require "./net_ssh/ssh_key"

module Net
  module SSH
    VERSION = "7.3.0.cr"

    # Обёртка над SSH2::Session с net-ssh-подобным API.
    class Session
      getter ssh2 : SSH2::Session

      def initialize(@ssh2 : SSH2::Session)
      end

      # net-ssh: ssh.exec!("cmd") → "stdout" (stderr отбрасывается).
      # Здесь (как в ssh.cr): кортеж {stdout, exit_status}.
      def exec!(command : String) : {String, Int32}
        channel = @ssh2.open_session
        channel.command(command)
        output = IO::Memory.new
        buffer = Bytes.new(4096)
        loop do
          n = channel.read(buffer)
          break if n.zero? || channel.eof?
          output.write(buffer[0, n])
        end
        status = channel.exit_status || 0
        channel.close
        {output.to_s, status}
      end

      # net-ssh: ssh.exec("cmd") { |data, channel| } — стримингово.
      def exec(command : String, &block : Bytes, Bool -> _) : Nil
        channel = @ssh2.open_session
        channel.command(command)
        buffer = Bytes.new(4096)
        loop do
          n = channel.read(buffer)
          break if n.zero? || channel.eof?
          yield buffer[0, n], false
        end
        channel.close
      end

      # Низкоуровневый канал (libssh2-direct).
      def channel(&block : SSH2::Channel -> _)
        ch = @ssh2.open_session
        yield ch
        ch.close
      end

      def close
        @ssh2.disconnect
      end
    end

    # Net::SSH.start — блок-форма (auto-close) и безблочная.
    def self.start(host : String, user : String, port : Int32 = 22,
                   keys : Array(String) = [] of String,
                   password : String? = nil,
                   timeout : Float64? = nil,
                   &block : Session -> _)
      session = start(host, user, port: port, keys: keys, password: password, timeout: timeout)
      begin
        yield session
      ensure
        session.close
      end
    end

    def self.start(host : String, user : String, port : Int32 = 22,
                   keys : Array(String) = [] of String,
                   password : String? = nil,
                   timeout : Float64? = nil) : Session
      raw = SSH2::Session.connect(host, port)
      # Конструктор SSH2::Session уже делает handshake.
      if key = keys.first?
        # libssh2 ждёт приватный и публичный ключ ("<priv>.pub" рядом).
        raw.login_with_pubkey(user, key, key + ".pub")
      elsif pw = password
        raw.login(user, pw)
      else
        raise ArgumentError.new("net-ssh: no auth method (keys: or password:)")
      end
      Session.new(raw)
    end

    # Net::SSH::KeyFactory — парсинг ключей (см. net_ssh/ssh_key.cr).
    module KeyFactory
      def self.load_public_key(path : String) : SSHKey
        SSHKey.load_public_key(path)
      end
    end
  end
end
