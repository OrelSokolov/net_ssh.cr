# net_ssh_cr — порт net-ssh (7.3) API поверх libssh2.
#
# 1:1 к call-сайтам ~/qp2/website (app/services/vpn/*):
#   Net::SSH.start(host, user, port: 22, keys: [...], passphrase:) do |ssh|
#     out = ssh.exec!("cmd")
#     ssh.exec("cmd") { |bytes, is_stderr| ... }
#     ssh.channel { |ch| ... }
#     ssh.scp.upload!(local, remote) / ssh.scp.download!(remote)
#   end
#
# Аутентификацию выполняет libssh2 (publickey/password); зашифрованные
# openssh-ключи расшифровываются bcrypt_pbkdf (Net::SSH::KeyFactory).

require "ssh2"
require "./net_ssh/ssh_key"
require "./net_ssh/bcrypt_pbkdf"
require "./net_ssh/scp"

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
        # libssh2 отдаёт данные до возврата 0 (EOF), поэтому выходим только
        # по n == 0 — eof может прийти вместе с последним куском данных.
        loop do
          n = channel.read(buffer)
          break if n.zero?
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
          break if n.zero?
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

      # net-scp: ssh.scp.upload!(local, remote) / ssh.scp.download!(remote)
      def scp : SCP::SessionWrapper
        SCP::SessionWrapper.new(self)
      end

      def close
        @ssh2.disconnect
      end
    end

    # Net::SSH.start — блок-форма (auto-close) и безблочная.
    def self.start(host : String, user : String, port : Int32 = 22,
                   keys : Array(String) = [] of String,
                   password : String? = nil,
                   passphrase : String? = nil,
                   timeout : Float64? = nil,
                   &block : Session -> _)
      session = start(host, user, port: port, keys: keys, password: password,
        passphrase: passphrase, timeout: timeout)
      begin
        yield session
      ensure
        session.close
      end
    end

    def self.start(host : String, user : String, port : Int32 = 22,
                   keys : Array(String) = [] of String,
                   password : String? = nil,
                   passphrase : String? = nil,
                   timeout : Float64? = nil) : Session
      raw = SSH2::Session.connect(host, port)
      # Конструктор SSH2::Session уже делает handshake.
      errors = [] of ::Exception
      keys.each do |key|
        # libssh2 сам парсит PEM/openssh-форматы и расшифровывает ключи
        # по passphrase; .pub-файл рядом с ключом не обязателен (публичная
        # часть выводится из приватного ключа).
        pub_path = key + ".pub"
        pubkey = File.exists?(pub_path) ? File.read(pub_path) : ""
        begin
          raw.login_with_data(user, File.read(key), pubkey, passphrase)
          return Session.new(raw) if raw.authenticated?
        rescue ex : SSH2::SSH2Error
          errors << ex
        end
      end
      if pw = password
        begin
          raw.login(user, pw)
          return Session.new(raw) if raw.authenticated?
        rescue ex : SSH2::SSH2Error
          errors << ex
        end
      end
      raw.disconnect
      if errors.empty?
        raise ArgumentError.new("net-ssh: no auth method (keys: or password:)")
      else
        raise errors.last
      end
    end

    # Net::SSH::KeyFactory — парсинг ключей (см. net_ssh/ssh_key.cr).
    module KeyFactory
      def self.load_public_key(path : String) : SSHKey
        SSHKey.load_public_key(path)
      end

      # net-ssh: KeyFactory.load_private_key(path, passphrase = nil) —
      # openssh-key-v1 (в т.ч. зашифрованный bcrypt_pbkdf) и PEM RSA.
      def self.load_private_key(path : String, passphrase : String? = nil) : SSHKey
        SSHKey.load_private_key(path, passphrase)
      end
    end
  end
end
