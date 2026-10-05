# SSHKey — порт гемов sshkey/net-ssh KeyFactory (оффлайн-часть):
# fingerprints pub-ключей в форматах ssh-keygen (MD5 hex, SHA256 base64),
# без обращения к libssh: чистый base64+digest.

require "base64"
require "digest"

module Net
  module SSH
    class SSHKey
      getter ssh_type : String
      getter blob : Bytes
      getter comment : String?

      # Из pub-файла или pub-строки "ssh-ed25519 AAAA... comment".
      def self.load_public_key(path : String) : SSHKey
        parse(File.read(path).strip)
      end

      def self.parse(pub_line : String) : SSHKey
        parts = pub_line.split
        raise ArgumentError.new("bad public key line") if parts.size < 2
        new(parts[0], Base64.decode(parts[1]), parts[2..].join(" ".presence || " "))
      end

      def initialize(@ssh_type : String, @blob : Bytes, @comment : String? = nil)
      end

      # ssh-keygen -l (MD5): "0b:20:6a:..."
      def fingerprint_md5 : String
        Digest::MD5.hexdigest(@blob).scan(/../).join(":")
      end

      # ssh-keygen -l (SHA256, без префикса): base64 (std, без паддинга убирать
      # не нужно — ssh-keygen оставляет "=")
      def fingerprint_sha256 : String
        Base64.strict_encode(Digest::SHA256.digest(@blob))
      end

      # Полная строка "256 SHA256:... comment"
      def ssh_keygen_l : String
        "#{bits} SHA256:#{fingerprint_sha256} #{@comment}"
      end

      def bits : Int32
        case @ssh_type
        when "ssh-ed25519" then 256
        when "ssh-rsa"
          # blob: string "ssh-rsa", mpint e, mpint n — mpint несёт знаковый
          # 0x00-байт спереди; bits = позиция старшего бита
          io = IO::Memory.new(@blob)
          read_string(io) # type
          read_string(io) # e
          n = read_string(io)
          stripped = [] of UInt8
          started = false
          n.each do |byte|
            started = true if byte != 0
            stripped << byte if started
          end
          stripped.size * 8 - stripped[0].leading_zeros_count
        else
          raise ArgumentError.new("unsupported key type: #{@ssh_type}")
        end
      end

      private def read_string(io : IO) : Bytes
        size = UInt32.new(io.read_bytes(UInt32, IO::ByteFormat::BigEndian))
        data = Bytes.new(size)
        io.read_fully(data)
        data
      end

      def self.load_private_key(path : String)
        # Каркас: приватный ключ передаётся libssh по пути (SSH.open внутри
        # libssh сам парсит PEM/openssh). Здесь — только pub-side логика.
        raise NotImplementedError.new("private key parsing is delegated to libssh (pass path via keys:) — use load_public_key for offline data")
      end
    end
  end
end
