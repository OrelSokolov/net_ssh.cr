# SSHKey — порт гемов sshkey/net-ssh KeyFactory (оффлайн-часть):
# fingerprints pub-ключей в форматах ssh-keygen (MD5 hex, SHA256 base64),
# парсинг приватных ключей: PEM RSA (ASN.1/DER вручную — OpenSSL::PKey из
# stdlib удалён) и openssh private format v1 (в т.ч. зашифрованные:
# bcrypt_pbkdf + aes*-ctr/cbc). Без libssh: чистая логика.

require "base64"
require "digest"
require "openssl"
require "./bcrypt_pbkdf"

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
          SSHKey.read_string(io) # type
          SSHKey.read_string(io) # e
          n = SSHKey.read_string(io)
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

      # --- Приватные ключи ----------------------------------------------------

      # Net::SSH::KeyFactory.load_private_key(path, passphrase).
      # Поддержка: PEM RSA (PKCS#1/PKCS#8), openssh-key-v1 (ed25519 и др.;
      # kdf none/bcrypt). Как и в net-ssh, fingerprints считаются по
      # публичному блобу ключа.
      def self.load_private_key(path : String, passphrase : String? = nil) : SSHKey
        pem = File.read(path)
        case
        when pem.includes?("BEGIN OPENSSH PRIVATE KEY")
          load_openssh_key(pem, passphrase)
        when pem.includes?("BEGIN RSA PRIVATE KEY"), pem.includes?("BEGIN PRIVATE KEY")
          load_rsa_pem(pem)
        else
          raise ArgumentError.new("unsupported private key format: #{path}")
        end
      end

      private def self.load_rsa_pem(pem : String) : SSHKey
        if pem.includes?("Proc-Type: 4,ENCRYPTED")
          raise ArgumentError.new("encrypted PEM RSA keys are not supported (use openssh format)")
        end
        der = pem_to_der(pem)
        ints = der_integers(der)
        # PKCS#1: version, n, e, d, ...; PKCS#8 (BEGIN PRIVATE KEY): внутри
        # octet-string лежит PKCS#1 — der_integers рекурсивно даёт n, e и там.
        n, e = pick_rsa_n_e(ints)
        io = IO::Memory.new
        write_string(io, "ssh-rsa")
        write_mpint(io, e)
        write_mpint(io, n)
        SSHKey.new("ssh-rsa", io.to_slice)
      end

      OPENSSH_MAGIC  = "openssh-key-v1\u{0}"
      OPENSSH_MBEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
      OPENSSH_MEND   = "-----END OPENSSH PRIVATE KEY-----"

      # ssh-имя шифра → EVP-имя OpenSSL.
      private CIPHER_EVP = {
        "aes256-cbc" => "aes-256-cbc",
        "aes192-cbc" => "aes-192-cbc",
        "aes128-cbc" => "aes-128-cbc",
        "aes256-ctr" => "aes-256-ctr",
        "aes192-ctr" => "aes-192-ctr",
        "aes128-ctr" => "aes-128-ctr",
        "3des-cbc"   => "des-ede3-cbc",
      }

      # keylen, blocksize, ivlen по ssh-имени шифра.
      private CIPHER_LENGTHS = {
        "none"       => {0, 8, 0},
        "aes256-cbc" => {32, 16, 16},
        "aes192-cbc" => {24, 16, 16},
        "aes128-cbc" => {16, 16, 16},
        "aes256-ctr" => {32, 16, 16},
        "aes192-ctr" => {24, 16, 16},
        "aes128-ctr" => {16, 16, 16},
        "3des-cbc"   => {24, 8, 8},
      }

      def self.load_openssh_key(pem : String, passphrase : String? = nil) : SSHKey
        datafull = pem.strip
        unless datafull.starts_with?(OPENSSH_MBEGIN) && datafull.ends_with?(OPENSSH_MEND)
          raise ArgumentError.new("Expected #{OPENSSH_MBEGIN} armor around private key")
        end
        datab64 = datafull[OPENSSH_MBEGIN.size...(datafull.size - OPENSSH_MEND.size)]
        data = Base64.decode(datab64.gsub(/\s/, ""))
        raise ArgumentError.new("Expected openssh-key-v1 magic") unless data[0, OPENSSH_MAGIC.bytesize] == OPENSSH_MAGIC.to_slice

        io = IO::Memory.new(data[OPENSSH_MAGIC.size..])
        ciphername = String.new(read_string(io))
        kdfname = String.new(read_string(io))
        kdfopts = IO::Memory.new(read_string(io))
        num_keys = read_u32(io)
        raise ArgumentError.new("Only 1 key is supported, got #{num_keys}") unless num_keys == 1

        pubblob = read_string(io)
        enc = read_string(io)

        lengths = CIPHER_LENGTHS[ciphername]?
        raise ArgumentError.new("#{ciphername} in private key is not supported") unless lengths
        keylen, blocksize, ivlen = lengths
        if enc.size < blocksize || (blocksize > 0 && enc.size % blocksize != 0)
          raise ArgumentError.new("Private key len:#{enc.size} is not a multiple of #{blocksize}")
        end

        decrypted = case kdfname
                    when "bcrypt"
                      raise ArgumentError.new("key is encrypted, but no passphrase given") unless passphrase
                      salt = read_string(kdfopts)
                      rounds = read_u32(kdfopts)
                      key = BCryptPbkdf.pbkdf2(passphrase.to_slice, salt, keylen + ivlen, rounds.to_i32)
                      decipher = OpenSSL::Cipher.new(CIPHER_EVP[ciphername])
                      decipher.decrypt
                      decipher.key = key[0, keylen]
                      decipher.iv = key[keylen, ivlen]
                      decipher.update(enc) + decipher.final
                    when "none"
                      raise ArgumentError.new("no passphrase expected for unencrypted key") if passphrase && ciphername == "none"
                      enc
                    else
                      raise ArgumentError.new("Expected kdf name to be none or bcrypt, got #{kdfname}")
                    end

        dio = IO::Memory.new(decrypted)
        check1 = read_u32(dio)
        check2 = read_u32(dio)
        raise ArgumentError.new("Decrypt failed on private key (wrong passphrase?)") if check1 != check2

        # Валидация структуры записи; blob/тип берём из заголовка контейнера.
        type_name = String.new(read_string(dio))
        comment = nil
        case type_name
        when "ssh-ed25519"
          pk = read_string(dio) # публичный ключ (32 байта)
          sk = read_string(dio) # приватный: seed(32) || pk(32)
          comment = String.new(read_string(dio))
          raise ArgumentError.new("pk does not match sk") unless pk == sk[pk.size..]
        else
          # rsa/ecdsa: приватные поля до comment; comment — последний string
          # перед padding. Читаем строки, пока длина выглядит валидно
          # (padding 1..N корректной строкой быть не может).
          last = nil
          while next_string_size_sane(dio)
            last = read_string(dio)
          end
          comment = String.new(last) if last
        end

        stype = String.new(read_string(IO::Memory.new(pubblob)))
        SSHKey.new(stype, pubblob, comment)
      end

      # Смотрит вперёд: остаётся ли строка валидной по длине.
      private def self.next_string_size_sane(dio : IO::Memory) : Bool
        return false if dio.size - dio.pos < 4
        size = dio.read_bytes(UInt32, IO::ByteFormat::BigEndian).to_i64
        dio.pos -= 4
        size >= 0 && size <= dio.size - dio.pos - 4
      end

      # --- PEM/DER хелперы ----------------------------------------------------

      private def self.pem_to_der(pem : String) : Bytes
        body = pem.lines.reject { |l| l.starts_with?("-----") || l.blank? }.join
        Base64.decode(body)
      end

      # Все INTEGER из DER (рекурсивно по вложенным SEQUENCE/OCTET STRING).
      private def self.der_integers(der : Bytes, acc = [] of Bytes) : Array(Bytes)
        i = 0
        while i < der.size
          tag = der[i]
          break if i + 1 >= der.size
          len = der[i + 1]
          hdr = 2
          if len & 0x80 != 0
            nlen = len & 0x7F
            break if i + 2 + nlen > der.size
            len = 0
            nlen.times { |k| len = (len << 8) | der[i + 2 + k] }
            hdr = 2 + nlen
          end
          body = der[(i + hdr)...(i + hdr + len)]?
          break if body.nil? || body.size != len
          case tag
          when 0x02 # INTEGER
            acc << body
          when 0x30, 0x04 # SEQUENCE, OCTET STRING
            der_integers(body, acc)
          end
          i += hdr + len
        end
        acc
      end

      # n — первое целое длиннее 8 байт (после version), e — следующее за ним.
      private def self.pick_rsa_n_e(ints : Array(Bytes)) : {Bytes, Bytes}
        n_idx = ints.index { |x| x.size > 8 } || raise ArgumentError.new("not an RSA key")
        n = ints[n_idx]
        e = ints[n_idx + 1]? || raise ArgumentError.new("not an RSA key")
        {n, e}
      end

      # --- SSH-блоб-хелперы ---------------------------------------------------

      protected def self.read_string(io : IO) : Bytes
        size = read_u32(io)
        data = Bytes.new(size)
        io.read_fully(data)
        data
      end

      protected def self.read_u32(io : IO) : UInt32
        io.read_bytes(UInt32, IO::ByteFormat::BigEndian)
      end

      private def self.write_string(io : IO, data : Bytes) : Nil
        io.write_bytes(data.size.to_u32, IO::ByteFormat::BigEndian)
        io.write(data)
      end

      private def self.write_string(io : IO, s : String) : Nil
        write_string(io, s.to_slice)
      end

      private def self.write_mpint(io : IO, data : Bytes) : Nil
        # убрать ведущие нули, добавить 0x00 если старший бит установлен
        i = 0
        while i < data.size - 1 && data[i] == 0
          i += 1
        end
        data = data[i..]
        if data[0] & 0x80 != 0
          data = Bytes.new(1, 0) + data
        end
        write_string(io, data)
      end
    end
  end
end
