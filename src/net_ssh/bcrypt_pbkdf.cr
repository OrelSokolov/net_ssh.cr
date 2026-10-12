# bcrypt_pbkdf — PBKDF2 с bcrypt-PRF (OpenSSH/OpenBSD), нужен для
# расшифровки зашифрованных ключей в openssh private format
# (kdf = bcrypt, cipher = aes256-ctr и др.).
#
# Точный порт OpenBSD bcrypt_pbkdf.c (тот же код в геме bcrypt_pbkdf 1.1,
# оттуда сняты oracle-векторы). Отличия bcrypt-хэша от классического bcrypt:
#   1. пароль и соль предварительно хэшируются SHA512;
#   2. выход расширен до 256 бит;
#   3. шифруется magic "OxychromaticBlowfishSwatDynamite";
#   4. 64 раунда расширения начального состояния.
# От PBKDF2: ключевой материал разбрасывается нелинейно (stride), чтобы
# нельзя было получить часть ключа без вычисления всего.

require "digest"
require "./blowfish_tables"

module Net
  module SSH
    module BCryptPbkdf
      BCRYPT_HASHSIZE = 32

      # Blowfish-контекст: S[4][256] + P[18] (раскладка как в blf_ctx).
      class State
        getter s : Array(UInt32)
        getter p : Array(UInt32)

        def initialize
          @s = Blowfish::ORIG_S.dup
          @p = Blowfish::ORIG_P.dup
        end

        # F-функция сети Фейстеля (s — плоский массив 1024 слова).
        private def f(x : UInt32) : UInt32
          s = @s
          (((s[(x >> 24) & 0xFF] &+ s[0x100 + ((x >> 16) & 0xFF)]) ^
            s[0x200 + ((x >> 8) & 0xFF)]) &+ s[0x300 + (x & 0xFF)])
        end

        # Blowfish_encipher.
        def encipher(xl : UInt32, xr : UInt32) : {UInt32, UInt32}
          p = @p
          xl ^= p[0]
          16.times do |i|
            if i.even?
              xr ^= f(xl) ^ p[1 + i]
            else
              xl ^= f(xr) ^ p[1 + i]
            end
          end
          {xr ^ p[17], xl}
        end

        # Blowfish_stream2word: циклическое чтение 4 байт из data.
        private def stream2word(data : Bytes, offset : Int32) : {UInt32, Int32}
          temp = 0_u32
          j = offset
          4.times do
            j = 0 if j >= data.size
            temp = (temp << 8) | data[j]
            j += 1
          end
          {temp, j}
        end

        # Blowfish_expand0state: расширение состояния ключом.
        def expand0state(key : Bytes) : Nil
          j = 0
          (Blowfish::BLF_N + 2).times do |i|
            temp, j = stream2word(key, j)
            @p[i] = @p[i] ^ temp
          end

          j = 0
          datal = 0_u32
          datar = 0_u32
          0.step(by: 2, to: Blowfish::BLF_N) do |i|
            datal, datar = encipher(datal, datar)
            @p[i] = datal
            @p[i + 1] = datar
          end

          4.times do |i|
            0.step(by: 2, to: 254) do |k|
              datal, datar = encipher(datal, datar)
              @s[i * 256 + k] = datal
              @s[i * 256 + k + 1] = datar
            end
          end
        end

        # Blowfish_expandstate: расширение состояния данными (salt) и ключом.
        def expandstate(data : Bytes, key : Bytes) : Nil
          j = 0
          (Blowfish::BLF_N + 2).times do |i|
            temp, j = stream2word(key, j)
            @p[i] = @p[i] ^ temp
          end

          j = 0
          datal = 0_u32
          datar = 0_u32
          0.step(by: 2, to: Blowfish::BLF_N) do |i|
            temp, j = stream2word(data, j)
            datal ^= temp
            temp, j = stream2word(data, j)
            datar ^= temp
            datal, datar = encipher(datal, datar)
            @p[i] = datal
            @p[i + 1] = datar
          end

          4.times do |i|
            0.step(by: 2, to: 254) do |k|
              temp, j = stream2word(data, j)
              datal ^= temp
              temp, j = stream2word(data, j)
              datar ^= temp
              datal, datar = encipher(datal, datar)
              @s[i * 256 + k] = datal
              @s[i * 256 + k + 1] = datar
            end
          end
        end

        # blf_enc над 8 словами (4 блока) на месте.
        def enc_words(cdata : Array(UInt32)) : Nil
          i = 0
          (cdata.size // 2).times do
            cdata[i], cdata[i + 1] = encipher(cdata[i], cdata[i + 1])
            i += 2
          end
        end
      end

      # bcrypt_hash: 32 байта из SHA512-предобработанных pass/salt.
      def self.bcrypt_hash(sha2pass : Bytes, sha2salt : Bytes) : Bytes
        state = State.new
        ciphertext = "OxychromaticBlowfishSwatDynamite".to_slice

        state.expandstate(sha2salt, sha2pass)
        64.times do
          state.expand0state(sha2salt)
          state.expand0state(sha2pass)
        end

        cdata = Array(UInt32).new(BCRYPT_HASHSIZE // 4, 0_u32)
        j = 0
        (BCRYPT_HASHSIZE // 4).times do |i|
          word, j = stream2word(ciphertext, j)
          cdata[i] = word
        end
        64.times { state.enc_words(cdata) }

        out = Bytes.new(BCRYPT_HASHSIZE)
        (BCRYPT_HASHSIZE // 4).times do |i|
          out[4 * i + 3] = ((cdata[i] >> 24) & 0xFF).to_u8
          out[4 * i + 2] = ((cdata[i] >> 16) & 0xFF).to_u8
          out[4 * i + 1] = ((cdata[i] >> 8) & 0xFF).to_u8
          out[4 * i + 0] = (cdata[i] & 0xFF).to_u8
        end
        out
      end

      # bcrypt_pbkdf(pass, salt, keylen, rounds) → keylen байт.
      # Соответствует BCryptPbkdf.key гема bcrypt_pbkdf / OpenSSH.
      def self.pbkdf2(pass : Bytes|String, salt : Bytes|String,
                      keylen : Int32, rounds : Int32) : Bytes
        pass = pass.to_slice if pass.is_a?(String)
        salt = salt.to_slice if salt.is_a?(String)
        raise ArgumentError.new("rounds must be >= 1") if rounds < 1
        raise ArgumentError.new("empty pass/salt/keylen") if pass.empty? || salt.empty? || keylen == 0

        origkeylen = keylen
        key = Bytes.new(keylen)

        sha2pass = Digest::SHA512.digest(pass)

        outsize = BCRYPT_HASHSIZE
        stride = (keylen + outsize - 1) // outsize
        amt = (keylen + stride - 1) // stride

        out = Bytes.new(outsize)
        tmpout = Bytes.new(outsize)

        count = 1
        while keylen > 0
          countsalt = Bytes[(
            (count >> 24) & 0xFF).to_u8, ((count >> 16) & 0xFF).to_u8,
            ((count >> 8) & 0xFF).to_u8, (count & 0xFF).to_u8]

          # первый раунд: соль = salt || count(BE32)
          sha2salt = Digest::SHA512.digest(salt + countsalt)
          tmpout.copy_from(bcrypt_hash(sha2pass, sha2salt))
          out.copy_from(tmpout)

          (1...rounds).each do
            # последующие раунды: соль = SHA512(предыдущий выход)
            sha2salt = Digest::SHA512.digest(tmpout)
            tmpout.copy_from(bcrypt_hash(sha2pass, sha2salt))
            outsize.times { |j| out[j] ^= tmpout[j] }
          end

          # pbkdf2-deviation: нелинейное распределение выхода.
          this_amt = Math.min(amt, keylen)
          i = 0
          while i < this_amt
            dest = i * stride + (count - 1)
            break if dest >= origkeylen
            key[dest] = out[i]
            i += 1
          end
          keylen -= i
          count += 1
        end

        key
      end

      private def self.stream2word(data : Bytes, offset : Int32) : {UInt32, Int32}
        temp = 0_u32
        j = offset
        4.times do
          j = 0 if j >= data.size
          temp = (temp << 8) | data[j]
          j += 1
        end
        {temp, j}
      end
    end
  end
end
