# Net::SCP — порт net-scp 4.x API (часть, используемая сайтом):
#   ssh.scp.upload!(local, remote)   # файл на сервер
#   ssh.scp.download!(remote)        # файл в память (String)
#   ssh.scp.download!(remote, local) # файл на диск
# Транспорт — SCP поверх libssh2 (SSH2::Session#scp_send_file/scp_recv).
# Каталоги не поддерживаются (сайт передаёт только файлы конфигов).

module Net
  module SCP
    class Error < ::Exception; end

    # Обёртка над Net::SSH::Session, возвращаемая ssh.scp.
    class SessionWrapper
      def initialize(@ssh : Net::SSH::Session)
      end

      # net-scp: upload!(local, remote, ...) — загрузить файл local на
      # сервер по пути remote.
      def upload!(local : String, remote : String) : Nil
        raise Error.new("not a file: #{local}") unless File.file?(local)
        @ssh.ssh2.scp_send_file(local, remote)
      end

      # net-scp: download!(remote, local = nil) — при local=nil скачивает
      # в память и возвращает String.
      def download!(remote : String, local : String? = nil) : String
        if local
          @ssh.ssh2.scp_recv_file(remote, local)
          local
        else
          io = IO::Memory.new
          @ssh.ssh2.scp_recv(remote) do |chan, stat|
            remaining = stat.st_size.to_i64
            buffer = Bytes.new(32768)
            while remaining > 0
              chunk = remaining < buffer.size ? remaining.to_i32 : buffer.size
              n = chan.read(buffer[0, chunk])
              break if n == 0
              io.write(buffer[0, n])
              remaining -= n
            end
          end
          io.to_s
        end
      end
    end

    # net-scp class-level: Net::SCP.upload!(host, user, local, remote, ssh_opts)
    # и download!(...) — открывают отдельную SSH-сессию.
    def self.upload!(host : String, user : String, local : String, remote : String,
                     **opts) : Nil
      Net::SSH.start(host, user, **opts) do |ssh|
        ssh.scp.upload!(local, remote)
      end
    end

    def self.download!(host : String, user : String, remote : String,
                       local : String? = nil, **opts) : String
      Net::SSH.start(host, user, **opts) do |ssh|
        ssh.scp.download!(remote, local)
      end
    end
  end
end
