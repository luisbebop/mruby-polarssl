if Object.const_defined? :PolarSSL
  module PolarSSL
    VERSION = '0.0.1'

    class MallocFailed < StandardError; end
    class NetWantRead < StandardError; end
    class NetWantWrite < StandardError; end
    class SSL
      class Error < StandardError; end
      class ReadTimeoutError < StandardError; end
    end
  end
end