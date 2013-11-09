if Object.const_defined? :PolarSSL
  module PolarSSL
    VERSION = '0.0.1'
    
    class MallocFailed < StandardError; end
  end
end