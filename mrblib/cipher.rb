module PolarSSL
  class Cipher
    class << self
      attr_reader :ciphers
    end

    @ciphers = [
      "DES-CBC",
      "DES-ECB",
      "DES3-CBC",
      "DES3-ECB"
    ]

    attr_accessor :padding, :key, :source, :bkey, :bsource, :iv, :biv
    attr_reader :length, :algorithm, :name, :mode, :final, :cipher, :type

    def initialize(algorithm)
      unless PolarSSL::Cipher.ciphers.include?(algorithm)
        raise PolarSSL::CipherError.new("Cipher not found") 
      end
      self.algorithm = algorithm
    end

    def key=(value)
      @bkey = [value.to_s].pack("H*")
      @key  = value
    end

    def source=(value)
      @bsource = [value.to_s].pack("H*")
      @source  = value
    end

    def iv=(value)
      @biv = [value.to_s].pack("H*")
      @iv  = value
    end

    def algorithm=(value)
      @name, @mode = value.split("-")
      @cipher = PolarSSL::Cipher.const_get(self.name)
      @algorithm=value
    end

    def decrypt
      @type = :decrypt
      self
    end

    def encrypt
      @type = :encrypt
      self
    end

    def update(data = nil)
      self.source = data if data
      bin = self.cipher.send("#{self.type}", self.mode, self.bkey, self.bsource, self.biv.to_s)
      bin.to_s.unpack("H*").first.to_s.upcase
    end
  end
end

