module PolarSSL
  class Cipher
    class DES
      def initialize(algorithm)
        super("#{self.name}-#{algorithm}")
      end

      def name
        "DES"
      end
    end
  end
end

