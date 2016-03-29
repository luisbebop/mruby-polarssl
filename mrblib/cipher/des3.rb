module PolarSSL
  class Cipher
    class DES3
      def initialize(algorithm)
        super("#{self.name}-#{algorithm}")
      end

      def name
        "DES3"
      end
    end
  end
end

