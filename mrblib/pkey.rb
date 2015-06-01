module PolarSSL
  module PKey
    class EC
      POLARSSL_ECP_DP_NONE      = 0
      POLARSSL_ECP_DP_SECP192R1 = 1  # 192-bits NIST curve
      POLARSSL_ECP_DP_SECP224R1 = 2  # 224-bits NIST curve
      POLARSSL_ECP_DP_SECP256R1 = 3  # 256-bits NIST curve
      POLARSSL_ECP_DP_SECP384R1 = 4  # 384-bits NIST curve
      POLARSSL_ECP_DP_SECP521R1 = 5  # 521-bits NIST curve
      POLARSSL_ECP_DP_BP256R1   = 6  # 256-bits Brainpool curve
      POLARSSL_ECP_DP_BP384R1   = 7  # 384-bits Brainpool curve
      POLARSSL_ECP_DP_BP512R1   = 8  # 512-bits Brainpool curve
      POLARSSL_ECP_DP_M221      = 8  # (not implemented yet)
      POLARSSL_ECP_DP_M255      = 9  # Curve25519
      POLARSSL_ECP_DP_M383      = 10 # (not implemented yet)
      POLARSSL_ECP_DP_M511      = 11 # (not implemented yet)
      POLARSSL_ECP_DP_SECP192K1 = 12 # (not implemented yet)
      POLARSSL_ECP_DP_SECP224K1 = 13 # (not implemented yet)
      POLARSSL_ECP_DP_SECP256K1 = 14 # 256-bits Koblitz curve

      CURVES = {
        "none"      => POLARSSL_ECP_DP_NONE,
        "secp192r1" => POLARSSL_ECP_DP_SECP192R1,
        "secp224r1" => POLARSSL_ECP_DP_SECP224R1,
        "secp256r1" => POLARSSL_ECP_DP_SECP256R1,
        "secp384r1" => POLARSSL_ECP_DP_SECP384R1,
        "secp521r1" => POLARSSL_ECP_DP_SECP521R1,
        "bp256r1"   => POLARSSL_ECP_DP_BP256R1,
        "bp384r1"   => POLARSSL_ECP_DP_BP384R1,
        "bp512r1"   => POLARSSL_ECP_DP_BP512R1,
        "m221"      => POLARSSL_ECP_DP_M221,
        "m255"      => POLARSSL_ECP_DP_M255,
        "m383"      => POLARSSL_ECP_DP_M383,
        "m511"      => POLARSSL_ECP_DP_M511,
        "secp192k1" => POLARSSL_ECP_DP_SECP192K1,
        "secp224k1" => POLARSSL_ECP_DP_SECP224K1,
        "secp256k1" => POLARSSL_ECP_DP_SECP256K1,
      }

      attr_reader :curve, :entropy, :ctr_drbg, :pem, :private_key

      def initialize(pem_or_curve = "secp256k1")
        alloc
        @entropy = PolarSSL::Entropy.new
        @ctr_drbg = PolarSSL::CtrDrbg.new(entropy, "ecdsa")
        check_pem(pem_or_curve)
      end

      private
      def check_pem(pem_or_curve)
        @curve = CURVES[pem_or_curve]
      end
    end
  end
end
