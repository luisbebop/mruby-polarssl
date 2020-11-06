#include "mruby.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/string.h"
#include "mruby/ext/io.h"

#include "mruby/variable.h"

/*#include "mruby/ext/context_log.h"*/

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/des.h"
#include "mbedtls/base64.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/version.h"
#include "mbedtls/debug.h"

#if defined(_WIN32)
#include <winsock2.h>
#define ioctl ioctlsocket
#else
#include <sys/ioctl.h>
#endif

/*ECDSA*/
#include "mbedtls/ecdsa.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if MRUBY_RELEASE_NO < 10000
static struct RClass *mrb_module_get(mrb_state *mrb, const char *name) {
  return mrb_class_get(mrb, name);
}
#endif

extern struct mrb_data_type mrb_io_type;

static void mrb_ssl_free(mrb_state *mrb, void *ptr) {
  mbedtls_ssl_context *ssl = ptr;

  if (ssl != NULL) {
    if (ssl->conf != NULL) {
      mbedtls_ssl_config_free((mbedtls_ssl_config  *)ssl->conf);
      mrb_free(mrb, (mbedtls_ssl_config  *)ssl->conf);
      ssl->conf = NULL;
    }

    mbedtls_ssl_free(ssl);
    mrb_free(mrb, ssl);
  }
}

static struct mrb_data_type mrb_entropy_type = { "Entropy", mrb_free };
static struct mrb_data_type mrb_ctr_drbg_type = { "CtrDrbg", mrb_free };
static struct mrb_data_type mrb_ssl_type = { "SSL", mrb_ssl_free };

static void entropycheck(mrb_state *mrb, mrb_value self, mbedtls_entropy_context **entropyp) {
  mbedtls_entropy_context *entropy;

  entropy = (mbedtls_entropy_context *)DATA_PTR(self);
  if (!entropy) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "no entropy found (BUG?)");
  }
  if (entropyp) *entropyp = entropy;
}

static mrb_value mrb_entropy_gather(mrb_state *mrb, mrb_value self) {
  mbedtls_entropy_context *entropy;

  entropycheck(mrb, self, &entropy);

  if( mbedtls_entropy_gather( entropy ) == 0 ) {
    return mrb_true_value();
  } else {
    return mrb_false_value();
  }
}

static mrb_value mrb_entropy_initialize(mrb_state *mrb, mrb_value self) {
  mbedtls_entropy_context *entropy;

  entropy = (mbedtls_entropy_context *)DATA_PTR(self);
  if (entropy) {
    mrb_free(mrb, entropy);
  }
  DATA_TYPE(self) = &mrb_entropy_type;
  DATA_PTR(self) = NULL;

  entropy = (mbedtls_entropy_context *)mrb_malloc(mrb, sizeof(mbedtls_entropy_context));
  DATA_PTR(self) = entropy;

  mbedtls_entropy_init(entropy);

  return self;
}

static mrb_value mrb_ctrdrbg_initialize(mrb_state *mrb, mrb_value self) {
  mbedtls_ctr_drbg_context *ctr_drbg;
  mbedtls_entropy_context *entropy_p;
  mrb_value entp, pers;
  int ret;

  ctr_drbg = (mbedtls_ctr_drbg_context *)DATA_PTR(self);
  if (ctr_drbg) {
    mrb_free(mrb, ctr_drbg);
  }
  DATA_TYPE(self) = &mrb_ctr_drbg_type;
  DATA_PTR(self) = NULL;

  mrb_get_args(mrb, "o|S", &entp, &pers);

  if (mrb_type(entp) != MRB_TT_DATA) {
    mrb_raise(mrb, E_TYPE_ERROR, "wrong argument class");
  }
  entropy_p = DATA_CHECK_GET_PTR(mrb, entp, &mrb_entropy_type, mbedtls_entropy_context);

  ctr_drbg = (mbedtls_ctr_drbg_context *)mrb_malloc(mrb, sizeof(mbedtls_ctr_drbg_context));
  DATA_PTR(self) = ctr_drbg;

  mbedtls_ctr_drbg_init(ctr_drbg);

  if (mrb_string_p(pers)) {
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@pers"), pers);
    ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy_p, (unsigned char *)RSTRING_PTR(pers), RSTRING_LEN(pers));
  } else {
    ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy_p, NULL, 0);
  }

  if (ret == MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED ) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Could not initialize entropy source");
  }

  return self;
}

static mrb_value mrb_ctrdrbg_random_bytes(mrb_state *mrb, mrb_value self) {
  mrb_int num_bytes;
  mbedtls_ctr_drbg_context *ctr_drbg;
  unsigned char *buf;
  mrb_value str;

  mrb_get_args(mrb, "i", &num_bytes);

  ctr_drbg = (mbedtls_ctr_drbg_context *)DATA_PTR(self);

  if (!ctr_drbg) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "DRBG not initialized");
  }

  buf = mrb_malloc(mrb, num_bytes);

  if (!buf) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Buffer allocation failed");
  }

  if (mbedtls_ctr_drbg_random(ctr_drbg, buf, num_bytes)) {
    free(buf);
    mrb_raise(mrb, E_RUNTIME_ERROR, "Random data generation failed");
  }

  str = mrb_str_new(mrb, (char *) buf, num_bytes);

  mrb_free(mrb, buf);
  buf = NULL;

  return str;
}

static mrb_value mrb_ctrdrbg_self_test() {
  if( mbedtls_ctr_drbg_self_test(0) == 0 ) {
    return mrb_true_value();
  } else {
    return mrb_false_value();
  }
}

#define E_MALLOC_FAILED (mrb_class_get_under(mrb,mrb_class_get(mrb, "PolarSSL"),"MallocFailed"))
#define E_NETWANTREAD (mrb_class_get_under(mrb,mrb_class_get(mrb, "PolarSSL"),"NetWantRead"))
#define E_NETWANTWRITE (mrb_class_get_under(mrb,mrb_class_get(mrb, "PolarSSL"),"NetWantWrite"))
#define E_SSL_ERROR (mrb_class_get_under(mrb,mrb_class_get_under(mrb,mrb_module_get(mrb, "PolarSSL"),"SSL"), "Error"))

#if defined(MRUBY_MBEDTLS_DEBUG_C)
static void my_debug_func( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
  printf("%s:%04d: %s", file, line, str);
}
#endif

static mrb_value mrb_ssl_initialize(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  mbedtls_ssl_config *conf;

#if MBEDTLS_VERSION_MAJOR == 1 && MBEDTLS_VERSION_MINOR == 1
  ssl_session *ssn;
#endif

  ssl = (mbedtls_ssl_context *)DATA_PTR(self);
  if (ssl) {
    mrb_ssl_free(mrb, ssl);
  }
  DATA_TYPE(self) = &mrb_ssl_type;
  DATA_PTR(self) = NULL;

  ssl = (mbedtls_ssl_context *)mrb_malloc(mrb, sizeof(mbedtls_ssl_context));
  DATA_PTR(self) = ssl;

  mbedtls_ssl_init(ssl);

  conf = (mbedtls_ssl_config *)mrb_malloc(mrb, sizeof(mbedtls_ssl_config));
  mbedtls_ssl_config_init( conf );

  mbedtls_ssl_config_defaults( conf, MBEDTLS_SSL_IS_CLIENT,
      MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT );

#if defined(MRUBY_MBEDTLS_DEBUG_C)
  mbedtls_ssl_conf_dbg( conf, my_debug_func, stdout );
  mbedtls_debug_set_threshold(5);
#endif

  mbedtls_ssl_setup( ssl, conf );

#if MBEDTLS_VERSION_MAJOR == 1 && MBEDTLS_VERSION_MINOR == 1
  ssn = (ssl_session *)mrb_malloc(mrb, sizeof(ssl_session));
  ssl_set_session( ssl, 0, 600, ssn );
  ssl_set_ciphersuites( ssl, ssl_default_ciphersuites );
#endif

  return self;
}

static mrb_value mrb_ssl_set_endpoint(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  mrb_int endpoint_mode;

  mrb_get_args(mrb, "i", &endpoint_mode);
  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);
  mbedtls_ssl_conf_authmode((mbedtls_ssl_config  *)ssl->conf, endpoint_mode);
  return mrb_true_value();
}

static mrb_value mrb_ssl_set_authmode(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  mrb_int authmode;

  mrb_get_args(mrb, "i", &authmode);
  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);
  mbedtls_ssl_conf_authmode((mbedtls_ssl_config  *)ssl->conf, authmode);
  return mrb_true_value();
}

static mrb_value mrb_ssl_set_rng(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  mbedtls_ctr_drbg_context *ctr_drbg;
  mrb_value rng;

  mrb_get_args(mrb, "o", &rng);
  mrb_data_check_type(mrb, rng, &mrb_ctr_drbg_type);
  ctr_drbg = DATA_CHECK_GET_PTR(mrb, rng, &mrb_ctr_drbg_type, mbedtls_ctr_drbg_context);
  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);

  mbedtls_ssl_conf_rng((mbedtls_ssl_config  *)ssl->conf, &mbedtls_ctr_drbg_random, ctr_drbg);
  return mrb_true_value();
}

static mrb_value mrb_ssl_set_socket(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  struct mrb_io *fptr;
  mrb_value socket;

  mrb_get_args(mrb, "o", &socket);
  mrb_data_check_type(mrb, socket, &mrb_io_type);
  fptr = DATA_CHECK_GET_PTR(mrb, socket, &mrb_io_type, struct mrb_io);
  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);
  mbedtls_ssl_set_bio( ssl, fptr, mbedtls_net_send, mbedtls_net_recv, NULL ); // timeout recv
  return mrb_true_value();
}

static mrb_value mrb_ssl_set_hostname(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  mrb_value hostname;

  mrb_get_args(mrb, "S", &hostname);

  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);
  mbedtls_ssl_set_hostname(ssl, RSTRING_PTR(hostname));

  return mrb_true_value();
}

static int mbedtls_status_is_ssl_in_progress( int ret )
{
  return( ret == MBEDTLS_ERR_SSL_WANT_READ ||
      ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
      ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS );
}

static mrb_value mrb_ssl_handshake(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  int ret;

  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);

  while( ( ret = mbedtls_ssl_handshake( ssl ) ) != 0 ) {
    if( ! mbedtls_status_is_ssl_in_progress( ret ) )
      break;
  }

  if (ret < 0) {
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
      mrb_raise(mrb, E_NETWANTREAD, "ssl_handshake() returned MBEDTLS_ERR_SSL_WANT_READ");
    } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      mrb_raise(mrb, E_NETWANTWRITE, "ssl_handshake() returned MBEDTLS_ERR_SSL_WANT_WRITE");
    } else {
      mrb_raise(mrb, E_SSL_ERROR, "ssl_handshake() returned E_SSL_ERROR");
    }
  }
  return mrb_true_value();
}

static mrb_value mrb_ssl_write(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  mrb_value msg;
  char *buffer;
  int ret;

  mrb_get_args(mrb, "S", &msg);
  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);

  buffer = RSTRING_PTR(msg);
  ret = mbedtls_ssl_write(ssl, (const unsigned char *)buffer, RSTRING_LEN(msg));
  if (ret < 0) {
    mrb_raise(mrb, E_SSL_ERROR, "ssl_write() returned E_SSL_ERROR");
  }
  return mrb_true_value();
}

static mrb_value mrb_ssl_read(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  mrb_int maxlen = 0;
  mrb_value value;
  char *buf;
  int ret;

  mrb_get_args(mrb, "i", &maxlen);

  buf = malloc(maxlen);
  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);
  ret = mbedtls_ssl_read(ssl, (unsigned char *)buf, maxlen);
  if ( ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || buf == NULL) {
    value = mrb_nil_value();
  } else if (ret < 0) {
    mrb_raise(mrb, E_SSL_ERROR, "ssl_read() returned E_SSL_ERROR");
    value = mrb_nil_value();
  } else {
    value = mrb_str_new(mrb, buf, ret);
  }

  if(buf != NULL) free(buf);
  return value;
}

static mrb_value mrb_ssl_close_notify(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  int ret;

  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);

  ret = mbedtls_ssl_close_notify(ssl);
  if (ret < 0) {
    mrb_raise(mrb, E_SSL_ERROR, "ssl_close_notify() returned E_SSL_ERROR");
  }
  return mrb_true_value();
}

static mrb_value mrb_ssl_close(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;

  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);
  return mrb_true_value();
}

static mrb_value mrb_ssl_bytes_available(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  mrb_int count=0, fd=0;

  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);
  fd = ((mbedtls_net_context *) ssl->p_bio)->fd;
  if (fd) ioctl(fd, FIONREAD, &count);

  return mrb_fixnum_value(count);
}

static mrb_value mrb_ssl_fileno(mrb_state *mrb, mrb_value self) {
  mbedtls_ssl_context *ssl;
  mrb_int fd=0;

  ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, mbedtls_ssl_context);
  fd = ((mbedtls_net_context *) ssl->p_bio)->fd;

  return mrb_fixnum_value(fd);
}

static void mrb_ecdsa_free(mrb_state *mrb, void *ptr) {
  mbedtls_ecdsa_context *ecdsa = ptr;

  if (ecdsa != NULL) {
    mbedtls_ecdsa_free(ecdsa);
    mrb_free(mrb, ptr);
  }
}

static struct mrb_data_type mrb_ecdsa_type = { "EC", mrb_ecdsa_free };

static mrb_value mrb_ecdsa_alloc(mrb_state *mrb, mrb_value self) {
  mbedtls_ecdsa_context *ecdsa;

  ecdsa = (mbedtls_ecdsa_context *)DATA_PTR(self);

  if (ecdsa) {
    mrb_ecdsa_free(mrb, ecdsa);
  }
  DATA_TYPE(self) = &mrb_ecdsa_type;
  DATA_PTR(self) = NULL;

  ecdsa = (mbedtls_ecdsa_context *)mrb_malloc(mrb, sizeof(mbedtls_ecdsa_context));
  DATA_PTR(self) = ecdsa;

  mbedtls_ecdsa_init(ecdsa);

  return self;
}

static mrb_value mrb_ecdsa_generate_key(mrb_state *mrb, mrb_value self) {
  mbedtls_ctr_drbg_context *ctr_drbg;
  mbedtls_ecp_curve_info *curve_info;
  mbedtls_ecdsa_context *ecdsa;
  mrb_value obj, curve;

  ecdsa    = DATA_CHECK_GET_PTR(mrb, self, &mrb_ecdsa_type, mbedtls_ecdsa_context);
  obj      = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@ctr_drbg"));
  curve    = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@curve"));
  ctr_drbg = DATA_CHECK_GET_PTR(mrb, obj, &mrb_ctr_drbg_type, mbedtls_ctr_drbg_context);

  if (mrb_string_p(curve)) {
    curve_info = (mbedtls_ecp_curve_info *)mbedtls_ecp_curve_info_from_name(RSTRING_PTR(curve));
  } else {
    return mrb_false_value();
  }

  if(mbedtls_ecdsa_genkey(ecdsa, curve_info->grp_id, mbedtls_ctr_drbg_random, ctr_drbg) == 0) {
    return mrb_true_value();
  } else {
    return mrb_false_value();
  }
}

static mrb_value mrb_ecdsa_load_pem(mrb_state *mrb, mrb_value self) {
  mbedtls_ecdsa_context *ecdsa;
  mbedtls_pk_context pkey;
  mrb_value pem;
  int ret = 0;
  char error[30] = {0};

  mrb_get_args(mrb, "S", &pem);

  mbedtls_pk_init( &pkey );

  ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *)RSTRING_PTR(pem), RSTRING_LEN(pem)+1, NULL, 0);
  if (ret == 0) {
    ecdsa = DATA_CHECK_GET_PTR(mrb, self, &mrb_ecdsa_type, mbedtls_ecdsa_context);
    ret = mbedtls_ecdsa_from_keypair(ecdsa, mbedtls_pk_ec(pkey));
    if (ret == 0) {
      mbedtls_pk_free( &pkey );
      return mrb_true_value();
    }
  }

  mbedtls_pk_free( &pkey );

  sprintf(error, "can't parse pem %d", ret);

  mrb_raise(mrb, E_RUNTIME_ERROR, error);
  return mrb_false_value();
}

static mrb_value mrb_ecdsa_public_key(mrb_state *mrb, mrb_value self) {
  mbedtls_ecdsa_context *ecdsa;
  unsigned char buf[300];
  unsigned char str[600];
  size_t len;
  int i, j;

  ecdsa = DATA_CHECK_GET_PTR(mrb, self, &mrb_ecdsa_type, mbedtls_ecdsa_context);

  memset(&str, 0, sizeof(str));
  memset(&buf, 0, sizeof(buf));

  if( mbedtls_ecp_point_write_binary( &ecdsa->grp, &ecdsa->Q,
        MBEDTLS_ECP_PF_COMPRESSED, &len, buf, sizeof(buf) ) != 0 )
  {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't extract Public Key");
    return mrb_false_value();
  }

  for(i=0, j=0; i < (int)len; i++,j+=2) {
    sprintf((char *)&str[j], "%c%c", "0123456789ABCDEF" [buf[i] / 16],
        "0123456789ABCDEF" [buf[i] % 16] );
  }

  return mrb_str_new(mrb, (char *)&str, len*2);
}

static mrb_value mrb_ecdsa_private_key(mrb_state *mrb, mrb_value self) {
  unsigned char buf[300];
  unsigned char str[600];
  mbedtls_ecdsa_context *ecdsa;
  size_t len, i, j;

  ecdsa = DATA_CHECK_GET_PTR(mrb, self, &mrb_ecdsa_type, mbedtls_ecdsa_context);

  memset(&str, 0, sizeof(str));
  memset(&buf, 0, sizeof(buf));

  if( mbedtls_ecp_point_write_binary( &ecdsa->grp, (mbedtls_ecp_point *)&ecdsa->d,
        MBEDTLS_ECP_PF_COMPRESSED, &len, buf, sizeof(buf) ) != 0 )
  {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't extract Public Key");
    return mrb_false_value();
  }

  for(i=0, j=0; i < len; i++,j+=2) {
    sprintf((char *)&str[j], "%c%c", "0123456789ABCDEF" [buf[i] / 16],
        "0123456789ABCDEF" [buf[i] % 16] );
  }

  /*return mrb_str_new(mrb, str, len*2);*/
  return mrb_str_new(mrb, (char *)&str[2], len*2 - 2);
}

static mrb_value mrb_ecdsa_sign(mrb_state *mrb, mrb_value self) {
  mbedtls_ctr_drbg_context *ctr_drbg;
  unsigned char buf[512], str[1024];
  size_t len=0;
  int i, j, ret=0;
  mbedtls_ecdsa_context *ecdsa;
  mrb_value hash, obj;

  memset(buf, 0, sizeof( buf ) );

  mrb_get_args(mrb, "S", &hash);

  obj      = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@ctr_drbg"));
  ecdsa    = DATA_CHECK_GET_PTR(mrb, self, &mrb_ecdsa_type, mbedtls_ecdsa_context);
  ctr_drbg = DATA_CHECK_GET_PTR(mrb, obj, &mrb_ctr_drbg_type, mbedtls_ctr_drbg_context);

  ret = mbedtls_ecdsa_write_signature(ecdsa, MBEDTLS_MD_SHA256, (unsigned char *)RSTRING_PTR(hash), RSTRING_LEN(hash),
      buf, &len, mbedtls_ctr_drbg_random, ctr_drbg);

  for(i=0, j=0; i < (int)len; i++,j+=2) {
    sprintf((char *)&str[j], "%c%c", "0123456789ABCDEF" [buf[i] / 16],
        "0123456789ABCDEF" [buf[i] % 16] );
  }

  if (ret == 0) {
    return mrb_str_new(mrb, (char *)&str, len*2);
  } else {
    return mrb_fixnum_value(ret);
  }
}

static mrb_value mrb_des_encrypt(mrb_state *mrb, mrb_value self) {
  mrb_value mode, key, source, iv;
  unsigned char output[100];
  mbedtls_des_context ctx;
  mrb_int len=8;

  memset(output, 0, sizeof(output));

  mrb_get_args(mrb, "SSSS", &mode, &key, &source, &iv);

  mbedtls_des_init(&ctx);
  mbedtls_des_setkey_enc(&ctx, (unsigned char *)RSTRING_PTR(key));

  if (mrb_str_cmp(mrb, mode, mrb_str_new(mrb, "CBC", 3)) == 0) {
    mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, RSTRING_LEN(source), (unsigned char *)RSTRING_PTR(iv),
        (unsigned char *)RSTRING_PTR(source), output);
    len = RSTRING_LEN(source);
  } else if (mrb_str_cmp(mrb, mode, mrb_str_new(mrb, "ECB", 3)) == 0) {
    mbedtls_des_crypt_ecb(&ctx, (unsigned char *)RSTRING_PTR(source), output);
  } else {
    mbedtls_des_free(&ctx);
    return mrb_nil_value();
  }

  mbedtls_des_free(&ctx);
  return mrb_str_new(mrb, (char *)&output, len);
}

static mrb_value mrb_des_decrypt(mrb_state *mrb, mrb_value self) {
  mrb_value mode, key, source, iv;
  unsigned char output[100];
  mbedtls_des_context ctx;
  mrb_int len=8;

  memset(output, 0, sizeof(output));

  mrb_get_args(mrb, "SSSS", &mode, &key, &source, &iv);

  mbedtls_des_init(&ctx);
  mbedtls_des_setkey_dec(&ctx, (unsigned char *)RSTRING_PTR(key));

  if (mrb_str_cmp(mrb, mode, mrb_str_new(mrb, "CBC", 3)) == 0) {
    mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, RSTRING_LEN(source), (unsigned char *)RSTRING_PTR(iv),
        (unsigned char *)RSTRING_PTR(source), output);
    len = RSTRING_LEN(source);
  } else if (mrb_str_cmp(mrb, mode, mrb_str_new(mrb, "ECB", 3)) == 0) {
    mbedtls_des_crypt_ecb(&ctx, (unsigned char *)RSTRING_PTR(source), output);
  } else {
    mbedtls_des_free(&ctx);
    return mrb_nil_value();
  }

  mbedtls_des_free(&ctx);
  return mrb_str_new(mrb, (char *)&output, len);
}

static mrb_value mrb_des3_encrypt(mrb_state *mrb, mrb_value self) {
  mrb_value mode, key, source, iv;
  unsigned char output[100];
  mbedtls_des3_context ctx;
  mrb_int len=16;

  memset(output, 0, sizeof(output));

  mrb_get_args(mrb, "SSSS", &mode, &key, &source, &iv);

  mbedtls_des3_init(&ctx);
  if (RSTRING_LEN(key) == 16) {
    mbedtls_des3_set2key_enc(&ctx, (unsigned char *)RSTRING_PTR(key));
  } else if (RSTRING_LEN(key) == 24) {
    mbedtls_des3_set3key_enc(&ctx, (unsigned char *)RSTRING_PTR(key));
  } else {
    mbedtls_des3_free(&ctx);
    return mrb_nil_value();
  }

  if (mrb_str_cmp(mrb, mode, mrb_str_new(mrb, "CBC", 3)) == 0) {
    mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, RSTRING_LEN(source), (unsigned char *)RSTRING_PTR(iv),
        (unsigned char *)RSTRING_PTR(source), output);
    len = RSTRING_LEN(source);
  } else if (mrb_str_cmp(mrb, mode, mrb_str_new(mrb, "ECB", 3)) == 0) {
    mbedtls_des3_crypt_ecb(&ctx, (unsigned char *)RSTRING_PTR(source), output);
    len = 8;
  } else {
    mbedtls_des3_free(&ctx);
    return mrb_nil_value();
  }

  mbedtls_des3_free(&ctx);
  return mrb_str_new(mrb, (char *)&output, len);
}

static mrb_value mrb_des3_decrypt(mrb_state *mrb, mrb_value self) {
  mrb_value mode, key, source, iv;
  unsigned char output[100];
  mbedtls_des3_context ctx;
  mrb_int len=16;

  memset(output, 0, sizeof(output));

  mrb_get_args(mrb, "SSSS", &mode, &key, &source, &iv);

  mbedtls_des3_init(&ctx);
  if (RSTRING_LEN(key) == 16) {
    mbedtls_des3_set2key_dec(&ctx, (unsigned char *)RSTRING_PTR(key));
  } else if (RSTRING_LEN(key) == 24) {
    mbedtls_des3_set3key_dec(&ctx, (unsigned char *)RSTRING_PTR(key));
  } else {
    mbedtls_des3_free(&ctx);
    return mrb_nil_value();
  }

  if (mrb_str_cmp(mrb, mode, mrb_str_new(mrb, "CBC", 3)) == 0) {
    mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, RSTRING_LEN(source), (unsigned char *)RSTRING_PTR(iv),
        (unsigned char *)RSTRING_PTR(source), output);
    len = RSTRING_LEN(source);
  } else if (mrb_str_cmp(mrb, mode, mrb_str_new(mrb, "ECB", 3)) == 0) {
    mbedtls_des3_crypt_ecb(&ctx, (unsigned char *)RSTRING_PTR(source), output);
    len = 8;
  } else {
    mbedtls_des3_free(&ctx);
    return mrb_nil_value();
  }

  mbedtls_des3_free(&ctx);
  return mrb_str_new(mrb, (char *)&output, len);
}

static mrb_value mrb_base64_encode(mrb_state *mrb, mrb_value self) {
  mrb_value src;
  size_t len;

  mrb_get_args(mrb, "S", &src);

  unsigned char buffer[RSTRING_LEN(src) * 3 + 1];
  memset(buffer, 0, sizeof(buffer));

  len = sizeof(buffer);
  mbedtls_base64_encode(buffer, len, &len, (unsigned char *)RSTRING_PTR(src), RSTRING_LEN(src));

  return mrb_str_new(mrb, (char *)&buffer, len);
}

static mrb_value mrb_base64_decode(mrb_state *mrb, mrb_value self) {
  mrb_value src;
  size_t len;

  mrb_get_args(mrb, "S", &src);

  unsigned char buffer[RSTRING_LEN(src) * 3 + 1];
  memset(buffer, 0, sizeof(buffer));

  len = sizeof(buffer);
  mbedtls_base64_decode(buffer, len, &len, (unsigned char *)RSTRING_PTR(src), RSTRING_LEN(src));

  return mrb_str_new(mrb, (char *)&buffer, len);
}

void mrb_mruby_polarssl_gem_init(mrb_state *mrb) {
  struct RClass *p, *e, *c, *s, *pkey, *ecdsa, *cipher, *des, *des3, *base64;

  p = mrb_define_module(mrb, "PolarSSL");
  pkey = mrb_define_module_under(mrb, p, "PKey");

  e = mrb_define_class_under(mrb, p, "Entropy", mrb->object_class);
  MRB_SET_INSTANCE_TT(e, MRB_TT_DATA);
  mrb_define_method(mrb, e, "initialize", mrb_entropy_initialize, MRB_ARGS_NONE());
  mrb_define_method(mrb, e, "gather", mrb_entropy_gather, MRB_ARGS_NONE());

  c = mrb_define_class_under(mrb, p, "CtrDrbg", mrb->object_class);
  MRB_SET_INSTANCE_TT(c, MRB_TT_DATA);
  mrb_define_method(mrb, c, "initialize", mrb_ctrdrbg_initialize, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1));
  mrb_define_method(mrb, c, "random_bytes", mrb_ctrdrbg_random_bytes, MRB_ARGS_REQ(1));
  mrb_define_singleton_method(mrb, (struct RObject*)c, "self_test", mrb_ctrdrbg_self_test, MRB_ARGS_NONE());

  s = mrb_define_class_under(mrb, p, "SSL", mrb->object_class);
  MRB_SET_INSTANCE_TT(s, MRB_TT_DATA);
  mrb_define_method(mrb, s, "initialize", mrb_ssl_initialize, MRB_ARGS_NONE());
  // 0: Endpoint mode for acting as a client.
  mrb_define_const(mrb, s, "SSL_IS_CLIENT", mrb_fixnum_value(MBEDTLS_SSL_IS_CLIENT));
  // 0: Certificate verification mode for doing no verification.
  mrb_define_const(mrb, s, "SSL_VERIFY_NONE", mrb_fixnum_value(MBEDTLS_SSL_VERIFY_NONE));
  // 1: Certificate verification mode for optional verification.
  mrb_define_const(mrb, s, "SSL_VERIFY_OPTIONAL", mrb_fixnum_value(MBEDTLS_SSL_VERIFY_OPTIONAL));
  // 2: Certificate verification mode for having required verification.
  mrb_define_const(mrb, s, "SSL_VERIFY_REQUIRED", mrb_fixnum_value(MBEDTLS_SSL_VERIFY_REQUIRED));
  mrb_define_method(mrb, s, "set_endpoint", mrb_ssl_set_endpoint, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "set_authmode", mrb_ssl_set_authmode, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "set_rng", mrb_ssl_set_rng, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "set_socket", mrb_ssl_set_socket, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "set_hostname", mrb_ssl_set_hostname, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "handshake", mrb_ssl_handshake, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "write", mrb_ssl_write, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "read", mrb_ssl_read, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, s, "bytes_available", mrb_ssl_bytes_available, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "fileno", mrb_ssl_fileno, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "close_notify", mrb_ssl_close_notify, MRB_ARGS_NONE());
  mrb_define_method(mrb, s, "close", mrb_ssl_close, MRB_ARGS_NONE());

  ecdsa = mrb_define_class_under(mrb, pkey, "EC", mrb->object_class);
  MRB_SET_INSTANCE_TT(ecdsa, MRB_TT_DATA);
  mrb_define_method(mrb, ecdsa, "alloc", mrb_ecdsa_alloc, MRB_ARGS_NONE());
  mrb_define_method(mrb, ecdsa, "generate_key", mrb_ecdsa_generate_key, MRB_ARGS_NONE());
  mrb_define_method(mrb, ecdsa, "load_pem", mrb_ecdsa_load_pem, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, ecdsa, "public_key", mrb_ecdsa_public_key, MRB_ARGS_NONE());
  mrb_define_method(mrb, ecdsa, "private_key", mrb_ecdsa_private_key, MRB_ARGS_NONE());
  mrb_define_method(mrb, ecdsa, "sign", mrb_ecdsa_sign, MRB_ARGS_REQ(1));

  cipher = mrb_define_class_under(mrb, p, "Cipher", mrb->object_class);

  des = mrb_define_class_under(mrb, cipher, "DES", cipher);
  mrb_define_class_method(mrb, des, "encrypt", mrb_des_encrypt, MRB_ARGS_REQ(4));
  mrb_define_class_method(mrb, des, "decrypt", mrb_des_decrypt, MRB_ARGS_REQ(4));

  des3 = mrb_define_class_under(mrb, cipher, "DES3", cipher);
  mrb_define_class_method(mrb, des3, "encrypt", mrb_des3_encrypt, MRB_ARGS_REQ(4));
  mrb_define_class_method(mrb, des3, "decrypt", mrb_des3_decrypt, MRB_ARGS_REQ(4));

  base64 = mrb_define_module_under(mrb, p, "Base64");
  mrb_define_class_method(mrb, base64, "encode", mrb_base64_encode, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, base64, "decode", mrb_base64_decode, MRB_ARGS_REQ(1));
}

void mrb_mruby_polarssl_gem_final(mrb_state *mrb) {
}

