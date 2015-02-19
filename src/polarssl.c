#include "mruby.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/string.h"
#include "mruby/ext/io.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/ssl.h"
#include "polarssl/version.h"
#include <sys/ioctl.h>

extern struct mrb_data_type mrb_io_type;

static void mrb_ssl_free(mrb_state *mrb, void *ptr) {
	ssl_context *ssl = ptr;
	
	if (ssl != NULL) {
		ssl_free(ssl);
	}
}

static struct mrb_data_type mrb_entropy_type = { "Entropy", mrb_free };
static struct mrb_data_type mrb_ctr_drbg_type = { "CtrDrbg", mrb_free };
static struct mrb_data_type mrb_ssl_type = { "SSL", mrb_ssl_free };

static void entropycheck(mrb_state *mrb, mrb_value self, entropy_context **entropyp) {
  entropy_context *entropy;

  entropy = (entropy_context *)DATA_PTR(self);
  if (!entropy) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "no entropy found (BUG?)");
  }
  if (entropyp) *entropyp = entropy;
}

static mrb_value mrb_entropy_gather(mrb_state *mrb, mrb_value self) {
  entropy_context *entropy;

  entropycheck(mrb, self, &entropy);

  if( entropy_gather( entropy ) == 0 ) {
	return mrb_true_value();
  } else {
	return mrb_false_value();
  }
}

static mrb_value mrb_entropy_initialize(mrb_state *mrb, mrb_value self) {
  entropy_context *entropy;

  entropy = (entropy_context *)DATA_PTR(self);
  if (entropy) {
    mrb_free(mrb, entropy);
  }
  DATA_TYPE(self) = &mrb_entropy_type;
  DATA_PTR(self) = NULL;

  entropy = (entropy_context *)mrb_malloc(mrb, sizeof(entropy_context));
  DATA_PTR(self) = entropy;
  
  entropy_init(entropy);
  
  return self;
}

static mrb_value mrb_ctrdrbg_initialize(mrb_state *mrb, mrb_value self) {
  ctr_drbg_context *ctr_drbg;
  entropy_context *entropy_p;
  mrb_value entp;
  int ret;

  ctr_drbg = (ctr_drbg_context *)DATA_PTR(self);
  if (ctr_drbg) {
    mrb_free(mrb, ctr_drbg);
  }
  DATA_TYPE(self) = &mrb_ctr_drbg_type;
  DATA_PTR(self) = NULL;

  mrb_get_args(mrb, "o", &entp);
  if (mrb_type(entp) != MRB_TT_DATA) {
	mrb_raise(mrb, E_TYPE_ERROR, "wrong argument class");
  }
  entropy_p = DATA_CHECK_GET_PTR(mrb, entp, &mrb_entropy_type, entropy_context);

  ctr_drbg = (ctr_drbg_context *)mrb_malloc(mrb, sizeof(ctr_drbg_context));
  DATA_PTR(self) = ctr_drbg;
  
  ret = ctr_drbg_init(ctr_drbg, entropy_func, entropy_p, NULL, 0 );
  if (ret == POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED ) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Could not initialize entropy source");	
  }

  return self;
}

static mrb_value mrb_ctrdrbg_self_test() {
  if( ctr_drbg_self_test(0) == 0 ) {
	return mrb_true_value();
  } else {
	return mrb_false_value();
  }
}

#define E_MALLOC_FAILED (mrb_class_get_under(mrb,mrb_class_get(mrb, "PolarSSL"),"MallocFailed"))
#define E_NETWANTREAD (mrb_class_get_under(mrb,mrb_class_get(mrb, "PolarSSL"),"NetWantRead"))
#define E_NETWANTWRITE (mrb_class_get_under(mrb,mrb_class_get(mrb, "PolarSSL"),"NetWantWrite"))
#define E_SSL_ERROR (mrb_class_get_under(mrb,mrb_class_get_under(mrb,mrb_class_get(mrb, "PolarSSL"),"SSL"), "Error"))

static mrb_value mrb_ssl_initialize(mrb_state *mrb, mrb_value self) {
  ssl_context *ssl;
  int ret;

  #if POLARSSL_VERSION_MAJOR == 1 && POLARSSL_VERSION_MINOR == 1
  ssl_session *ssn;
  #endif

  ssl = (ssl_context *)DATA_PTR(self);
  if (ssl) {
    mrb_ssl_free(mrb, ssl);
  }
  DATA_TYPE(self) = &mrb_ssl_type;
  DATA_PTR(self) = NULL;

  ssl = (ssl_context *)mrb_malloc(mrb, sizeof(ssl_context));
  DATA_PTR(self) = ssl;
  
  ret = ssl_init(ssl);
  if (ret == POLARSSL_ERR_SSL_MALLOC_FAILED) {
    mrb_raise(mrb, E_MALLOC_FAILED, "ssl_init() memory allocation failed.");	
  }

  #if POLARSSL_VERSION_MAJOR == 1 && POLARSSL_VERSION_MINOR == 1
  ssn = (ssl_session *)mrb_malloc(mrb, sizeof(ssl_session));
  ssl_set_session( ssl, 0, 600, ssn );
  ssl_set_ciphersuites( ssl, ssl_default_ciphersuites );
  #endif
  
  return self;
}

static mrb_value mrb_ssl_set_endpoint(mrb_state *mrb, mrb_value self) {
	ssl_context *ssl;
	mrb_int endpoint_mode;
	
	mrb_get_args(mrb, "i", &endpoint_mode);	
	ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, ssl_context);
	ssl_set_endpoint(ssl, endpoint_mode);
	return mrb_true_value();
}

static mrb_value mrb_ssl_set_authmode(mrb_state *mrb, mrb_value self) {
	ssl_context *ssl;
	mrb_int authmode;
	
	mrb_get_args(mrb, "i", &authmode);	
	ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, ssl_context);
	ssl_set_authmode(ssl, authmode);
	return mrb_true_value();
}

static mrb_value mrb_ssl_set_rng(mrb_state *mrb, mrb_value self) {
	ssl_context *ssl;
	ctr_drbg_context *ctr_drbg;
	mrb_value rng;
	
	mrb_get_args(mrb, "o", &rng);
	mrb_data_check_type(mrb, rng, &mrb_ctr_drbg_type);
	ctr_drbg = DATA_CHECK_GET_PTR(mrb, rng, &mrb_ctr_drbg_type, ctr_drbg_context);	
	ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, ssl_context);
	ssl_set_rng(ssl, ctr_drbg_random, ctr_drbg);
	return mrb_true_value();
}

static mrb_value mrb_ssl_set_socket(mrb_state *mrb, mrb_value self) {
	ssl_context *ssl;
	struct mrb_io *fptr;
	mrb_value socket;
	
	mrb_get_args(mrb, "o", &socket);
	mrb_data_check_type(mrb, socket, &mrb_io_type);
	fptr = DATA_CHECK_GET_PTR(mrb, socket, &mrb_io_type, struct mrb_io);	
	ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, ssl_context);
	ssl_set_bio( ssl, net_recv, &fptr->fd, net_send, &fptr->fd );
	return mrb_true_value();
}

static mrb_value mrb_ssl_handshake(mrb_state *mrb, mrb_value self) {
	ssl_context *ssl;
	int ret;
	
	ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, ssl_context);
	
	ret = ssl_handshake(ssl);
	if (ret < 0) {
		if (ret == POLARSSL_ERR_NET_WANT_READ) {
			mrb_raise(mrb, E_NETWANTREAD, "ssl_handshake() returned POLARSSL_ERR_NET_WANT_READ");
		} else if (ret == POLARSSL_ERR_NET_WANT_WRITE) {
			mrb_raise(mrb, E_NETWANTWRITE, "ssl_handshake() returned POLARSSL_ERR_NET_WANT_WRITE");
		} else {
			mrb_raise(mrb, E_SSL_ERROR, "ssl_handshake() returned E_SSL_ERROR");
		}
	}
	return mrb_true_value();
}

static mrb_value mrb_ssl_write(mrb_state *mrb, mrb_value self) {
	ssl_context *ssl;
	mrb_value msg;
	char *buffer;
	int ret;
	
	mrb_get_args(mrb, "S", &msg);
	ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, ssl_context);
	
	buffer = RSTRING_PTR(msg);
	ret = ssl_write(ssl, (const unsigned char *)buffer, RSTRING_LEN(msg));
	if (ret < 0) {
		mrb_raise(mrb, E_SSL_ERROR, "ssl_write() returned E_SSL_ERROR");
	}
	return mrb_true_value();
}

static mrb_value mrb_ssl_read(mrb_state *mrb, mrb_value self) {
	ssl_context *ssl;
	mrb_int maxlen = 0;
	mrb_value buf;
	int ret;
	
	mrb_get_args(mrb, "i", &maxlen);
	buf = mrb_str_buf_new(mrb, maxlen);
	ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, ssl_context);
	ret = ssl_read(ssl, (unsigned char *)RSTRING_PTR(buf), maxlen);
	if ( ret == 0 || ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY) {
		return mrb_nil_value();
	} else if (ret < 0) {
		mrb_raise(mrb, E_SSL_ERROR, "ssl_read() returned E_SSL_ERROR");
	} else {
		mrb_str_resize(mrb, buf, ret);
	}
	return buf;
}

static mrb_value mrb_ssl_close_notify(mrb_state *mrb, mrb_value self) {
	ssl_context *ssl;
	int ret;
	
	ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, ssl_context);
	
	ret = ssl_close_notify(ssl);
	if (ret < 0) {
		mrb_raise(mrb, E_SSL_ERROR, "ssl_close_notify() returned E_SSL_ERROR");
	}
	return mrb_true_value();
}

static mrb_value mrb_ssl_close(mrb_state *mrb, mrb_value self) {
	ssl_context *ssl;
	
	ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, ssl_context);
	memset(ssl, 0, sizeof(ssl_context));
	return mrb_true_value();
}

static mrb_value mrb_ssl_bytes_available(mrb_state *mrb, mrb_value self) {
	ssl_context *ssl;
    mrb_int count=0;

	ssl = DATA_CHECK_GET_PTR(mrb, self, &mrb_ssl_type, ssl_context);
    ioctl(*((int *)ssl->p_recv), FIONREAD, &count);

	return mrb_fixnum_value(count);
}

void mrb_mruby_polarssl_gem_init(mrb_state *mrb) {
	struct RClass *p, *e, *c, *s;
	
	p = mrb_define_module(mrb, "PolarSSL");
	
	e = mrb_define_class_under(mrb, p, "Entropy", mrb->object_class);
	MRB_SET_INSTANCE_TT(e, MRB_TT_DATA);
	mrb_define_method(mrb, e, "initialize", mrb_entropy_initialize, MRB_ARGS_NONE());
	mrb_define_method(mrb, e, "gather", mrb_entropy_gather, MRB_ARGS_NONE());

	c = mrb_define_class_under(mrb, p, "CtrDrbg", mrb->object_class);
	MRB_SET_INSTANCE_TT(c, MRB_TT_DATA);
	mrb_define_method(mrb, c, "initialize", mrb_ctrdrbg_initialize, MRB_ARGS_REQ(1));
	mrb_define_singleton_method(mrb, (struct RObject*)c, "self_test", mrb_ctrdrbg_self_test, MRB_ARGS_NONE());
	
	s = mrb_define_class_under(mrb, p, "SSL", mrb->object_class);
	MRB_SET_INSTANCE_TT(s, MRB_TT_DATA);
	mrb_define_method(mrb, s, "initialize", mrb_ssl_initialize, MRB_ARGS_NONE());
	// 0: Endpoint mode for acting as a client.
	mrb_define_const(mrb, s, "SSL_IS_CLIENT", mrb_fixnum_value(SSL_IS_CLIENT));
	// 0: Certificate verification mode for doing no verification.
	mrb_define_const(mrb, s, "SSL_VERIFY_NONE", mrb_fixnum_value(SSL_VERIFY_NONE));
	// 1: Certificate verification mode for optional verification.
	mrb_define_const(mrb, s, "SSL_VERIFY_OPTIONAL", mrb_fixnum_value(SSL_VERIFY_OPTIONAL));
	// 2: Certificate verification mode for having required verification.
	mrb_define_const(mrb, s, "SSL_VERIFY_REQUIRED", mrb_fixnum_value(SSL_VERIFY_REQUIRED));
	mrb_define_method(mrb, s, "set_endpoint", mrb_ssl_set_endpoint, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, s, "set_authmode", mrb_ssl_set_authmode, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, s, "set_rng", mrb_ssl_set_rng, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, s, "set_socket", mrb_ssl_set_socket, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, s, "handshake", mrb_ssl_handshake, MRB_ARGS_NONE());
	mrb_define_method(mrb, s, "write", mrb_ssl_write, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, s, "read", mrb_ssl_read, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, s, "bytes_available", mrb_ssl_bytes_available, MRB_ARGS_NONE());
	mrb_define_method(mrb, s, "close_notify", mrb_ssl_close_notify, MRB_ARGS_NONE());
	mrb_define_method(mrb, s, "close", mrb_ssl_close, MRB_ARGS_NONE());
}

void mrb_mruby_polarssl_gem_final(mrb_state *mrb) {	
}
