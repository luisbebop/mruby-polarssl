#include "mruby.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/ssl.h"
#include "polarssl/version.h"

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
}

void mrb_mruby_polarssl_gem_final(mrb_state *mrb) {	
}
