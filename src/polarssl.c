#include "mruby.h"
#include "mruby/data.h"
#include "polarssl/entropy.h"

static void lib_entropy_free(mrb_state *mrb, void *ptr) {
  entropy_context *entropy = ptr;

  if (entropy != NULL) {
    mrb_free(mrb, entropy);
  }
}

static struct mrb_data_type mrb_entropy_type = { "ENTROPY", lib_entropy_free };

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

static mrb_value mrb_entropy_init(mrb_state *mrb, mrb_value self) {
  entropy_context *entropy;

  entropy = (entropy_context *)DATA_PTR(self);
  if (entropy) {
    lib_entropy_free(mrb, entropy);
  }
  DATA_TYPE(self) = &mrb_entropy_type;
  DATA_PTR(self) = NULL;

  entropy = (entropy_context *)mrb_malloc(mrb, sizeof(*entropy));
  DATA_PTR(self) = entropy;
  entropy_init(entropy);
  return self;
}

void mrb_mruby_polarssl_gem_init(mrb_state *mrb) {
	struct RClass *p, *e;
	
	p = mrb_define_module(mrb, "PolarSSL");
	e = mrb_define_class_under(mrb, p, "Entropy", mrb->object_class);
	mrb_define_method(mrb, e, "initialize", mrb_entropy_init, MRB_ARGS_NONE());
	mrb_define_method(mrb, e, "gather", mrb_entropy_gather, MRB_ARGS_NONE());
}

void mrb_mruby_polarssl_gem_final(mrb_state *mrb) {	
}
