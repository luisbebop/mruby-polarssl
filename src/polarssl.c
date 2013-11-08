#include "mruby.h"
#include <stdio.h>
#include <string.h>
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/string.h"
#include "mruby/variable.h"

#include <err.h>

void mrb_mruby_polarssl_gem_init(mrb_state *mrb) {
	struct RClass *d;
	d = mrb_define_module(mrb, "PolarSSL");
}

void mrb_mruby_polarssl_gem_final(mrb_state *mrb) {
	
}