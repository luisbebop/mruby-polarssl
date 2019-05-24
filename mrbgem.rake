MRuby::Gem::Specification.new('mruby-polarssl') do |spec|
  spec.license = 'Apache License 2.0'
  spec.authors = 'luisbebop@gmail.com'
  spec.version = "2.1.2"

  polarssl_dirname = 'polarssl'
  polarssl_src = "#{spec.dir}/#{polarssl_dirname}"
  spec.cc.include_paths << "#{polarssl_src}/include"
  spec.cc.include_paths << "#{polarssl_src}/../../mruby-io/include"
  spec.cc.include_paths << "#{build.root}/src"
  spec.cc.flags << '-D_FILE_OFFSET_BITS=64 -Wall -W -Wdeclaration-after-statement'
  spec.cc.flags << '-D_NETBSD_SOURCE' if RUBY_PLATFORM =~ /netbsd/i

  spec.objs += Dir.glob("#{polarssl_src}/library/*.{c,cpp,m,asm,S}").map { |f| f.relative_path_from(dir).pathmap("#{build_dir}/%X.o") }

  spec.add_dependency 'mruby-print'
  spec.add_dependency 'mruby-string-ext', core: 'mruby-string-ext'
  spec.add_dependency 'mruby-io'
  spec.add_dependency 'mruby-socket'
  spec.add_test_dependency 'mruby-mtest'
end
