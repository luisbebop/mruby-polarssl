MRuby::Gem::Specification.new('mruby-polarssl') do |spec|
  spec.license = 'GPL'
  spec.authors = 'luisbebop@gmail.com'

  spec.cc.include_paths << "#{build.root}/src"

  spec.add_dependency('mruby-io')
  spec.add_dependency('mruby-mtest')
end