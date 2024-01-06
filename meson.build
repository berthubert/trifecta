project('trifecta', 'cpp', default_options : ['cpp_std=c++17'])

sqlitedep = dependency('sqlite3', version : '>3')
thread_dep = dependency('threads')
json_dep = dependency('nlohmann_json')
fmt_dep = dependency('fmt', version: '>9', static: true)

cpphttplib = dependency('cpp-httplib')
sqlitewriter_dep = dependency('sqlitewriter', static: true)
doctest_dep=dependency('doctest')
bcryptcpp_dep = dependency('bcryptcpp', static: true)
simplesockets_dep = dependency('simplesockets', static: true)
argparse_dep = dependency('argparse', version: '>=3')

vcs_ct=vcs_tag(command: ['git', 'describe', '--tags', '--always', '--dirty', '--abbrev=9'], 
      input:'git_version.h.in',
      output:'git_version.h',
      replace_string:'@GIT_VERSION@')

vcs_dep= declare_dependency (sources: vcs_ct)

executable('trifecta', 'trifecta.cc', 'serv.cc', 'support.cc',
	dependencies: [sqlitedep, json_dep, fmt_dep, cpphttplib, sqlitewriter_dep,
	bcryptcpp_dep, argparse_dep, simplesockets_dep, vcs_dep])


executable('testrunner', 'testrunner.cc', 'support.cc', 'serv.cc',
	dependencies: [sqlitedep, json_dep, fmt_dep, bcryptcpp_dep, argparse_dep, sqlitewriter_dep, cpphttplib, doctest_dep, simplesockets_dep])

