project('trifecta', 'cpp', default_options : ['cpp_std=c++17'])

sqlitedep = dependency('sqlite3', version : '>3')
thread_dep = dependency('threads')
json_dep = dependency('nlohmann_json')
fmt_dep = dependency('fmt', version: '>9')
cpphttplib = dependency('cpp-httplib')
sqlitewriter_dep = dependency('sqlitewriter')
doctest_dep=dependency('doctest')
cryptopp_dep=dependency('libcrypto++')
bcryptcpp_dep = dependency('bcryptcpp')
argparse_dep = dependency('argparse', version: '>=3')

executable('serv', 'serv.cc', 'support.cc',
	dependencies: [sqlitedep, json_dep, fmt_dep, cpphttplib, sqlitewriter_dep,
	cryptopp_dep, bcryptcpp_dep, argparse_dep])


executable('testrunner', 'testrunner.cc', 'support.cc',
	dependencies: [sqlitedep, json_dep, sqlitewriter_dep, doctest_dep, cryptopp_dep])

