# Set project attribute
project('fastauthd', 'c', version: '1.0', license: 'MIT')

glib_dep = dependency('glib-2.0', required: true)
gio_dep = dependency('gio-2.0', required: true)

# Set source file path
FASTAUTHD_PAM_PATH = meson.source_root() / 'fastauthd_pam'
FASTAUTHD_NSS_PATH = meson.source_root() / 'fastauthd_nss'
OIDC_PATH = meson.source_root() / 'fastauthd_oidc'
FASTAUTHD_PATH = meson.source_root() / 'fastauthd'

# Build fastauthd PAM share object
pam_src = FASTAUTHD_PAM_PATH / 'libpam_fastauthd.c'
pam_fastauthd_so = shared_library('pam_fastauthd', pam_src, c_args: ['-fPIC'], dependencies: [dependency('pam'), glib_dep, gio_dep],
                                  link_args: ['-lcrypt', '-lcjson'], install: true,
                                  install_dir: '/usr/lib64/security/')

pam_test_src = FASTAUTHD_PAM_PATH / 'fastauthd_test.c'
pam_fastauthd_test = executable('fastauthd_test', pam_test_src, dependencies: [dependency('pam')],
                                 link_args: ['-lcrypt'], install: true,
                                 install_dir: './')

# Build fastauthd NSS share object
nss_src = FASTAUTHD_NSS_PATH / 'libnss_fastauthd.c'
nss_fastauthd_so = shared_library('nss_fastauthd', nss_src, c_args: ['-fPIC'],
                               install: true, install_dir: '/usr/lib/x86_64-linux-gnu/')

# Build fastauthd oidc
oidc_dbus_interface = OIDC_PATH / 'fastauthd_oidc_introspection.xml'
oidc_dbus_output_file = OIDC_PATH / 'fastauthd_oidc_autogen' / 'fastauthd_oidc_gdbus_autogen'

result = run_command('mkdir', '-p', 'fastauthd_oidc/autogen')
if result.returncode() == 0
    message('Command executed successfully')
else
    message('Command failed with error code: ' + result.returncode().to_string())
    message(result.stdout())
endif

result = run_command('gdbus-codegen',
                     '--interface-prefix=com.fastauthd.oidc.',
                     '--generate-c-code=fastauthd_oidc/autogen/fastauthd_oidc_gdbus_autogen',
                     '--c-namespace=fastauthd_oidc',
                     '--c-generate-object-manager',
                     '--generate-docbook=fastauthd-oidc-docs',
                     oidc_dbus_interface)
if result.returncode() == 0
    message('Command executed successfully')
else
    message('Command failed with error code: ' + result.returncode().to_string())
    message(result.stdout())
endif

oidc_sources = [
    OIDC_PATH / 'fastauthd_oidc.c',
    OIDC_PATH / 'fastauthd_oidc_dbus_service.c',
    OIDC_PATH / 'fastauthd_oidc_msa.c',
    OIDC_PATH / 'autogen' / 'fastauthd_oidc_gdbus_autogen.c',
    'fastauthd_systemd.c',
]
oidc_inc = include_directories('fastauthd_oidc/include')
oidc_program = executable('fastauthd_oidc', oidc_sources,
                          include_directories: [oidc_inc],
                          dependencies: [glib_dep, gio_dep], link_args: ['-lcjson', '-lcurl', '-lsystemd'],
                          install: true, install_dir: '/usr/bin/')


# Build fastauthd
# First step: Using gdbus-codegen to generate code
dbus_interface = FASTAUTHD_PATH / 'fastauthd_introspection.xml'
dbus_output_file = FASTAUTHD_PATH / 'fastauthd_autogen' / 'fastauthd_gdbus_autogen'

result = run_command('mkdir', '-p', 'fastauthd/autogen')
if result.returncode() == 0
    message('Command executed successfully')
else
    message('Command failed with error code: ' + result.returncode().to_string())
    message(result.stdout())
endif

result = run_command('gdbus-codegen',
                     '--interface-prefix=com.fastauthd.broker.',
                     '--generate-c-code=fastauthd/autogen/fastauthd_gdbus_autogen',
                     '--c-namespace=fastauthd',
                     '--c-generate-object-manager',
                     '--generate-docbook=fastauthd-docs',
                     dbus_interface)
if result.returncode() == 0
    message('Command executed successfully')
else
    message('Command failed with error code: ' + result.returncode().to_string())
    message(result.stdout())
endif

fastauthd_sources = [
    FASTAUTHD_PATH / 'fastauthd.c',
    FASTAUTHD_PATH / 'fastauthd_dbus_service.c',
    FASTAUTHD_PATH / 'fastauthd_nssdb_manager.c',
    FASTAUTHD_PATH / 'autogen' / 'fastauthd_gdbus_autogen.c',
    FASTAUTHD_PATH / 'fastauthd_config.c',
    'fastauthd_systemd.c',
]

fastauthd_inc = include_directories('fastauthd/include')
fastauthd_program = executable('fastauthd', fastauthd_sources,
                               include_directories: [fastauthd_inc],
                               dependencies: [glib_dep, gio_dep], link_args: ['-lsystemd', '-lcjson', '-ljwt'],
                               install: true, install_dir: '/usr/bin/')
# Set install path
systemd_install_dir = '/etc/systemd/system/'
systemd_service_file_dir = meson.source_root() / 'systemd_services'

systemd_fastauthd_service_file = systemd_service_file_dir / 'fastauthd.service'
install_data(systemd_fastauthd_service_file, install_dir: systemd_install_dir)
systemd_fastauthd_oidc_service_file = systemd_service_file_dir / 'fastauthd_oidc.service'
install_data(systemd_fastauthd_oidc_service_file, install_dir: systemd_fastauthd_oidc_service_file)

# Clean cache file
clean = custom_target('fastauthd_clean',
  command: ['rm', '-rf', meson.build_root() / 'build'],
  output: 'fastauthd_clean')
