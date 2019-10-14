from building import *

# get current directory
cwd     = GetCurrentDir()
# The set of source files associated with this SConscript file.
src     = Split("""
src/smtp_client_data.c
src/smtp_client.c
""")

if GetDepend(['SMTP_CLIENT_USING_TLS']):
    src += Glob('src/smtp_client_tls.c')

if GetDepend(['SMTP_CLIENT_USING_SAMPLE']):
    src += Glob('example/smtp_client_example.c')

path    = [cwd + '/inc']

group = DefineGroup('smtp_client', src, depend = ['PKG_USING_SMTP_CLIENT'], CPPPATH = path)

Return('group')
