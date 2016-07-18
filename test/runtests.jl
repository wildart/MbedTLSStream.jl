using MbedTLSStream
using Base.Test

# write your own tests here
@test 1 == 1

# err = ccall((:mbedtls_stream_init, :libmbedtlsstream), Cint, (Cstring, Cstring), ENV["SSL_CERT_FILE"], Cstring(C_NULL))
# mbedtls_stream_cb = cglobal((:mbedtls_stream_new, :libmbedtlsstream))
# ccall((:git_stream_register_tls, :libgit2), Cint, (Ptr{Void},), mbedtls_stream_cb)

# test clone
# isdir("TEST-ssl") && rm("TEST-ssl", force=true, recursive=true)
# LibGit2.clone("https://github.com/JuliaLang/Example.jl.git", "TEST-ssl")

# ccall((:mbedtls_stream_shutdown, :libmbedtlsstream), Cint, ())