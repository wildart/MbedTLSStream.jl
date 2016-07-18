module MbedTLSStream

using MbedTLS

const roots = ObjectIdDict()
push_root(obj) = (roots[obj] = nothing)
pop_root(obj) = delete!(roots, obj)

function set_error(cls::LibGit2.Error.Class, msg::String)
    ccall((:giterr_set_str, :libgit2), Void, (Cint, Cstring), Cint(cls), msg)
    return
end

function ssl_set_error(error)
    @assert error != MbedTLS.MBEDTLS_ERR_SSL_WANT_READ
    @assert error != MbedTLS.MBEDTLS_ERR_SSL_WANT_WRITE

    errstr = error != 0 ? MbedTLS.strerror(error) : "unknown SSL error"

    set_error(LibGit2.Error.SSL, "SSL error: $(num2hex(Int16(error))) - $errstr")
    return Cint(error)
end

function memcpy(src::Ptr{UInt8}, sz)
    dest = convert(Ptr{UInt8}, Libc.malloc(sizeof(UInt8) * sz))
    unsafe_copy!(dest, src, sz)
    return dest
end
memcpy(src::Cstring, sz) = memcpy(convert(Ptr{UInt8}, src), sz)

function init_ssl()
    info("Initializing MbedTLS...")

    global tls_entropy = MbedTLS.Entropy()
    global tls_rng = MbedTLS.CtrDrbg()
    MbedTLS.seed!(tls_rng, tls_entropy)

    global tls_conf = MbedTLS.SSLConfig()
    MbedTLS.rng!(tls_conf, tls_rng)
    MbedTLS.config_defaults!(tls_conf)
    MbedTLS.authmode!(tls_conf, MbedTLS.MBEDTLS_SSL_VERIFY_REQUIRED)
    MbedTLS.ca_chain!(tls_conf, MbedTLS.crt_parse_file(ENV["SSL_CERT_FILE"]))
end

@enum GIT_CERT CERT_NONE CERT_X509 GIT_CERT_HOSTKEY_LIBSSH2 GIT_CERT_STRARRAY

immutable GitCert
    cert_type::Cint
end
GitCert(ctype::GIT_CERT) = GitCert(Cint(ctype))

immutable GitCertX509
    parent::GitCert
    data::Ptr{Void} # Pointer to the X.509 certificate data
    len::Csize_t    # Length of the memory block pointed to by `data`.
end
GitCertX509(data::Ptr{Void}, len::Int) = GitCertX509(GitCert(CERT_X509), data, Csize_t(len))
GitCertX509() = GitCertX509(C_NULL, 0)

immutable GitStream
    version::Cint

    encrypted::Cint
    proxy_support::Cint

    connect::Ptr{Void}     # int (*connect)(struct git_stream *);
    certificate::Ptr{Void} # int (*certificate)(git_cert **, struct git_stream *);
    set_proxy::Ptr{Void}   # int (*set_proxy)(struct git_stream *, const char *proxy_url);
    read::Ptr{Void}        # ssize_t (*read)(struct git_stream *, void *, size_t);
    write::Ptr{Void}       # ssize_t (*write)(struct git_stream *, const char *, size_t, int);
    close::Ptr{Void}       # int (*close)(struct git_stream *);
    free::Ptr{Void}        # void (*free)(struct git_stream *);
end
GitStream(; encrypted::Cint = zero(Cint),
            proxy_support::Cint = zero(Cint),
            connect::Ptr{Void} = C_NULL,
            certificate::Ptr{Void} = C_NULL,
            set_proxy::Ptr{Void} = C_NULL,
            read::Ptr{Void} = C_NULL,
            write::Ptr{Void} = C_NULL,
            close::Ptr{Void} = C_NULL,
            free::Ptr{Void} = C_NULL) =
    GitStream(one(Cint),
              encrypted,
              proxy_support,
              connect,
              certificate,
              set_proxy,
              read,
              write,
              close,
              free)

type TLSStream
    sock::TCPSocket
    host::String
    port::String
    ctx::MbedTLS.SSLContext # mbedtls_ssl_context *ssl;
    cert::GitCertX509 # git_cert_x509 cert_info;
end

type TLSWrapper
    parent::GitStream
    stream::Ptr{TLSStream}
end

function getstream(tls_ptr::Ptr{TLSWrapper})
    tls = unsafe_load(tls_ptr,1)
    stream = unsafe_pointer_to_objref(tls.stream)
end

function bio_write(ctx_stm::Ptr{Void}, c_msg::Ptr{UInt8}, sz::Csize_t)
    print("bio_write: $sz => ")
    jl_ctx = unsafe_pointer_to_objref(ctx_stm)
    print("B: $jl_ctx ")
    n = unsafe_write(jl_ctx, c_msg, sz)
    println("A: $jl_ctx => $n")
    return Cint(n)
end

function bio_read(ctx_stm::Ptr{Void}, c_msg::Ptr{UInt8}, sz::Csize_t)
    print("bio_read: $sz <= ")
    jl_ctx = unsafe_pointer_to_objref(ctx_stm)
    print("B: $jl_ctx")
    n = unsafe_read(jl_ctx, c_msg, sz)
    n = n != nothing ? n : sz
    println("A: $jl_ctx => $n")
    return Cint(n)
end

function tls_stream_connect(tls_ptr::Ptr{TLSWrapper})
    stream = getstream(tls_ptr)
    try
        # println(stream.host, " ", stream.port)

        Base.connect!(stream.sock, stream.host, parse(UInt16, stream.port))

        MbedTLS.hostname!(stream.ctx, stream.host)
        MbedTLS.set_bio!(stream.ctx, stream.sock)
        # stream.ctx.bio = stream.sock
        # MbedTLS.set_bio!(stream.ctx,
        #                  pointer_from_objref(stream.sock),
        #                  cfunction(bio_write, Cint, (Ptr{Void}, Ptr{UInt8}, Csize_t)),
        #                  cfunction(bio_read, Cint, (Ptr{Void}, Ptr{UInt8}, Csize_t)))
        MbedTLS.handshake(stream.ctx)
    catch ex
        ret = if isa(ex, MbedTLS.MbedException)
            ssl_set_error(ex.ret)
        else
            set_error(LibGit2.Error.SSL, "$ex")
            Cint(-1)
        end
        return ret
    end

    return zero(Cint)
end

function tls_stream_certificate(out::Ptr{Ptr{Void}}, stream::Ptr{Void})
    # out[] = Ref(GitCert(CERT_X509))
    println("tls_stream_certificate: ")
    return zero(Cint)
end

function tls_stream_setproxy(stream::Ptr{Void}, proxyurl::Cstring)
    println("tls_stream_setproxy: ")
    return zero(Cint)
end

function tls_stream_read(tls_ptr::Ptr{TLSWrapper}, data::Ptr{UInt8}, len::Csize_t)
    stream = getstream(tls_ptr)
    ret = ccall((:mbedtls_ssl_read, MbedTLS.MBED_TLS), Cint,
                (Ptr{Void}, Ptr{Void}, Csize_t),
                stream.ctx.data, data, len)
    ret <= 0 && ssl_set_error(ret)
    return Cint(ret)
end

function tls_stream_write(tls_ptr::Ptr{TLSWrapper}, data::Ptr{UInt8}, len::Csize_t, flags::Cint)
    stream = getstream(tls_ptr)
    ret = ccall((:mbedtls_ssl_write, MbedTLS.MBED_TLS), Cint,
              (Ptr{Void}, Ptr{Void}, Csize_t),
              stream.ctx.data, data, len)
    ret <= 0 && ssl_set_error(ret)
    return Cint(ret)
end

function tls_stream_close(tls_ptr::Ptr{TLSWrapper})
    stream = getstream(tls_ptr)

    # close SSL context
    try
        if isopen(stream.sock)
            close(stream.ctx)
        end
    catch
        return Cint(-1)
    end

    # close socket
    Base.uvfinalize(stream.sock)

    # println("$(stream.sock)")

    return zero(Cint)
end

function tls_stream_free(tls_ptr::Ptr{TLSWrapper})
    stream = getstream(tls_ptr)

    # remove anchor
    pop_root(stream)

    # clear wrapper memory
    Libc.free(tls_ptr)

    return
end

function tls_stream(out::Ptr{Ptr{Void}}, host::Cstring, port::Cstring)

    # Create socket: socket.jl:243
    sock = TCPSocket(Libc.malloc(Base._sizeof_uv_tcp))
    Base.associate_julia_struct(sock.handle,sock)
    err = ccall(:uv_tcp_init,Cint,(Ptr{Void},Ptr{Void}),
                Base.eventloop(),sock.handle)
    if err != 0
        Libc.free(sock.handle)
        sock.handle = C_NULL
        return Cint(-1)
    end
    sock.status = Base.StatusInit

    # init ssl context
    ctx = MbedTLS.SSLContext()
    MbedTLS.setup!(ctx, tls_conf)

    io = TLSStream(
        sock,
        unsafe_string(host),
        unsafe_string(port),
        ctx,
        GitCertX509()
    )
    push_root(io)

    parent = GitStream(
        encrypted   = one(Cint),
        connect     = cfunction(tls_stream_connect, Cint, (Ptr{TLSWrapper},)),
        certificate = cfunction(tls_stream_certificate, Cint, (Ptr{Ptr{Void}}, Ptr{Void})),
        set_proxy   = cfunction(tls_stream_setproxy, Cint, (Ptr{Void}, Cstring)),
        read        = cfunction(tls_stream_read, Cint, (Ptr{TLSWrapper}, Ptr{UInt8}, Csize_t)),
        write       = cfunction(tls_stream_write, Cint, (Ptr{TLSWrapper}, Ptr{UInt8}, Csize_t, Cint)),
        close       = cfunction(tls_stream_close, Cint, (Ptr{TLSWrapper},)),
        free        = cfunction(tls_stream_free, Void, (Ptr{TLSWrapper},))
    )

    tls = TLSWrapper(
        parent,
        pointer_from_objref(io)
    )

    # duplicate tls stream structure (to avoid GC)
    data = memcpy(convert(Ptr{UInt8}, pointer_from_objref(tls)), sizeof(tls))
    unsafe_store!(out, data, 1)

    return zero(Cint)
end

function __init__()
    init_ssl()
    const tls_stream_cb = cfunction(tls_stream, Cint, (Ptr{Ptr{Void}}, Cstring, Cstring))
    ccall((:git_stream_register_tls, :libgit2), Cint, (Ptr{Void},), tls_stream_cb)
end

end # module
