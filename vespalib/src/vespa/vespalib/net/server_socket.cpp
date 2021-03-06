// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "server_socket.h"
#include "socket_spec.h"
#include <sys/stat.h>
#include <dirent.h>

#include <vespa/log/log.h>
LOG_SETUP(".vespalib.net.server_socket");

namespace vespalib {

bool is_socket(const vespalib::string &path) {
    struct stat info;
    if (path.empty() || (lstat(path.c_str(), &info) != 0)) {
        return false;
    }
    return S_ISSOCK(info.st_mode);
}

void
ServerSocket::cleanup()
{
    if (valid() && is_socket(_path)) {
        unlink(_path.c_str());
    }
}

ServerSocket::ServerSocket(const SocketSpec &spec)
    : _handle(spec.server_address().listen()),
      _path(spec.path())
{
    if (!_handle.valid() && is_socket(_path)) {
        if (!spec.client_address().connect_async().valid()) {
            LOG(warning, "removing old socket: '%s'", _path.c_str());
            unlink(_path.c_str());
            _handle = spec.server_address().listen();
        }
    }
    if (!_handle.valid()) {
        LOG(warning, "listen failed: '%s'", spec.spec().c_str());
    }
}

ServerSocket::ServerSocket(const vespalib::string &spec)
    : ServerSocket(SocketSpec(spec))
{
}

ServerSocket::ServerSocket(int port)
    : ServerSocket(SocketSpec::from_port(port))
{
}

ServerSocket::ServerSocket(ServerSocket &&rhs)
    : _handle(std::move(rhs._handle)),
      _path(std::move(rhs._path))
{
    rhs._path.clear();
}

ServerSocket &
ServerSocket::operator=(ServerSocket &&rhs)
{
    cleanup();
    _handle = std::move(rhs._handle);
    _path = std::move(rhs._path);
    rhs._path.clear();
    return *this;
}

SocketAddress
ServerSocket::address() const
{
    return SocketAddress::address_of(_handle.get());
}

void
ServerSocket::shutdown()
{
    _handle.shutdown();
}

SocketHandle
ServerSocket::accept()
{
    return _handle.accept();
}

} // namespace vespalib
