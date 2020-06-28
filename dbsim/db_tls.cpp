/*
 * Copyright (C) 2020 Codership Oy <info@codership.com>
 *
 * This file is part of wsrep-lib.
 *
 * Wsrep-lib is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * Wsrep-lib is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wsrep-lib.  If not, see <https://www.gnu.org/licenses/>.
 */

/** @file db_tls.cpp
 *
 * This file demonstrates the use of TLS service. It does not implement
 * real encryption, but may manipulate stream bytes for testing purposes.
 */

#include "db_tls.hpp"

#include "wsrep/logger.hpp"

#include <unistd.h> // read()/write()
#include <cerrno>

namespace
{
    class db_stream : public wsrep::tls_stream
    {
    public:
        db_stream(int fd)
            : fd_(fd)
        { }
        struct stats
        {
            size_t bytes_read{0};
            size_t bytes_written{0};
        };
        int fd() const { return fd_; }
        void inc_reads(size_t val) { stats_.bytes_read += val; }
        void inc_writes(size_t val) { stats_.bytes_written += val; }
        const stats& get_stats() const { return stats_; }
    private:
        int fd_;
        stats stats_;
    };
}


wsrep::tls_context* db::tls::create_tls_context() WSREP_NOEXCEPT
{
    return 0;
}

void db::tls::destroy(wsrep::tls_context*) WSREP_NOEXCEPT
{ }

wsrep::tls_stream* db::tls::create_tls_stream(
    wsrep::tls_context*, int fd) WSREP_NOEXCEPT
{
    return new db_stream(fd);
}

ssize_t db::tls::client_handshake(wsrep::tls_stream*) WSREP_NOEXCEPT
{
    // @todo: Emulate non-blocking handshake.
    return wsrep::tls_service::success;
}

ssize_t db::tls::server_handshake(wsrep::tls_stream*) WSREP_NOEXCEPT
{
    // @todo: Emulate non-blocking handshake.
    return wsrep::tls_service::success;
}

wsrep::tls_service::op_result db::tls::read(
    wsrep::tls_stream* stream,
    void* buf, size_t max_count) WSREP_NOEXCEPT
{
    auto dbs(static_cast<db_stream*>(stream));
    ssize_t read_result(::read(dbs->fd(), buf, max_count));
    if (read_result > 0)
    {
        dbs->inc_reads(read_result);
        return wsrep::tls_service::op_result{
            wsrep::tls_service::success, size_t(read_result)};
    }
    else if (read_result == 0)
    {
        return wsrep::tls_service::op_result{
            wsrep::tls_service::eof, 0};
    }
    else if (errno == EAGAIN || errno == EWOULDBLOCK)
    {
        return wsrep::tls_service::op_result{
            wsrep::tls_service::want_read, 0};
    }
    else
    {
        return wsrep::tls_service::op_result{
            read_result, 0};
    }
}

wsrep::tls_service::op_result db::tls::write(
    wsrep::tls_stream* stream,
    const void* buf, size_t count) WSREP_NOEXCEPT
{
    auto dbs(static_cast<db_stream*>(stream));
    ssize_t write_result(::write(dbs->fd(), buf, count));
    if (write_result > 0)
    {
        dbs->inc_writes(write_result);
        return wsrep::tls_service::op_result{
            wsrep::tls_service::success, size_t(write_result)};
    }
    else if (write_result == 0)
    {
        return wsrep::tls_service::op_result{
            wsrep::tls_service::eof, 0};
    }
    else if (errno == EAGAIN || errno == EWOULDBLOCK)
    {
        return wsrep::tls_service::op_result{
            wsrep::tls_service::want_write, 0};
    }
    else
    {
        return wsrep::tls_service::op_result{
            write_result, 0};
    }
}

void db::tls::shutdown(wsrep::tls_stream* stream) WSREP_NOEXCEPT
{
    auto dbs(static_cast<db_stream*>(stream));
    wsrep::log_info() << "Stream shutdown: " << dbs->get_stats().bytes_read
                      << " " << dbs->get_stats().bytes_written;
    delete dbs;
}
