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

#include <unistd.h> // read()
#include <sys/types.h>
#include <sys/socket.h> // send()
#include <cerrno>
#include <cstring>

#include <mutex>
#include <string>

namespace
{
    class db_stream : public wsrep::tls_stream
    {
    public:
        db_stream(int fd)
            : fd_(fd)
            , state_(s_initialized)
        { }
        struct stats
        {
            size_t bytes_read{0};
            size_t bytes_written{0};
        };

        /*
         *    in       |--> idle --|
         *     |-> ch -|      ^    | -> want_read  --|
         *     |-> sh -|      |    | -> want_write --|
         *                    |----------------------|
         */
        enum state
        {
            s_initialized,
            s_client_handshake,
            s_server_handshake,
            s_idle,
            s_want_read,
            s_want_write
        };

        enum wsrep::tls_service::status client_handshake();

        enum wsrep::tls_service::status server_handshake();

        enum state state() const { return state_; }

        int fd() const { return fd_; }
        void inc_reads(size_t val) { stats_.bytes_read += val; }
        void inc_writes(size_t val) { stats_.bytes_written += val; }
        const stats& get_stats() const { return stats_; }
    private:
        enum wsrep::tls_service::status handle_handshake_read(const char* expect);

        int fd_;
        enum state state_;
        stats stats_;
    };

    enum wsrep::tls_service::status db_stream::client_handshake()
    {
        enum wsrep::tls_service::status ret;
        assert(state_ == s_initialized || state_ == s_client_handshake);
        if (state_ == s_initialized)
        {
            (void)::send(fd_, "clie", 4, MSG_NOSIGNAL);
            ret = wsrep::tls_service::want_read;
            state_ = s_client_handshake;
            wsrep::log_info() << this << " client handshake sent";
            stats_.bytes_written += 4;
        }
        else
        {
            if ((ret = handle_handshake_read("serv")) ==
                wsrep::tls_service::success)
            {
                state_ = s_idle;
            }
        }
        return ret;
    }

    enum wsrep::tls_service::status db_stream::server_handshake()
    {
        enum wsrep::tls_service::status ret;
        assert(state_ == s_initialized || state_ == s_server_handshake);
        if (state_ == s_initialized)
        {
            ::send(fd_, "serv", 4, MSG_NOSIGNAL);
            ret = wsrep::tls_service::want_read;
            state_ = s_server_handshake;
            stats_.bytes_written += 4;
        }
        else
        {
            if ((ret = handle_handshake_read("clie")) ==
                wsrep::tls_service::success)
            {
                state_ = s_idle;
            }
        }
        return ret;
    }

    enum wsrep::tls_service::status db_stream::handle_handshake_read(
        const char* expect)
    {
        assert(::strlen(expect) >= 4);
        char buf[4] = { };
        ssize_t read_result(::read(fd_, buf, sizeof(buf)));
        if (read_result > 0) stats_.bytes_read += read_result;
        enum wsrep::tls_service::status ret;
        if (read_result == -1 &&
            (errno == EWOULDBLOCK || errno == EAGAIN))
        {
            ret = wsrep::tls_service::want_read;
        }
        else if (read_result == 0)
        {
            ret = wsrep::tls_service::eof;
        }
        else if (read_result != 4 || ::memcmp(buf, expect, 4))
        {
            ret = wsrep::tls_service::error;
        }
        else
        {
            ret = wsrep::tls_service::success;
        }
        return ret;
    }
}


static db_stream::stats global_stats;
std::mutex global_stats_lock;

static void merge_to_global_stats(const db_stream::stats& stats)
{
    std::lock_guard<std::mutex> lock(global_stats_lock);
    global_stats.bytes_read += stats.bytes_read;
    global_stats.bytes_written += stats.bytes_written;
}



wsrep::tls_context* db::tls::create_tls_context() WSREP_NOEXCEPT
{
    return reinterpret_cast<wsrep::tls_context*>(1);
}

void db::tls::destroy(wsrep::tls_context*) WSREP_NOEXCEPT
{ }

wsrep::tls_stream* db::tls::create_tls_stream(
    wsrep::tls_context*, int fd) WSREP_NOEXCEPT
{
    auto ret(new db_stream(fd));
    wsrep::log_debug() << "New DB stream: " << ret;
    return ret;
}

ssize_t db::tls::client_handshake(wsrep::tls_stream* stream) WSREP_NOEXCEPT
{
    return reinterpret_cast<db_stream*>(stream)->client_handshake();
}

ssize_t db::tls::server_handshake(wsrep::tls_stream* stream) WSREP_NOEXCEPT
{
    return reinterpret_cast<db_stream*>(stream)->server_handshake();
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
    ssize_t write_result(::send(dbs->fd(), buf, count, MSG_NOSIGNAL));
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
    merge_to_global_stats(dbs->get_stats());
    wsrep::log_debug() << "Stream shutdown: " << dbs->get_stats().bytes_read
                      << " " << dbs->get_stats().bytes_written;
    wsrep::log_debug() << "Stream pointer" << dbs;
    delete dbs;
}

std::string db::tls::stats()
{
    std::ostringstream oss;
    oss << "Transport stats:\n"
        << "  bytes_read: " << global_stats.bytes_read << "\n"
        << "  bytes_written: " << global_stats.bytes_written << "\n";
    return oss.str();
}
