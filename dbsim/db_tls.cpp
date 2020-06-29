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
            , last_error_()
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

        int get_error_number() const { return last_error_; }
        const void* get_error_category() const { return 0; }
        const char* get_error_message() const
        {
            return ::strerror(last_error_);
        }
        enum wsrep::tls_service::status client_handshake();

        enum wsrep::tls_service::status server_handshake();

        wsrep::tls_service::op_result read(void*, size_t);

        wsrep::tls_service::op_result write(const void*, size_t);

        enum state state() const { return state_; }

        int fd() const { return fd_; }
        void inc_reads(size_t val) { stats_.bytes_read += val; }
        void inc_writes(size_t val) { stats_.bytes_written += val; }
        const stats& get_stats() const { return stats_; }
    private:
        enum wsrep::tls_service::status handle_handshake_read(const char* expect);
        void clear_error() { last_error_ = 0; }

        int fd_;
        enum state state_;
        int last_error_;
        stats stats_;
    };

    enum wsrep::tls_service::status db_stream::client_handshake()
    {
        clear_error();
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
        clear_error();
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

    wsrep::tls_service::op_result db_stream::read(void* buf, size_t max_count)
    {
        clear_error();
        ssize_t read_result(::read(fd_, buf, max_count));
        if (read_result > 0)
        {
            inc_reads(read_result);
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
            last_error_ = errno;
            return wsrep::tls_service::op_result{
                wsrep::tls_service::error, 0};
        }
    }

    wsrep::tls_service::op_result db_stream::write(
        const void* buf, size_t count)
    {
        clear_error();
        ssize_t write_result(::send(fd_, buf, count, MSG_NOSIGNAL));
        if (write_result > 0)
        {
            inc_writes(write_result);
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
            last_error_ = errno;
            return wsrep::tls_service::op_result{
                wsrep::tls_service::error, 0};
        }
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

int db::tls::get_error_number(const wsrep::tls_stream* stream)
    const WSREP_NOEXCEPT
{
    return static_cast<const db_stream*>(stream)->get_error_number();
}

const void* db::tls::get_error_category(const wsrep::tls_stream* stream)
    const WSREP_NOEXCEPT
{
    return static_cast<const db_stream*>(stream)->get_error_category();
}

const char* db::tls::get_error_message(const wsrep::tls_stream* stream)
    const WSREP_NOEXCEPT
{
    return static_cast<const db_stream*>(stream)->get_error_message();
}

enum wsrep::tls_service::status
db::tls::client_handshake(wsrep::tls_stream* stream) WSREP_NOEXCEPT
{
    return static_cast<db_stream*>(stream)->client_handshake();
}

enum wsrep::tls_service::status
db::tls::server_handshake(wsrep::tls_stream* stream) WSREP_NOEXCEPT
{
    return static_cast<db_stream*>(stream)->server_handshake();
}

wsrep::tls_service::op_result db::tls::read(
    wsrep::tls_stream* stream,
    void* buf, size_t max_count) WSREP_NOEXCEPT
{
    return static_cast<db_stream*>(stream)->read(buf, max_count);
}

wsrep::tls_service::op_result db::tls::write(
    wsrep::tls_stream* stream,
    const void* buf, size_t count) WSREP_NOEXCEPT
{
    return static_cast<db_stream*>(stream)->write(buf, count);
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
