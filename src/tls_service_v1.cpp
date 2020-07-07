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

#include "tls_service_v1.hpp"

#include "wsrep/tls_service.hpp"
#include "wsrep/logger.hpp"
#include "v26/wsrep_tls_service.h"
#include "service_helpers.hpp"

namespace wsrep_tls_service_v1
{
    static wsrep::tls_service* tls_service_impl{0};

    static wsrep_tls_context_t* tls_context_create_cb()
    {
        assert(tls_service_impl);
        return reinterpret_cast<wsrep_tls_context_t*>(0x1);
    }

    static void tls_context_free_cb(wsrep_tls_context_t*)
    {
        assert(tls_service_impl);
    }

    static int tls_stream_init_cb(
        wsrep_tls_context_t* context,
        wsrep_tls_stream_t* stream)
    {
        assert(tls_service_impl);
        stream->opaque =
            tls_service_impl->create_tls_stream(
                reinterpret_cast<wsrep::tls_context*>(context), stream->fd);
        if (not stream->opaque)
        {
            return ENOMEM;
        }
        return 0;
    }

    static void tls_stream_deinit_cb(
        wsrep_tls_stream_t* stream)
    {
        assert(tls_service_impl);
        tls_service_impl->destroy(
            reinterpret_cast<wsrep::tls_stream*>(stream->opaque));
    }

    static int tls_stream_get_error_number_cb(const wsrep_tls_stream_t* stream)
    {
        assert(tls_service_impl);
        return tls_service_impl->get_error_number(
            reinterpret_cast<const wsrep::tls_stream*>(stream->opaque));
    }

    static const void* tls_stream_get_error_category_cb(
        const wsrep_tls_stream_t* stream)
    {
        assert(tls_service_impl);
        return tls_service_impl->get_error_category(
            reinterpret_cast<const wsrep::tls_stream*>(stream->opaque));
    }

    static const char* tls_error_message_get_cb(
        int value, const void* category)
    {
        assert(tls_service_impl);
        return tls_service_impl->get_error_message(value, category);
    }

    static enum wsrep_tls_result map_return_value(ssize_t status)
    {
        switch (status)
        {
        case wsrep::tls_service::success:
            return wsrep_tls_result_success;
        case wsrep::tls_service::want_read:
            return wsrep_tls_result_want_read;
        case wsrep::tls_service::want_write:
            return wsrep_tls_result_want_write;
        case wsrep::tls_service::eof:
            return wsrep_tls_result_eof;
        case wsrep::tls_service::error:
            return wsrep_tls_result_error;
        default:
            assert(status < 0);
            return wsrep_tls_result_error;
        }
    }


    static enum wsrep_tls_result
    tls_stream_client_handshake_cb(wsrep_tls_stream_t* stream)
    {
        assert(tls_service_impl);
        return map_return_value(
            tls_service_impl->client_handshake(
                reinterpret_cast<wsrep::tls_stream*>(stream->opaque)));
    }

    static enum wsrep_tls_result
    tls_stream_server_handshake_cb(wsrep_tls_stream_t* stream)
    {
        assert(tls_service_impl);
        return map_return_value(
            tls_service_impl->server_handshake(
                reinterpret_cast<wsrep::tls_stream*>(stream->opaque)));
    }

    static enum wsrep_tls_result tls_stream_read_cb(
        wsrep_tls_stream_t* stream,
        void* buf,
        size_t max_count,
        size_t* bytes_transferred)
    {
        assert(tls_service_impl);
        auto result(tls_service_impl->read(
                        reinterpret_cast<wsrep::tls_stream*>(stream->opaque),
                        buf, max_count));
        *bytes_transferred = result.bytes_transferred;
        return map_return_value(result.status);
    }

    static enum wsrep_tls_result tls_stream_write_cb(
        wsrep_tls_stream_t* stream,
        const void* buf,
        size_t count,
        size_t* bytes_transferred)
    {
        assert(tls_service_impl);
        auto result(tls_service_impl->write(
                        reinterpret_cast<wsrep::tls_stream*>(stream->opaque),
                        buf, count));
        *bytes_transferred = result.bytes_transferred;
        return map_return_value(result.status);
    }

    static enum wsrep_tls_result
    tls_stream_shutdown_cb(wsrep_tls_stream_t* stream)
    {
        assert(tls_service_impl);
        // @todo Handle other values than success.
        return map_return_value(
            tls_service_impl->shutdown(
                reinterpret_cast<wsrep::tls_stream*>(stream->opaque)));
    }

    static wsrep_tls_service_v1_t tls_service_callbacks =
    {
        tls_context_create_cb,
        tls_context_free_cb,
        tls_error_message_get_cb,
        tls_stream_init_cb,
        tls_stream_deinit_cb,
        tls_stream_get_error_number_cb,
        tls_stream_get_error_category_cb,
        tls_stream_client_handshake_cb,
        tls_stream_server_handshake_cb,
        tls_stream_read_cb,
        tls_stream_write_cb,
        tls_stream_shutdown_cb

    };


}

int wsrep::tls_service_v1_probe(void* dlh)
{
    typedef int (*init_fn)(wsrep_tls_service_v1_t*);
    return wsrep_impl::service_probe<init_fn>(
        dlh, WSREP_TLS_SERVICE_INIT_FUNC_V1, "thread service v1");
}

int wsrep::tls_service_v1_init(void* dlh,
                               wsrep::tls_service* tls_service)
{
    if (not (dlh && tls_service)) return EINVAL;

    typedef int (*init_fn)(wsrep_tls_service_v1_t*);
    wsrep_tls_service_v1::tls_service_impl = tls_service;
    int ret(0);
    if ((ret = wsrep_impl::service_init<init_fn>(
             dlh, WSREP_TLS_SERVICE_INIT_FUNC_V1,
             &wsrep_tls_service_v1::tls_service_callbacks,
             "tls service v1")))
    {
        wsrep_tls_service_v1::tls_service_impl = 0;
    }
    return ret;
}

void wsrep::tls_service_v1_deinit(void* dlh)
{
    typedef int (*deinit_fn)();
    wsrep_impl::service_deinit<deinit_fn>(
        dlh, WSREP_TLS_SERVICE_DEINIT_FUNC_V1, "tls service v1");
}
