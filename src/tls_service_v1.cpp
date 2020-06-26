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

#include <dlfcn.h>
#include <cerrno>

namespace wsrep_tls_service_v1
{
    static wsrep::tls_service* tls_service_impl{0};

    static wsrep_tls_context_t* tls_context_create_cb()
    {
        assert(tls_service_impl);
        return reinterpret_cast<wsrep_tls_context_t*>(
            tls_service_impl->create_tls_context());
    }

    static void tls_context_free_cb(wsrep_tls_context_t* context)
    {
        assert(tls_service_impl);
        tls_service_impl->destroy(
            reinterpret_cast<wsrep::tls_context*>(context));
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

    static wsrep_tls_service_v1_t tls_service_callbacks =
    {
        tls_context_create_cb,
        tls_context_free_cb,
        0,
        0,
        tls_stream_init_cb,
    };


}

int wsrep::tls_service_v1_init(void* dlh,
                               wsrep::tls_service* tls_service)
{
    if (not (dlh && tls_service)) return EINVAL;

    typedef int (*init_fn)(wsrep_tls_service_v1_t*);
    union {
        init_fn dlfun;
        void* obj;
    } alias;
    alias.obj = dlsym(dlh, WSREP_TLS_SERVICE_INIT_FUNC_V1);
    if (alias.obj)
    {
        wsrep::log_info() << "Initializing TLS instrumentation";
        wsrep_tls_service_v1::tls_service_impl = tls_service;
        return (*alias.dlfun)(&wsrep_tls_service_v1::tls_service_callbacks);
    }
    else
    {
        wsrep::log_info()
            << "Provider does not support TLS instrumentation";
        return ENOTSUP;
    }
}
