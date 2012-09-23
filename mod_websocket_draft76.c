/*
 * Copyright 2010-2012 self.disconnect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*                       _                _                     _         _
 *   _ __ ___   ___   __| | __      __ _ | |__  ___  ___   ___ | | __ _ _| |_   mod_websocket
 *  | '_ ` _ \ / _ \ / _` | \ \ /\ / / _ \ '_ \/ __// _ \ / __\| |/ / _ \_  _|  Apache Interface to WebSocket
 *  | | | | | | (_) | (_| |  \ V  V /  __/ |_) )__ \ (_) | (___|   (  __/| |__
 *  |_| |_| |_|\___/ \__,_|___\_/\_/ \___|_,__/|___/\___/ \___/|_|\_\___| \__/
 *                       |_____|
 *   mod_websocket_draft76.c
 *   Apache API inteface structures
 */

#include "apr_md5.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"

#include "websocket_plugin.h"

#define CORE_PRIVATE
#include "http_core.h"
#include "http_connection.h"

#if !defined(APR_ARRAY_IDX)
#define APR_ARRAY_IDX(ary,i,type) (((type *)(ary)->elts)[i])
#endif
#if !defined(APR_ARRAY_PUSH)
#define APR_ARRAY_PUSH(ary,type) (*((type *)apr_array_push(ary)))
#endif

module AP_MODULE_DECLARE_DATA websocket_draft76_module;

typedef struct
{
    int support_draft75;
    char *location;
    apr_dso_handle_t *res_handle;
    WebSocketPlugin *plugin;
} websocket_config_rec;

/* The extended data size must be at least as big as the block data size */
#define BLOCK_DATA_SIZE              4096
#define EXTENDED_DATA_SIZE          16384

#define DATA_FRAMING_READ_TYPE          0
#define DATA_FRAMING_IN_TEXT_DATA       1
#define DATA_FRAMING_IN_BINARY_DATA     2
#define DATA_FRAMING_IN_BINARY_LENGTH   3
#define DATA_FRAMING_CLOSE              4

/*
 * Configuration
 */

static void *mod_websocket_create_dir_config(apr_pool_t *p, char *path)
{
    websocket_config_rec *conf = NULL;

    if (path != NULL) {
        conf = apr_pcalloc(p, sizeof(websocket_config_rec));
        if (conf != NULL) {
            conf->location = apr_pstrdup(p, path);
        }
    }
    return (void *) conf;
}

static apr_status_t mod_websocket_cleanup_config(void *data)
{
    if (data != NULL) {
        websocket_config_rec *conf = (websocket_config_rec *) data;

        if (conf != NULL) {
            if ((conf->plugin != NULL) && (conf->plugin->destroy != NULL)) {
                conf->plugin->destroy(conf->plugin);
            }
            conf->plugin = NULL;
            if (conf->res_handle != NULL) {
                apr_dso_unload(conf->res_handle);
                conf->res_handle = NULL;
            }
        }
    }
    return APR_SUCCESS;
}

static const char *mod_websocket_conf_handler(cmd_parms *cmd, void *confv, const char *path, const char *name)
{
    websocket_config_rec *conf = (websocket_config_rec *) confv;
    char *response;

    if ((conf != NULL) && (path != NULL) && (name != NULL)) {
        apr_dso_handle_t *res_handle = NULL;
        apr_dso_handle_sym_t sym;

        if (apr_dso_load(&res_handle, ap_server_root_relative(cmd->pool, path), cmd->pool) == APR_SUCCESS) {
            if ((apr_dso_sym(&sym, res_handle, name) == APR_SUCCESS) && (sym != NULL)) {
                WebSocketPlugin *plugin = ((WS_Init) sym) ();
                if ((plugin != NULL) &&
                    (plugin->version == WEBSOCKET_PLUGIN_VERSION_0) &&
                    (plugin->size >= sizeof(WebSocketPlugin)) &&
                    (plugin->on_message != NULL)) { /* Require an on_message handler */
                    conf->res_handle = res_handle;
                    conf->plugin = plugin;
                    apr_pool_cleanup_register(cmd->pool, conf, mod_websocket_cleanup_config, apr_pool_cleanup_null);
                    response = NULL;
                }
                else {
                    apr_dso_unload(res_handle);
                    response = "Invalid response from initialization function";
                }
            }
            else {
                apr_dso_unload(res_handle);
                response = "Could not find initialization function in module";
            }
        }
        else {
            response = "Could not open WebSocket handler module";
        }
    }
    else {
        response = "Invalid parameters";
    }
    return response;
}

/*
 * Functions available to plugins.
 */

typedef struct _WebSocketState
{
    request_rec *r;
    apr_bucket_brigade *obb;
    apr_thread_mutex_t *mutex;
    apr_array_header_t *protocols;
    int closing;
    int using_draft75;
} WebSocketState;

static request_rec *CALLBACK mod_websocket_request(const struct _WebSocketServer *server)
{
    if ((server != NULL) && (server->state != NULL)) {
        return server->state->r;
    }
    return NULL;
}

static const char *CALLBACK mod_websocket_header_get(const struct _WebSocketServer *server, const char *key)
{
    if ((server != NULL) && (server->state != NULL) && (key != NULL)) {
        WebSocketState *state = server->state;

        if (state->r != NULL) {
            return apr_table_get(state->r->headers_in, key);
        }
    }
    return NULL;
}

static void CALLBACK mod_websocket_header_set(const struct _WebSocketServer *server, const char *key, const char *value)
{
    if ((server != NULL) && (server->state != NULL) && (key != NULL) && (value != NULL)) {
        WebSocketState *state = server->state;

        if (state->r != NULL) {
            apr_table_setn(state->r->headers_out, key, value);
        }
    }
}

static void mod_websocket_parse_protocol(const WebSocketServer *server, const char *sec_websocket_protocol)
{
    /*
     * The client-supplied WebSocket protocol entry consists of a space-delimited
     * list of client-side supported protocols. Parse the list, and create an
     * array containing those protocol names.
     */
    if ((server != NULL) && (server->state != NULL) && (server->state->r != NULL)) {
        apr_array_header_t *protocols = apr_array_make(server->state->r->pool, 1, sizeof(char *));
        char *protocol_state = NULL;
        char *protocol = apr_strtok(apr_pstrdup(server->state->r->pool, sec_websocket_protocol), " ", &protocol_state);

        while (protocol != NULL) {
            APR_ARRAY_PUSH(protocols, char *) = protocol;
            protocol = apr_strtok(NULL, " ", &protocol_state);
        }
        if (!apr_is_empty_array(protocols)) {
            server->state->protocols = protocols;
        }
    }
}

static size_t CALLBACK mod_websocket_protocol_count(const struct _WebSocketServer *server)
{
    size_t count = 0;

    if ((server != NULL) && (server->state != NULL) && (server->state->protocols != NULL) && !apr_is_empty_array(server->state->protocols)) {
        count = (size_t) server->state->protocols->nelts;
    }
    return count;
}

static const char *CALLBACK mod_websocket_protocol_index(const struct _WebSocketServer *server, const size_t index)
{
    if ((index >= 0) && (index < mod_websocket_protocol_count(server))) {
        return APR_ARRAY_IDX(server->state->protocols, index, char *);
    }
    return NULL;
}

static void CALLBACK mod_websocket_protocol_set(const struct _WebSocketServer *server, const char *protocol)
{
    if ((server != NULL) && (server->state != NULL)) {
        WebSocketState *state = server->state;

        mod_websocket_header_set(server, "Sec-WebSocket-Protocol" + state->using_draft75, protocol);
    }
}

static size_t CALLBACK mod_websocket_plugin_send(const struct _WebSocketServer *server, const int type, const unsigned char *buffer, const size_t buffer_size)
{
    size_t written = 0;

    if ((server != NULL) && (server->state != NULL)) {
        WebSocketState *state = server->state;

        apr_thread_mutex_lock(state->mutex);

        if ((state->r != NULL) && (state->obb != NULL) && !state->closing) {
            ap_filter_t *of = state->r->connection->output_filters;
            const char header = (char) type;

            ap_fwrite(of, state->obb, &header, 1);
            if (type >= 0x80) {
                /* Binary data */
                char length[16], tmp;
                size_t buffer_length = (buffer != NULL) ? buffer_size : 0;
                int n = 0, half, i;

                /* Fill in the length bytes (in reverse order) */
                do {
                    /*
                     * Turn on the high-order bit for each byte in the length sequence
                     * (we will turn it off for the last byte later)
                     */
                    length[n++] = (buffer_length & 0x7F) | 0x80;
                    buffer_length >>= 7;
                } while (buffer_length != 0);

                /*
                 * Turn off the high-order bit for the last byte in the length sequence
                 * (which is actually the first, as the bytes are reversed)
                 */
                length[0] &= 0x7F;

                /* Since we filled in the length bytes backwards, reverse them */
                half = n >> 1;
                for (i = 0; i < half; i++) {
                    tmp = length[i];
                    length[i] = length[n - i - 1];
                    length[n - i - 1] = tmp;
                }

                /* Write the /length/ bytes */
                ap_fwrite(of, state->obb, length, n);

                if ((buffer != NULL) && (buffer_size > 0)) {
                    /* If we have /data/, write it */
                    ap_fwrite(of, state->obb, (const char *) buffer, buffer_size);
                    written = buffer_size;
                }

                if ((type == 0xFF) && (buffer == NULL) && (buffer_size == 0) && !state->using_draft75) {
                    /* Special case for closing the connection */
                    state->closing = 1;
                }
            }
            else {
                /* Text data */
                const char trailer = '\xFF';

                if (buffer != NULL) {
                    /* If we have /data/, write it */
                    ap_fwrite(of, state->obb, (const char *) buffer, buffer_size);
                    written = buffer_size;
                }
                ap_fwrite(of, state->obb, &trailer, 1);
            }
            ap_fflush(of, state->obb);
        }
        apr_thread_mutex_unlock(state->mutex);
    }
    return written;
}

static void CALLBACK mod_websocket_plugin_close(const WebSocketServer *server)
{
    if ((server != NULL) && (server->state != NULL)) {
        WebSocketState *state = server->state;

        if (!state->using_draft75) {
            /* Send closing handshake */
            mod_websocket_plugin_send(server, 0xFF, NULL, 0);
            /*
             * The clients -- at least Chrome and Safari (with latest WebKit) -- do not
             * respond to the "terminate the WebSocket connection" byte sequence of
             * 0xFF 0x00. So, just close the connection.
             */
        }
        state->r->connection->keepalive = AP_CONN_CLOSE;

        ap_lingering_close(state->r->connection);       /* Is there a better way? -- FIXME */
    }
}

/*
 * Read a buffer of data from the input stream.
 */
static int mod_websocket_read_block(request_rec *r, char *buffer, apr_size_t bufsiz)
{
    apr_status_t rv;
    apr_bucket_brigade *bb;
    apr_size_t readbufsiz = 0;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (bb != NULL) {
        if ((rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, bufsiz)) == APR_SUCCESS) {
            if ((rv = apr_brigade_flatten(bb, buffer, &bufsiz)) == APR_SUCCESS) {
                readbufsiz = bufsiz;
            }
        }
        apr_brigade_destroy(bb);
    }
    return readbufsiz;
}

/*
 * Decode a handshake key into its corresponding number and spaces.
 */
static apr_uint32_t mod_websocket_decode(const char *key, int *spaces)
{
    apr_uint32_t number = 0;
    int num_spaces = 0;

    const char *ptr;

    for (ptr = key; *ptr != '\0'; ptr++) {
        if ((*ptr >= '0') && (*ptr <= '9')) {
            number = number * 10 + (*ptr - '0');
        }
        else if (*ptr == ' ') {
            num_spaces++;
        }
    }
    *spaces = num_spaces;

    return number;
}

/*
 * Pack a 32-bit number into its corresponding big-endian equivalent.
 */
static void mod_websocket_pack(apr_uint32_t number, unsigned char *packed)
{
    packed[0] = (unsigned char) ((number >> 24) & 0xFF);
    packed[1] = (unsigned char) ((number >> 16) & 0xFF);
    packed[2] = (unsigned char) ((number >> 8) & 0xFF);
    packed[3] = (unsigned char) ((number) & 0xFF);
}

/*
 * Determine the client challenge from three keys.
 */
static int mod_websocket_challenge(const char *key1, const char *key2, const char *key3, unsigned char *challenge)
{
    int status = -1, spaces1 = 0, spaces2 = 0;
    apr_uint32_t number1 = mod_websocket_decode(key1, &spaces1);
    apr_uint32_t number2 = mod_websocket_decode(key2, &spaces2);
    /*
     * Make sure that the number of spaces is greater than 0, and that the number
     * is an integral multiple of the number of spaces.
     */
    if ((spaces1 > 0) && ((number1 % spaces1) == 0) &&
        (spaces2 > 0) && ((number2 % spaces2) == 0)) {
        apr_uint32_t part1 = number1 / spaces1;
        apr_uint32_t part2 = number2 / spaces2;

        mod_websocket_pack(part1, challenge);
        mod_websocket_pack(part2, challenge + 4);
        memcpy(challenge + 8, key3, 8);
        status = 0;
    }
    return status;
}

static int mod_websocket_handshake(const char *key1, const char *key2, const char *key3, unsigned char *response)
{
    int status = -1;

    if ((key1 != NULL) && (key2 != NULL) && (key3 != NULL) && (response != NULL)) {
        unsigned char challenge[16] = { 0 };

        if (!(status = mod_websocket_challenge(key1, key2, key3, challenge))) {
            if (apr_md5(response, challenge, (apr_size_t) sizeof(challenge)) == APR_SUCCESS) {
                status = 0;
            }
        }
    }
    return status;
}

/*
 * This is the WebSocket request handler. Since WebSocket headers are quite
 * similar to HTTP headers, we will use most of the HTTP protocol handling
 * code. The difference is that we will disable the HTTP content body handling,
 * and then process the body according to the WebSocket specification.
 */
static int mod_websocket_method_handler(request_rec *r)
{
    if ((strcmp(r->handler, "websocket-handler") == 0) &&
        (r->method_number == M_GET) && (r->parsed_uri.path != NULL) && (r->headers_in != NULL)) {
        const char *upgrade = apr_table_get(r->headers_in, "Upgrade");

        if ((upgrade != NULL) && !strcasecmp(upgrade, "WebSocket")) {
            /* Need to serialize the connections to minimize a denial of service attack -- FIXME */

            const char *connection = apr_table_get(r->headers_in, "Connection");
            const char *sec_websocket_key1 = apr_table_get(r->headers_in, "Sec-WebSocket-Key1");
            const char *sec_websocket_key2 = apr_table_get(r->headers_in, "Sec-WebSocket-Key2");

            if ((connection != NULL) && !strcasecmp(connection, "Upgrade")) {
                websocket_config_rec *conf = (websocket_config_rec *) ap_get_module_config(r->per_dir_config, &websocket_draft76_module);

                if ((conf != NULL) && (conf->plugin != NULL)) {
                    int using_draft75;

                    if ((sec_websocket_key1 != NULL) &&
                        (sec_websocket_key2 != NULL)) {
                        using_draft75 = 0;
                    }
                    else if (conf->support_draft75) {
                        /* Draft-75 (use 4 so we can easily skip past the four bytes of "Sec-" when creating the output header) */
                        using_draft75 = 4;
                    }
                    else {
                        /* Invalid */
                        using_draft75 = -1;
                    }
                    if (using_draft75 != -1) {
                        const char *host = apr_table_get(r->headers_in, "Host");        /* Verify -- FIXME */
                        const char *origin = apr_table_get(r->headers_in, "Origin");    /* Verify -- FIXME */
                        const char *sec_websocket_protocol = apr_table_get(r->headers_in, "Sec-WebSocket-Protocol" + using_draft75);
                        char sec_websocket_key3[8] = { 0 };
                        ap_filter_t *input_filter = r->input_filters, *http_filter = NULL;
                        int expected_filters = 2;
                        int secure = 0;

                        /*
                         * Since we are handling a WebSocket connection, not a standard HTTP
                         * connection, remove the HTTP input filter. Also, see if we are
                         * communicating over a secure connection (is there a better way?).
                         */
                        while ((input_filter != NULL) && (expected_filters > 0)) {
                            if ((input_filter->frec != NULL) &&
                                (input_filter->frec->name != NULL)) {
                                if (!strcasecmp(input_filter->frec->name, "http_in")) {
                                    http_filter = input_filter;
                                    expected_filters--;
                                }
                                else if (!strcasecmp(input_filter->frec->name, "ssl/tls filter")) {
                                    secure = 1;
                                    expected_filters--;
                                }
                            }
                            input_filter = input_filter->next;
                        }
                        if (http_filter) {
                            ap_remove_input_filter(http_filter);
                        }

                        /* Key3 is provided in the content body. */
                        if (using_draft75 || (mod_websocket_read_block(r, sec_websocket_key3, 8) == 8)) {
                            unsigned char response[APR_MD5_DIGESTSIZE];

                            if (using_draft75 || !mod_websocket_handshake(sec_websocket_key1, sec_websocket_key2, sec_websocket_key3, response)) {
                                WebSocketState state = { r, NULL, NULL, NULL, 0, using_draft75 };
                                WebSocketServer server = {
                                    sizeof(WebSocketServer), 1, &state, mod_websocket_request, mod_websocket_header_get, mod_websocket_header_set,
                                    mod_websocket_protocol_count, mod_websocket_protocol_index, mod_websocket_protocol_set,
                                    mod_websocket_plugin_send, mod_websocket_plugin_close
                                };
                                const char *location = apr_pstrcat(r->pool, (secure ? "wss://" : "ws://"), host, r->unparsed_uri, NULL);
                                void *plugin_private = NULL;

                                apr_table_clear(r->headers_out);
                                apr_table_setn(r->headers_out, "Upgrade", "WebSocket");
                                apr_table_setn(r->headers_out, "Connection", "Upgrade");
                                apr_table_setn(r->headers_out, "Sec-WebSocket-Location" + using_draft75, location);
                                if (origin != NULL) {
                                    apr_table_setn(r->headers_out, "Sec-WebSocket-Origin" + using_draft75, origin);
                                }

                                /* Handle the WebSocket protocol */
                                if (sec_websocket_protocol != NULL) {
                                    /* Parse the WebSocket protocol entry */
                                    mod_websocket_parse_protocol(&server, sec_websocket_protocol);

                                    if (mod_websocket_protocol_count(&server) > 0) {
                                        /* Default to using the first protocol in the list (plugin may be overide this in on_connect) */
                                        mod_websocket_protocol_set(&server, mod_websocket_protocol_index(&server, 0));
                                    }
                                }

                                apr_thread_mutex_create(&state.mutex, APR_THREAD_MUTEX_DEFAULT, r->pool);
                                apr_thread_mutex_lock(state.mutex);

                                /* If the plugin supplies an on_connect function, it must return non-null on success */
                                if ((conf->plugin->on_connect == NULL) ||
                                    ((plugin_private = conf->plugin->on_connect(&server)) != NULL)) {
                                    apr_pool_t *pool = NULL;
                                    apr_bucket_alloc_t *bucket_alloc;
                                    apr_bucket_brigade *obb;

                                    /* Now that the connection has been established, disable the socket timeout */
                                    apr_socket_timeout_set(ap_get_module_config(r->connection->conn_config, &core_module), -1);

                                    /* Set response status code and status line */
                                    r->status = 101;
                                    r->status_line = using_draft75 ? "101 Web Socket Protocol Handshake" : "101 WebSocket Protocol Handshake";

                                    /* Send the headers */
                                    ap_send_interim_response(r, 1);

                                    /* Create the output bucket brigade */
                                    if ((apr_pool_create(&pool, r->pool) == APR_SUCCESS) &&
                                        ((bucket_alloc = apr_bucket_alloc_create(pool)) != NULL) &&
                                        ((obb = apr_brigade_create(pool, bucket_alloc)) != NULL)) {
                                        unsigned char block[BLOCK_DATA_SIZE], *extended_data = NULL;
                                        apr_off_t extended_data_offset = 0;
                                        apr_size_t block_size, data_length = 0, extended_data_size = 0;
                                        apr_size_t data_limit = 33554432;       /* Make this a user configurable setting -- FIXME */
                                        int framing_state = DATA_FRAMING_READ_TYPE, type = -1;
                                        ap_filter_t *of = r->connection->output_filters;

                                        if (!using_draft75) {
                                            /* Write the handshake response */
                                            ap_fwrite(of, obb, (const char *) response, (apr_size_t) sizeof(response));
                                            ap_fflush(of, obb);
                                        }

                                        /* Allow the plugin to now write to the client */
                                        state.obb = obb;
                                        apr_thread_mutex_unlock(state.mutex);

                                        while ((framing_state != DATA_FRAMING_CLOSE) &&
                                               ((block_size = mod_websocket_read_block(r, (char *) block, sizeof(block))) > 0)) {
                                            apr_off_t block_offset = 0, block_data_offset = 0;
                                            apr_size_t block_length = 0;

                                            while (block_offset < block_size) {
                                                switch (framing_state) {
                                                case DATA_FRAMING_READ_TYPE:
                                                    type = (int) block[block_offset];
                                                    framing_state = (type & 0x80) ? DATA_FRAMING_IN_BINARY_LENGTH : DATA_FRAMING_IN_TEXT_DATA;
                                                    block_data_offset = ++block_offset;
                                                    data_length = 0;
                                                    break;
                                                case DATA_FRAMING_IN_TEXT_DATA:
                                                    while (block_offset < block_size) {
                                                        if (block[block_offset++] == 0xFF) {    /* End of data */
                                                            unsigned char *message;

                                                            block_length = (apr_size_t) (block_offset - block_data_offset - 1);
                                                            data_length += block_length;

                                                            if (extended_data_offset > 0) {
                                                                memmove(&extended_data[extended_data_offset], &block[block_data_offset], block_length);
                                                                extended_data_offset = 0;
                                                                message = extended_data;
                                                            }
                                                            else {
                                                                message = &block[block_data_offset];
                                                            }
                                                            conf->plugin->on_message(plugin_private, &server, type, message, data_length);
                                                            type = -1;
                                                            framing_state = DATA_FRAMING_READ_TYPE;
                                                            break;
                                                        }
                                                    }
                                                    if (framing_state == DATA_FRAMING_IN_TEXT_DATA) {
                                                        /* The data spans blocks */
                                                        unsigned char *previous_extended_data = extended_data;

                                                        block_length = (apr_size_t) (block_offset - block_data_offset);
                                                        data_length += block_length;
                                                        /*
                                                         * If the new block data will extended past the end
                                                         * of the extended buffer, increase it. Include the
                                                         * size of an additional block in the calculation
                                                         * so that we will always have enough room in the
                                                         * extended buffer when we reach an end-of-data
                                                         * marker.
                                                         */
                                                        if ((extended_data_offset + block_length + BLOCK_DATA_SIZE) > extended_data_size) {
                                                            extended_data_size += EXTENDED_DATA_SIZE;
                                                            extended_data =
                                                                (unsigned char *) realloc(extended_data, extended_data_size * sizeof(unsigned char));
                                                        }
                                                        if (extended_data != NULL) {
                                                            memmove(&extended_data[extended_data_offset], &block[block_data_offset], block_length);
                                                            extended_data_offset += block_length;
                                                        }
                                                        else {
                                                            /* The memory allocation failed, close the connection */
                                                            if (previous_extended_data != NULL) {
                                                                free(previous_extended_data);
                                                            }
                                                            framing_state = DATA_FRAMING_CLOSE;
                                                        }
                                                    }
                                                    break;
                                                case DATA_FRAMING_IN_BINARY_DATA:
                                                    /* Handle binary data frames */
                                                    if (extended_data != NULL) {
                                                        apr_size_t block_data_length;

                                                        block_length = (apr_size_t) (block_size - block_offset);
                                                        block_data_length = (data_length > block_length) ? block_length : data_length;
                                                        memmove(&extended_data[extended_data_offset], &block[block_offset], block_data_length);
                                                        extended_data_offset += block_data_length;
                                                        block_offset += block_data_length;
                                                        data_length -= block_data_length;

                                                        if (data_length == 0) {
                                                            /*
                                                             * Binary data frames aren't supported by the
                                                             * specification, so don't pass them on to the
                                                             * plugin. Just silently discard the data.
                                                             *
                                                             * conf->plugin->on_message(plugin_private, &server, type, extended_data, extended_data_offset);
                                                             */
                                                            extended_data_offset = 0;
                                                            type = -1;
                                                            framing_state = DATA_FRAMING_READ_TYPE;
                                                        }
                                                    }
                                                    else {
                                                        framing_state = DATA_FRAMING_CLOSE;
                                                    }
                                                    break;
                                                case DATA_FRAMING_IN_BINARY_LENGTH:
                                                    data_length = data_length * 128 + (block[block_offset] & 0x7F);

                                                    if (data_length > data_limit) {
                                                        /* Exceeded implementation-specific limit */
                                                        framing_state = DATA_FRAMING_CLOSE;
                                                    }
                                                    else if ((block[block_offset] & 0x80) == 0) {
                                                        /* Encountered end-of-length marker */
                                                        if (data_length == 0) {
                                                            framing_state = ((type == 0xFF) && !using_draft75) ? DATA_FRAMING_CLOSE : DATA_FRAMING_READ_TYPE;
                                                        }
                                                        else {
                                                            /* Always use the extended data to handle binary content */
                                                            if (data_length > extended_data_size) {
                                                                extended_data_size = data_length;
                                                                extended_data =
                                                                    (unsigned char *) realloc(extended_data, extended_data_size * sizeof(unsigned char));
                                                            }
                                                            extended_data_offset = 0;
                                                            framing_state = DATA_FRAMING_IN_BINARY_DATA;
                                                        }
                                                    }
                                                    block_offset++;
                                                    break;
                                                default:
                                                    break;
                                                }
                                            }
                                        }
                                        if (extended_data != NULL) {
                                            free(extended_data);
                                        }

                                        /* Send server-side closing handshake */
                                        mod_websocket_plugin_send(&server, 0xFF, NULL, 0);

                                        /* Disallow the plugin from writing to the client */
                                        apr_thread_mutex_lock(state.mutex);
                                        state.obb = NULL;

                                        apr_brigade_destroy(obb);
                                    }
                                    apr_thread_mutex_unlock(state.mutex);

                                    /* Tell the plugin that we are disconnecting */
                                    if (conf->plugin->on_disconnect != NULL) {
                                        conf->plugin->on_disconnect(plugin_private, &server);
                                    }

                                    /* Close the connection (in case it isn't closed yet) */
                                    r->connection->keepalive = AP_CONN_CLOSE;

                                    apr_thread_mutex_destroy(state.mutex);

                                    return OK;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return DECLINED;
}

static const command_rec websocket_cmds[] = {
    AP_INIT_TAKE2("WebSocketHandler", mod_websocket_conf_handler, NULL, OR_AUTHCFG,
                  "Shared library containing WebSocket implementation followed by function initialization function name"),
    AP_INIT_FLAG("SupportDraft75", ap_set_flag_slot, (void *) APR_OFFSETOF(websocket_config_rec, support_draft75), OR_AUTHCFG,
                 "Support Draft-75 WebSocket Protocol"),
    {NULL}
};

/* Declare the handlers for other events. */
static void mod_websocket_register_hooks(apr_pool_t *p)
{
    /* Register for method calls. */
    ap_hook_handler(mod_websocket_method_handler, NULL, NULL, APR_HOOK_FIRST - 1);
}

module AP_MODULE_DECLARE_DATA websocket_draft76_module = {
    STANDARD20_MODULE_STUFF,
    mod_websocket_create_dir_config,    /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create server config structure */
    NULL,                       /* merge server config structures */
    websocket_cmds,             /* command table */
    mod_websocket_register_hooks,       /* register hooks */
};
