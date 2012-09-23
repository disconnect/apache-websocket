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
 *   mod_websocket.c
 *   Apache API inteface structures
 */

#include "apr_base64.h"
#include "apr_sha1.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"

#include "websocket_plugin.h"
#include "validate_utf8.h"

#define CORE_PRIVATE
#include "http_core.h"
#include "http_connection.h"

#if !defined(APR_ARRAY_IDX)
#define APR_ARRAY_IDX(ary,i,type) (((type *)(ary)->elts)[i])
#endif
#if !defined(APR_ARRAY_PUSH)
#define APR_ARRAY_PUSH(ary,type) (*((type *)apr_array_push(ary)))
#endif

module AP_MODULE_DECLARE_DATA websocket_module;

typedef struct
{
    char *location;
    apr_dso_handle_t *res_handle;
    WebSocketPlugin *plugin;
    apr_int64_t payload_limit;
} websocket_config_rec;

#define BLOCK_DATA_SIZE              4096

#define DATA_FRAMING_MASK               0
#define DATA_FRAMING_START              1
#define DATA_FRAMING_PAYLOAD_LENGTH     2
#define DATA_FRAMING_PAYLOAD_LENGTH_EXT 3
#define DATA_FRAMING_EXTENSION_DATA     4
#define DATA_FRAMING_APPLICATION_DATA   5
#define DATA_FRAMING_CLOSE              6

#define FRAME_GET_FIN(BYTE)         (((BYTE) >> 7) & 0x01)
#define FRAME_GET_RSV1(BYTE)        (((BYTE) >> 6) & 0x01)
#define FRAME_GET_RSV2(BYTE)        (((BYTE) >> 5) & 0x01)
#define FRAME_GET_RSV3(BYTE)        (((BYTE) >> 4) & 0x01)
#define FRAME_GET_OPCODE(BYTE)      ( (BYTE)       & 0x0F)
#define FRAME_GET_MASK(BYTE)        (((BYTE) >> 7) & 0x01)
#define FRAME_GET_PAYLOAD_LEN(BYTE) ( (BYTE)       & 0x7F)

#define FRAME_SET_FIN(BYTE)         (((BYTE) & 0x01) << 7)
#define FRAME_SET_OPCODE(BYTE)       ((BYTE) & 0x0F)
#define FRAME_SET_MASK(BYTE)        (((BYTE) & 0x01) << 7)
#define FRAME_SET_LENGTH(X64, IDX)  (unsigned char)(((X64) >> ((IDX)*8)) & 0xFF)

#define OPCODE_CONTINUATION 0x0
#define OPCODE_TEXT         0x1
#define OPCODE_BINARY       0x2
#define OPCODE_CLOSE        0x8
#define OPCODE_PING         0x9
#define OPCODE_PONG         0xA

#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WEBSOCKET_GUID_LEN 36

#define STATUS_CODE_OK                1000
#define STATUS_CODE_GOING_AWAY        1001
#define STATUS_CODE_PROTOCOL_ERROR    1002
#define STATUS_CODE_RESERVED          1004 /* Protocol 8: frame too large */
#define STATUS_CODE_INVALID_UTF8      1007
#define STATUS_CODE_POLICY_VIOLATION  1008
#define STATUS_CODE_MESSAGE_TOO_LARGE 1009
#define STATUS_CODE_INTERNAL_ERROR    1011

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
            conf->payload_limit = 32 * 1024 * 1024;
        }
    }
    return (void *)conf;
}

static apr_status_t mod_websocket_cleanup_config(void *data)
{
    if (data != NULL) {
        websocket_config_rec *conf = (websocket_config_rec *)data;

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

static const char *mod_websocket_conf_handler(cmd_parms *cmd, void *confv,
                                              const char *path,
                                              const char *name)
{
    websocket_config_rec *conf = (websocket_config_rec *)confv;
    char *response;

    if ((conf != NULL) && (path != NULL) && (name != NULL)) {
        apr_dso_handle_t *res_handle = NULL;
        apr_dso_handle_sym_t sym;

        if (apr_dso_load
            (&res_handle, ap_server_root_relative(cmd->pool, path),
             cmd->pool) == APR_SUCCESS) {
            if ((apr_dso_sym(&sym, res_handle, name) == APR_SUCCESS) &&
                (sym != NULL)) {
                WebSocketPlugin *plugin = ((WS_Init) sym) ();
                if ((plugin != NULL) &&
                    (plugin->version == WEBSOCKET_PLUGIN_VERSION_0) &&
                    (plugin->size >= sizeof(WebSocketPlugin)) &&
                    (plugin->on_message != NULL)) { /* Require an on_message handler */
                    conf->res_handle = res_handle;
                    conf->plugin = plugin;
                    apr_pool_cleanup_register(cmd->pool, conf,
                                              mod_websocket_cleanup_config,
                                              apr_pool_cleanup_null);
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

static const char *mod_websocket_conf_max_message_size(cmd_parms *cmd,
                                                       void *confv,
                                                       const char *size)
{
    websocket_config_rec *conf = (websocket_config_rec *)confv;
    char *response;

    if ((conf != NULL) && (size != NULL)) {
        apr_int64_t payload_limit = apr_atoi64(size);
        if (payload_limit > 0) {
            conf->payload_limit = payload_limit;
            response = NULL;
        }
        else {
            response = "Invalid maximum message size";
        }
    }
    else {
        response = "Invalid parameter";
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
    apr_int64_t protocol_version;
} WebSocketState;

static request_rec *CALLBACK mod_websocket_request(const WebSocketServer *server)
{
    if ((server != NULL) && (server->state != NULL)) {
        return server->state->r;
    }
    return NULL;
}

static const char *CALLBACK mod_websocket_header_get(const WebSocketServer *server,
                                                     const char *key)
{
    if ((server != NULL) && (key != NULL)) {
        WebSocketState *state = server->state;

        if ((state != NULL) && (state->r != NULL)) {
            return apr_table_get(state->r->headers_in, key);
        }
    }
    return NULL;
}

static void CALLBACK mod_websocket_header_set(const WebSocketServer *server,
                                              const char *key,
                                              const char *value)
{
    if ((server != NULL) && (key != NULL) && (value != NULL)) {
        WebSocketState *state = server->state;

        if ((state != NULL) && (state->r != NULL)) {
            apr_table_setn(state->r->headers_out,
                           apr_pstrdup(state->r->pool, key),
                           apr_pstrdup(state->r->pool, value));
        }
    }
}

static size_t CALLBACK mod_websocket_protocol_count(const WebSocketServer *server)
{
    size_t count = 0;

    if ((server != NULL) && (server->state != NULL) &&
        (server->state->protocols != NULL) &&
        !apr_is_empty_array(server->state->protocols)) {
        count = (size_t) server->state->protocols->nelts;
    }
    return count;
}

static const char *CALLBACK mod_websocket_protocol_index(const WebSocketServer *server,
                                                         const size_t index)
{
    if ((index >= 0) && (index < mod_websocket_protocol_count(server))) {
        return APR_ARRAY_IDX(server->state->protocols, index, char *);
    }
    return NULL;
}

static void CALLBACK mod_websocket_protocol_set(const WebSocketServer *server,
                                                const char *protocol)
{
    if ((server != NULL) && (protocol != NULL)) {
        WebSocketState *state = server->state;

        if ((state != NULL) && (state->r != NULL)) {
            apr_table_setn(state->r->headers_out, "Sec-WebSocket-Protocol",
                           apr_pstrdup(state->r->pool, protocol));
        }
    }
}

static size_t CALLBACK mod_websocket_plugin_send(const WebSocketServer *server,
                                                 const int type,
                                                 const unsigned char *buffer,
                                                 const size_t buffer_size)
{
    apr_uint64_t payload_length =
        (apr_uint64_t) ((buffer != NULL) ? buffer_size : 0);
    size_t written = 0;

    /* Deal with size more that 63 bits - FIXME */

    if ((server != NULL) && (server->state != NULL)) {
        WebSocketState *state = server->state;

        apr_thread_mutex_lock(state->mutex);

        if ((state->r != NULL) && (state->obb != NULL) && !state->closing) {
            unsigned char header[32];
            ap_filter_t *of = state->r->connection->output_filters;
            apr_size_t pos = 0;
            unsigned char opcode;

            switch (type) {
            case MESSAGE_TYPE_TEXT:
                opcode = OPCODE_TEXT;
                break;
            case MESSAGE_TYPE_BINARY:
                opcode = OPCODE_BINARY;
                break;
            case MESSAGE_TYPE_PING:
                opcode = OPCODE_PING;
                break;
            case MESSAGE_TYPE_PONG:
                opcode = OPCODE_PONG;
                break;
            case MESSAGE_TYPE_CLOSE:
            default:
                state->closing = 1;
                opcode = OPCODE_CLOSE;
                break;
            }
            header[pos++] = FRAME_SET_FIN(1) | FRAME_SET_OPCODE(opcode);
            if (payload_length < 126) {
                header[pos++] =
                    FRAME_SET_MASK(0) | FRAME_SET_LENGTH(payload_length, 0);
            }
            else {
                if (payload_length < 65536) {
                    header[pos++] = FRAME_SET_MASK(0) | 126;
                }
                else {
                    header[pos++] = FRAME_SET_MASK(0) | 127;
                    header[pos++] = FRAME_SET_LENGTH(payload_length, 7);
                    header[pos++] = FRAME_SET_LENGTH(payload_length, 6);
                    header[pos++] = FRAME_SET_LENGTH(payload_length, 5);
                    header[pos++] = FRAME_SET_LENGTH(payload_length, 4);
                    header[pos++] = FRAME_SET_LENGTH(payload_length, 3);
                    header[pos++] = FRAME_SET_LENGTH(payload_length, 2);
                }
                header[pos++] = FRAME_SET_LENGTH(payload_length, 1);
                header[pos++] = FRAME_SET_LENGTH(payload_length, 0);
            }
            ap_fwrite(of, state->obb, (const char *)header, pos); /* Header */
            if (payload_length > 0) {
                if (ap_fwrite(of, state->obb,
                              (const char *)buffer,
                              buffer_size) == APR_SUCCESS) { /* Payload Data */
                    written = buffer_size;
                }
            }
            if (ap_fflush(of, state->obb) != APR_SUCCESS) {
                written = 0;
            }
        }
        apr_thread_mutex_unlock(state->mutex);
    }
    return written;
}

static void CALLBACK mod_websocket_plugin_close(const WebSocketServer *
                                                server)
{
    if (server != NULL) {
        /* Send closing handshake */
        mod_websocket_plugin_send(server, MESSAGE_TYPE_CLOSE, NULL, 0);
    }
}

/*
 * Read a buffer of data from the input stream.
 */
static apr_size_t mod_websocket_read_block(request_rec *r, char *buffer,
                                           apr_size_t bufsiz)
{
    apr_status_t rv;
    apr_bucket_brigade *bb;
    apr_size_t readbufsiz = 0;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (bb != NULL) {
        if ((rv =
             ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, bufsiz)) == APR_SUCCESS) {
            if ((rv =
                 apr_brigade_flatten(bb, buffer, &bufsiz)) == APR_SUCCESS) {
                readbufsiz = bufsiz;
            }
        }
        apr_brigade_destroy(bb);
    }
    return readbufsiz;
}

/*
 * Base64-encode the SHA-1 hash of the client-supplied key with the WebSocket
 * GUID appended to it.
 */
static void mod_websocket_handshake(const WebSocketServer *server,
                                    const char *key)
{
    WebSocketState *state = server->state;
    apr_byte_t response[32];
    apr_byte_t digest[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t context;
    int len;

    apr_sha1_init(&context);
    apr_sha1_update(&context, key, strlen(key));
    apr_sha1_update(&context, WEBSOCKET_GUID, WEBSOCKET_GUID_LEN);
    apr_sha1_final(digest, &context);

    len = apr_base64_encode_binary((char *)response, digest, sizeof(digest));
    response[len] = '\0';

    apr_table_setn(state->r->headers_out, "Sec-WebSocket-Accept",
                   apr_pstrdup(state->r->pool, (const char *)response));
}

/*
 * The client-supplied WebSocket protocol entry consists of a list of
 * client-side supported protocols. Parse the list, and create an array
 * containing those protocol names.
 */
static void mod_websocket_parse_protocol(const WebSocketServer *server,
                                         const char *sec_websocket_protocol)
{
    WebSocketState *state = server->state;
    apr_array_header_t *protocols =
        apr_array_make(state->r->pool, 1, sizeof(char *));
    char *protocol_state = NULL;
    char *protocol =
        apr_strtok(apr_pstrdup(state->r->pool, sec_websocket_protocol),
                   ", \t", &protocol_state);

    while (protocol != NULL) {
        APR_ARRAY_PUSH(protocols, char *) = protocol;
        protocol = apr_strtok(NULL, ", \t", &protocol_state);
    }
    if (!apr_is_empty_array(protocols)) {
        state->protocols = protocols;
    }
}

typedef struct _WebSocketFrameData
{
    apr_uint64_t application_data_offset;
    unsigned char *application_data;
    unsigned char fin;
    unsigned char opcode;
    unsigned int utf8_state;
} WebSocketFrameData;

/*
 * The data framing handler requires that the server state mutex is locked by
 * the caller upon entering this function. It will be locked when leaving too.
 */
static void mod_websocket_data_framing(const WebSocketServer *server,
                                       websocket_config_rec *conf,
                                       void *plugin_private)
{
    WebSocketState *state = server->state;
    request_rec *r = state->r;
    apr_pool_t *pool = NULL;
    apr_bucket_alloc_t *bucket_alloc;
    apr_bucket_brigade *obb;

    /* We cannot use the same bucket allocator for the ouput bucket brigade
     * obb as the one associated with the connection (r->connection->bucket_alloc)
     * because the same bucket allocator cannot be used in two different
     * threads, and we use the connection bucket allocator in this
     * thread - see docs on apr_bucket_alloc_create(). This results in
     * occasional core dumps. So create our own bucket allocator and pool
     * for output thread bucket brigade. (Thanks to Alex Bligh -- abligh)
     */

    if ((apr_pool_create(&pool, r->pool) == APR_SUCCESS) &&
        ((bucket_alloc = apr_bucket_alloc_create(pool)) != NULL) &&
        ((obb = apr_brigade_create(pool, bucket_alloc)) != NULL)) {
        unsigned char block[BLOCK_DATA_SIZE];
        apr_int64_t block_size;
        apr_int64_t extension_bytes_remaining = 0;
        apr_int64_t payload_length = 0;
        apr_int64_t mask_offset = 0;
        int framing_state = DATA_FRAMING_START;
        int payload_length_bytes_remaining = 0;
        int mask_index = 0, masking = 0;
        unsigned char mask[4] = { 0, 0, 0, 0 };
        unsigned char fin = 0, opcode = 0xFF;
        WebSocketFrameData control_frame = { 0, NULL, 1, 8, UTF8_VALID };
        WebSocketFrameData message_frame = { 0, NULL, 1, 0, UTF8_VALID };
        WebSocketFrameData *frame = &control_frame;
        unsigned short status_code = STATUS_CODE_OK;
        unsigned char status_code_buffer[2];

        /* Allow the plugin to now write to the client */
        state->obb = obb;
        apr_thread_mutex_unlock(state->mutex);

        while ((framing_state != DATA_FRAMING_CLOSE) &&
               ((block_size =
                 mod_websocket_read_block(r, (char *)block,
                                          sizeof(block))) > 0)) {
            apr_int64_t block_offset = 0;

            while (block_offset < block_size) {
                switch (framing_state) {
                case DATA_FRAMING_START:
                    /*
                     * Since we don't currently support any extensions,
                     * the reserve bits must be 0
                     */
                    if ((FRAME_GET_RSV1(block[block_offset]) != 0) ||
                        (FRAME_GET_RSV2(block[block_offset]) != 0) ||
                        (FRAME_GET_RSV3(block[block_offset]) != 0)) {
                        framing_state = DATA_FRAMING_CLOSE;
                        status_code = STATUS_CODE_PROTOCOL_ERROR;
                        break;
                    }
                    fin = FRAME_GET_FIN(block[block_offset]);
                    opcode = FRAME_GET_OPCODE(block[block_offset++]);

                    framing_state = DATA_FRAMING_PAYLOAD_LENGTH;

                    if (opcode >= 0x8) { /* Control frame */
                        if (fin) {
                            frame = &control_frame;
                            frame->opcode = opcode;
                            frame->utf8_state = UTF8_VALID;
                        }
                        else {
                            framing_state = DATA_FRAMING_CLOSE;
                            status_code = STATUS_CODE_PROTOCOL_ERROR;
                            break;
                        }
                    }
                    else { /* Message frame */
                        frame = &message_frame;
                        if (opcode) {
                            if (frame->fin) {
                                frame->opcode = opcode;
                                frame->utf8_state = UTF8_VALID;
                            }
                            else {
                                framing_state = DATA_FRAMING_CLOSE;
                                status_code = STATUS_CODE_PROTOCOL_ERROR;
                                break;
                            }
                        }
                        else if (frame->fin ||
                                 ((opcode = frame->opcode) == 0)) {
                            framing_state = DATA_FRAMING_CLOSE;
                            status_code = STATUS_CODE_PROTOCOL_ERROR;
                            break;
                        }
                        frame->fin = fin;
                    }
                    payload_length = 0;
                    payload_length_bytes_remaining = 0;

                    if (block_offset >= block_size) {
                        break; /* Only break if we need more data */
                    }
                case DATA_FRAMING_PAYLOAD_LENGTH:
                    payload_length = (apr_int64_t)
                        FRAME_GET_PAYLOAD_LEN(block[block_offset]);
                    masking = FRAME_GET_MASK(block[block_offset++]);

                    if (payload_length == 126) {
                        payload_length = 0;
                        payload_length_bytes_remaining = 2;
                    }
                    else if (payload_length == 127) {
                        payload_length = 0;
                        payload_length_bytes_remaining = 8;
                    }
                    else {
                        payload_length_bytes_remaining = 0;
                    }
                    if ((masking == 0) ||   /* Client-side mask is required */
                        ((opcode >= 0x8) && /* Control opcodes cannot have a payload larger than 125 bytes */
                         (payload_length_bytes_remaining != 0))) {
                        framing_state = DATA_FRAMING_CLOSE;
                        status_code = STATUS_CODE_PROTOCOL_ERROR;
                        break;
                    }
                    else {
                        framing_state = DATA_FRAMING_PAYLOAD_LENGTH_EXT;
                    }
                    if (block_offset >= block_size) {
                        break;  /* Only break if we need more data */
                    }
                case DATA_FRAMING_PAYLOAD_LENGTH_EXT:
                    while ((payload_length_bytes_remaining > 0) &&
                           (block_offset < block_size)) {
                        payload_length *= 256;
                        payload_length += block[block_offset++];
                        payload_length_bytes_remaining--;
                    }
                    if (payload_length_bytes_remaining == 0) {
                        if ((payload_length < 0) ||
                            (payload_length > conf->payload_limit)) {
                            /* Invalid payload length */
                            framing_state = DATA_FRAMING_CLOSE;
                            status_code = (state->protocol_version >= 13) ?
                                           STATUS_CODE_MESSAGE_TOO_LARGE :
                                           STATUS_CODE_RESERVED;
                            break;
                        }
                        else if (masking != 0) {
                            framing_state = DATA_FRAMING_MASK;
                        }
                        else {
                            framing_state = DATA_FRAMING_EXTENSION_DATA;
                            break;
                        }
                    }
                    if (block_offset >= block_size) {
                        break;  /* Only break if we need more data */
                    }
                case DATA_FRAMING_MASK:
                    while ((mask_index < 4) && (block_offset < block_size)) {
                        mask[mask_index++] = block[block_offset++];
                    }
                    if (mask_index == 4) {
                        framing_state = DATA_FRAMING_EXTENSION_DATA;
                        mask_offset = 0;
                        mask_index = 0;
                        if ((mask[0] == 0) && (mask[1] == 0) &&
                            (mask[2] == 0) && (mask[3] == 0)) {
                            masking = 0;
                        }
                    }
                    else {
                        break;
                    }
                    /* Fall through */
                case DATA_FRAMING_EXTENSION_DATA:
                    /* Deal with extension data when we support them -- FIXME */
                    if (extension_bytes_remaining == 0) {
                        if (payload_length > 0) {
                            frame->application_data = (unsigned char *)
                                realloc(frame->application_data,
                                        frame->application_data_offset +
                                        payload_length);
                            if (frame->application_data == NULL) {
                                framing_state = DATA_FRAMING_CLOSE;
                                status_code = (state->protocol_version >= 13) ?
                                               STATUS_CODE_INTERNAL_ERROR :
                                               STATUS_CODE_GOING_AWAY;
                                break;
                            }
                        }
                        framing_state = DATA_FRAMING_APPLICATION_DATA;
                    }
                    /* Fall through */
                case DATA_FRAMING_APPLICATION_DATA:
                    {
                        apr_int64_t block_data_length;
                        apr_int64_t block_length = 0;
                        apr_uint64_t application_data_offset =
                            frame->application_data_offset;
                        unsigned char *application_data =
                            frame->application_data;

                        block_length = block_size - block_offset;
                        block_data_length =
                            (payload_length >
                             block_length) ? block_length : payload_length;

                        if (masking) {
                            apr_int64_t i;

                            if (opcode == OPCODE_TEXT) {
                                unsigned int utf8_state = frame->utf8_state;
                                unsigned char c;

                                for (i = 0; i < block_data_length; i++) {
                                    c = block[block_offset++] ^
                                        mask[mask_offset++ & 3];
                                    utf8_state =
                                        validate_utf8[utf8_state + c];
                                    if (utf8_state == UTF8_INVALID) {
                                        payload_length = block_data_length;
                                        break;
                                    }
                                    application_data
                                        [application_data_offset++] = c;
                                }
                                frame->utf8_state = utf8_state;
                            }
                            else {
                                /* Need to optimize the unmasking -- FIXME */
                                for (i = 0; i < block_data_length; i++) {
                                    application_data
                                        [application_data_offset++] =
                                        block[block_offset++] ^
                                        mask[mask_offset++ & 3];
                                }
                            }
                        }
                        else if (block_data_length > 0) {
                            memcpy(&application_data[application_data_offset],
                                   &block[block_offset], block_data_length);
                            if (opcode == OPCODE_TEXT) {
                                apr_int64_t i, application_data_end =
                                    application_data_offset +
                                    block_data_length;
                                unsigned int utf8_state = frame->utf8_state;

                                for (i = application_data_offset;
                                     i < application_data_end; i++) {
                                    utf8_state =
                                        validate_utf8[utf8_state +
                                                      application_data[i]];
                                    if (utf8_state == UTF8_INVALID) {
                                        payload_length = block_data_length;
                                        break;
                                    }
                                }
                                frame->utf8_state = utf8_state;
                            }
                            application_data_offset += block_data_length;
                            block_offset += block_data_length;
                        }
                        payload_length -= block_data_length;

                        if (payload_length == 0) {
                            int message_type = MESSAGE_TYPE_INVALID;

                            switch (opcode) {
                            case OPCODE_TEXT:
                                if ((fin &&
                                    (frame->utf8_state != UTF8_VALID)) ||
                                    (frame->utf8_state == UTF8_INVALID)) {
                                    framing_state = DATA_FRAMING_CLOSE;
                                    status_code = STATUS_CODE_INVALID_UTF8;
                                }
                                else {
                                    message_type = MESSAGE_TYPE_TEXT;
                                }
                                break;
                            case OPCODE_BINARY:
                                message_type = MESSAGE_TYPE_BINARY;
                                break;
                            case OPCODE_CLOSE:
                                framing_state = DATA_FRAMING_CLOSE;
                                status_code = STATUS_CODE_OK;
                                break;
                            case OPCODE_PING:
                                mod_websocket_plugin_send(server,
                                                          MESSAGE_TYPE_PONG,
                                                          application_data,
                                                          application_data_offset);
                                break;
                            case OPCODE_PONG:
                                break;
                            default:
                                framing_state = DATA_FRAMING_CLOSE;
                                status_code = STATUS_CODE_PROTOCOL_ERROR;
                                break;
                            }
                            if (fin && (message_type != MESSAGE_TYPE_INVALID)) {
                                conf->plugin->on_message(plugin_private,
                                                         server, message_type,
                                                         application_data,
                                                         application_data_offset);
                            }
                            if (framing_state != DATA_FRAMING_CLOSE) {
                                framing_state = DATA_FRAMING_START;

                                if (fin) {
                                    if (frame->application_data != NULL) {
                                        free(frame->application_data);
                                        frame->application_data = NULL;
                                    }
                                    application_data_offset = 0;
                                }
                            }
                        }
                        frame->application_data_offset =
                            application_data_offset;
                    }
                    break;
                case DATA_FRAMING_CLOSE:
                    block_offset = block_size;
                    break;
                default:
                    framing_state = DATA_FRAMING_CLOSE;
                    status_code = STATUS_CODE_PROTOCOL_ERROR;
                    break;
                }
            }
        }
        if (message_frame.application_data != NULL) {
            free(message_frame.application_data);
        }
        if (control_frame.application_data != NULL) {
            free(control_frame.application_data);
        }

        /* Send server-side closing handshake */
        status_code_buffer[0] = (status_code >> 8) & 0xFF;
        status_code_buffer[1] = status_code & 0xFF;
        mod_websocket_plugin_send(server, MESSAGE_TYPE_CLOSE,
                                  status_code_buffer,
                                  sizeof(status_code_buffer));

        /* We are done with the bucket brigade */
        apr_thread_mutex_lock(state->mutex);
        state->obb = NULL;
        apr_brigade_destroy(obb);
    }
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
        (r->method_number == M_GET) && (r->parsed_uri.path != NULL) &&
        (r->headers_in != NULL)) {
        const char *upgrade = apr_table_get(r->headers_in, "Upgrade");
        const char *connection = apr_table_get(r->headers_in, "Connection");
        int upgrade_connection = 0;

        if ((upgrade != NULL) &&
            (connection != NULL) && !strcasecmp(upgrade, "WebSocket")) {
            upgrade_connection = !strcasecmp(connection, "Upgrade");
            if (!upgrade_connection) {
                char *token = ap_get_token(r->pool, &connection, 0);

                while (token && *token) {       /* Parse the Connection value */
                    upgrade_connection = !strcasecmp(token, "Upgrade");
                    if (upgrade_connection) {
                        break;
                    }
                    while (*connection == ';') {
                        ++connection;
                        ap_get_token(r->pool, &connection, 0);  /* Skip parameters */
                    }
                    if (*connection++ != ',') {
                        break;  /* Invalid without comma */
                    }
                    token =
                        (*connection) ? ap_get_token(r->pool, &connection,
                                                     0) : NULL;
                }
            }
        }
        if (upgrade_connection) {
            /* Need to serialize the connections to minimize a denial of service attack -- FIXME */

            const char *host = apr_table_get(r->headers_in, "Host");
            const char *sec_websocket_key =
                apr_table_get(r->headers_in, "Sec-WebSocket-Key");
            const char *sec_websocket_version =
                apr_table_get(r->headers_in, "Sec-WebSocket-Version");
            apr_int64_t protocol_version =
                (sec_websocket_version !=
                 NULL) ? apr_atoi64(sec_websocket_version) : 0;

            if ((host != NULL) &&
                (sec_websocket_key != NULL) &&
                ((protocol_version == 7) ||
                 (protocol_version == 8) || (protocol_version == 13))) {
                /* const char *sec_websocket_origin = apr_table_get(r->headers_in, "Sec-WebSocket-Origin"); */
                /* const char *origin = apr_table_get(r->headers_in, "Origin"); */
                /* We need to validate the Host and Origin -- FIXME */

                websocket_config_rec *conf = (websocket_config_rec *)
                    ap_get_module_config(r->per_dir_config,
                                         &websocket_module);

                if ((conf != NULL) && (conf->plugin != NULL)) {
                    WebSocketState state =
                        { r, NULL, NULL, NULL, 0, protocol_version };
                    WebSocketServer server = {
                        sizeof(WebSocketServer), 1, &state,
                        mod_websocket_request, mod_websocket_header_get,
                        mod_websocket_header_set,
                        mod_websocket_protocol_count,
                        mod_websocket_protocol_index,
                        mod_websocket_protocol_set,
                        mod_websocket_plugin_send, mod_websocket_plugin_close
                    };
                    const char *sec_websocket_protocol =
                        apr_table_get(r->headers_in, "Sec-WebSocket-Protocol");
                    void *plugin_private = NULL;
                    ap_filter_t *input_filter;

                    /*
                     * Since we are handling a WebSocket connection, not a standard HTTP
                     * connection, remove the HTTP input filter.
                     */
                    for (input_filter = r->input_filters;
                         input_filter != NULL;
                         input_filter = input_filter->next) {
                        if ((input_filter->frec != NULL) &&
                            (input_filter->frec->name != NULL) &&
                            !strcasecmp(input_filter->frec->name, "http_in")) {
                            ap_remove_input_filter(input_filter);
                            break;
                        }
                    }

                    apr_table_clear(r->headers_out);
                    apr_table_setn(r->headers_out, "Upgrade", "websocket");
                    apr_table_setn(r->headers_out, "Connection", "Upgrade");

                    /* Set the expected acceptance response */
                    mod_websocket_handshake(&server, sec_websocket_key);

                    /* Handle the WebSocket protocol */
                    if (sec_websocket_protocol != NULL) {
                        /* Parse the WebSocket protocol entry */
                        mod_websocket_parse_protocol(&server,
                                                     sec_websocket_protocol);

                        if (mod_websocket_protocol_count(&server) > 0) {
                            /*
                             * Default to using the first protocol in the list
                             * (plugin should overide this in on_connect)
                             */
                            mod_websocket_protocol_set(&server,
                                                       mod_websocket_protocol_index
                                                       (&server, 0));
                        }
                    }

                    apr_thread_mutex_create(&state.mutex,
                                            APR_THREAD_MUTEX_DEFAULT,
                                            r->pool);
                    apr_thread_mutex_lock(state.mutex);

                    /*
                     * If the plugin supplies an on_connect function, it must
                     * return non-null on success
                     */
                    if ((conf->plugin->on_connect == NULL) ||
                        ((plugin_private =
                          conf->plugin->on_connect(&server)) != NULL)) {
                        /*
                         * Now that the connection has been established,
                         * disable the socket timeout
                         */
                        apr_socket_timeout_set(ap_get_module_config
                                               (r->connection->conn_config,
                                                &core_module), -1);

                        /* Set response status code and status line */
                        r->status = HTTP_SWITCHING_PROTOCOLS;
                        r->status_line = ap_get_status_line(r->status);

                        /* Send the headers */
                        ap_send_interim_response(r, 1);

                        /* The main data framing loop */
                        mod_websocket_data_framing(&server, conf,
                                                   plugin_private);

                        apr_thread_mutex_unlock(state.mutex);

                        /* Tell the plugin that we are disconnecting */
                        if (conf->plugin->on_disconnect != NULL) {
                            conf->plugin->on_disconnect(plugin_private,
                                                        &server);
                        }
                        r->connection->keepalive = AP_CONN_CLOSE;
                    }
                    else {
                        apr_table_clear(r->headers_out);

                        /* The connection has been refused */
                        r->status = HTTP_FORBIDDEN;
                        r->status_line = ap_get_status_line(r->status);
                        r->header_only = 1;
                        r->connection->keepalive = AP_CONN_CLOSE;

                        ap_send_error_response(r, 0);

                        apr_thread_mutex_unlock(state.mutex);
                    }
                    /* Close the connection */
                    ap_lingering_close(r->connection);

                    apr_thread_mutex_destroy(state.mutex);

                    return OK;
                }
            }
        }
    }
    return DECLINED;
}

static const command_rec websocket_cmds[] = {
    AP_INIT_TAKE2("WebSocketHandler", mod_websocket_conf_handler, NULL,
                  OR_AUTHCFG,
                  "Shared library containing WebSocket implementation followed by function initialization function name"),
    AP_INIT_TAKE1("MaxMessageSize", mod_websocket_conf_max_message_size, NULL,
                  OR_AUTHCFG,
                  "Maximum size (in bytes) of a message to accept; default is 33554432 bytes (32 MB)"),
    {NULL}
};

/* Declare the handlers for other events. */
static void mod_websocket_register_hooks(apr_pool_t *p)
{
    /* Register for method calls. */
    ap_hook_handler(mod_websocket_method_handler, NULL, NULL,
                    APR_HOOK_FIRST - 1);
}

module AP_MODULE_DECLARE_DATA websocket_module = {
    STANDARD20_MODULE_STUFF,
    mod_websocket_create_dir_config,    /* create per-directory config structure */
    NULL,                               /* merge per-directory config structures */
    NULL,                               /* create server config structure */
    NULL,                               /* merge server config structures */
    websocket_cmds,                     /* command table */
    mod_websocket_register_hooks,       /* register hooks */
};
