/*
 * Copyright 2010 self.disconnect
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

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"

#include "apr_md5.h"
#include "apr_strings.h"

#include "websocket_plugin.h"

module AP_MODULE_DECLARE_DATA websocket_module;

typedef struct {
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
  return (void *)conf;
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
        WebSocketPlugin *plugin = ((WS_Init)sym)();
        if ((plugin != NULL) &&
            (plugin->version == 0) &&
            (plugin->size >= sizeof(WebSocketServer)) &&
            (plugin->on_message != NULL)) { /* Require an on_message handler */
          conf->res_handle = res_handle;
          conf->plugin = plugin;
          apr_pool_cleanup_register(cmd->pool, conf, mod_websocket_cleanup_config, apr_pool_cleanup_null);
          response = NULL;
        } else {
          apr_dso_unload(res_handle);
          response = "Invalid response from initialization function";
        }
      } else {
        apr_dso_unload(res_handle);
        response = "Could not find initialization function in module";
      }
    } else {
      response = "Could not open WebSocket handler module";
    }
  } else {
    response = "Invalid parameters";
  }
  return response;
}

/*
 * Functions available to plugins.
 */

typedef struct _WebSocketState {
  request_rec *r;
  apr_bucket_brigade *obb;
} WebSocketState;

static size_t mod_websocket_plugin_send(const struct _WebSocketServer *server, const int type, const unsigned char *buffer, const size_t buffer_size)
{
  size_t written = 0;

  if ((server != NULL) && (server->state != NULL) && (type == 0)) { /* Only support type 0 (UTF-8) for now */
    WebSocketState *ws_state = (WebSocketState *) server->state;

    if ((ws_state->r != NULL) && (ws_state->obb != NULL)) {
      ap_filter_t *of = ws_state->r->connection->output_filters;
      const char header = '\0', trailer = '\xFF';

      ap_fwrite(of, ws_state->obb, &header, 1);
      ap_fwrite(of, ws_state->obb, (const char *)buffer, buffer_size);
      ap_fwrite(of, ws_state->obb, &trailer, 1);
      ap_fflush(of, ws_state->obb);
      written = buffer_size;
    }
  }
  return written;
}

static void mod_websocket_plugin_close(const WebSocketServer *server)
{
  if ((server != NULL) && (server->state != NULL)) {
    WebSocketState *ws_state = (WebSocketState *) server->state;

    ws_state->r->connection->keepalive = AP_CONN_CLOSE; /* Is this right? -- FIXME */
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
      number = number*10 + (*ptr - '0');
    } else if (*ptr == ' ') {
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
  packed[0] = (unsigned char)((number >> 24) & 0xFF);
  packed[1] = (unsigned char)((number >> 16) & 0xFF);
  packed[2] = (unsigned char)((number >>  8) & 0xFF);
  packed[3] = (unsigned char)((number      ) & 0xFF);
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
    apr_uint32_t part1 = number1/spaces1;
    apr_uint32_t part2 = number2/spaces2;

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
    unsigned char challenge[16] = {0};

    if (!(status = mod_websocket_challenge(key1, key2, key3, challenge))) {
      if (apr_md5(response, challenge, (apr_size_t)sizeof(challenge)) == APR_SUCCESS) {
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

      if ((connection != NULL) &&
          (sec_websocket_key1 != NULL) &&
          (sec_websocket_key2 != NULL)) {
        if (!strcasecmp(connection, "Upgrade")) {
          const char *host = apr_table_get(r->headers_in, "Host"); /* Verify -- FIXME */
          const char *origin = apr_table_get(r->headers_in, "Origin"); /* Verify -- FIXME */
          const char *cookie = apr_table_get(r->headers_in, "Cookie");
          const char *sec_websocket_protocol = apr_table_get(r->headers_in, "Sec-WebSocket-Protocol");
          char sec_websocket_key3[8] = {0};
          ap_filter_t *input_filter = r->input_filters;

          /*
           * Since we are handling a WebSocket connection, not a standard HTTP
           * connection, remove the HTTP input filter.
           */
          while (input_filter != NULL) {
            if ((input_filter->frec != NULL) &&
                (input_filter->frec->name != NULL) &&
                !strcasecmp(input_filter->frec->name, "HTTP_IN")) {
              ap_remove_input_filter(input_filter);
              break;
            }
            input_filter = input_filter->next;
          }

          /* Key3 is provided in the content body. */
          if (mod_websocket_read_block(r, sec_websocket_key3, 8) == 8) {
            unsigned char response[APR_MD5_DIGESTSIZE];

            if (!mod_websocket_handshake(sec_websocket_key1, sec_websocket_key2, sec_websocket_key3, response)) {
              websocket_config_rec *conf = (websocket_config_rec *) ap_get_module_config(r->per_dir_config, &websocket_module);
              WebSocketState server_state = {r, NULL};
              WebSocketServer server = {
                sizeof(WebSocketServer), 1, &server_state, mod_websocket_plugin_send, mod_websocket_plugin_close
              };

              if ((conf != NULL) && (conf->plugin != NULL)) {
                void *plugin_private = (conf->plugin->on_connect != NULL) ? conf->plugin->on_connect(&server) : NULL;
                const int secure = 0; /* How do we determine if this is a secure connection or not? -- FIXME */
                const char *location = apr_pstrcat(r->pool, (secure ? "wss://" : "ws://"), host, r->parsed_uri.path, NULL);

                apr_table_clear(r->headers_out);
                apr_table_setn(r->headers_out, "Upgrade", "WebSocket");
                apr_table_setn(r->headers_out, "Connection", "Upgrade");
                apr_table_setn(r->headers_out, "Sec-WebSocket-Location", location);
                if (origin != NULL) {
                  apr_table_setn(r->headers_out, "Sec-WebSocket-Origin", origin);
                }
                if (sec_websocket_protocol != NULL) {
                  apr_table_setn(r->headers_out, "Sec-WebSocket-Protocol", sec_websocket_protocol);
                }
                if (cookie != NULL) {
                  /* Handle cookies -- FIXME */
                }

                /* Set response status code and status line */
                r->status = 101;
                r->status_line = "101 WebSocket Protocol Handshake";

                /* Send the headers */
                ap_send_interim_response(r, 1);

                /* Create the output bucket brigade */
                ap_filter_t *of = r->connection->output_filters;
                apr_bucket_brigade *obb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

                if (obb != NULL) {
                  unsigned char block[BLOCK_DATA_SIZE], *extended_data = NULL;
                  apr_off_t extended_data_offset = 0;
                  apr_size_t block_size, data_length = 0, extended_data_size = 0;
                  apr_size_t data_limit = 33554432; /* Make this a user configurable setting -- FIXME */
                  int state = DATA_FRAMING_READ_TYPE, type = -1;

                  /* Write the handshake response */
                  ap_fwrite(of, obb, (const char *)response, (apr_size_t)sizeof(response));
                  ap_fflush(of, obb);

                  /* Allow the plugin to now write to the client */
                  server_state.obb = obb;

                  while ((state != DATA_FRAMING_CLOSE) &&
                         ((block_size = mod_websocket_read_block(r, (char *)block, sizeof(block))) > 0)) {
                    apr_off_t block_offset = 0, block_data_offset = 0;
                    apr_size_t block_length = 0;

                    while (block_offset < block_size) {
                      switch (state) {
                        case DATA_FRAMING_READ_TYPE:
                          type = (int)block[block_offset];
                          state = (type & 0x80) ? DATA_FRAMING_IN_BINARY_LENGTH : DATA_FRAMING_IN_TEXT_DATA;
                          block_data_offset = ++block_offset;
                          data_length = 0;
                          break;
                        case DATA_FRAMING_IN_TEXT_DATA:
                          while (block_offset < block_size) {
                            if (block[block_offset++] == 0xFF) { /* End of data */
                              unsigned char *message;

                              block_length = block_offset - block_data_offset - 1;
                              data_length += block_length;

                              if (extended_data_offset > 0) {
                                memmove(&extended_data[extended_data_offset], &block[block_data_offset], block_length);
                                extended_data_offset = 0;
                                message = extended_data;
                              } else {
                                message = &block[block_data_offset];
                              }
                              conf->plugin->on_message(plugin_private, &server, type, message, data_length);
                              type = -1;
                              state = DATA_FRAMING_READ_TYPE;
                              break;
                            }
                          }
                          if (state == DATA_FRAMING_IN_TEXT_DATA) {
                            /* The data spans blocks */
                            unsigned char *previous_extended_data = extended_data;

                            block_length = block_offset - block_data_offset;
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
                              extended_data = (unsigned char *) realloc(extended_data, extended_data_size*sizeof(unsigned char));
                            }
                            if (extended_data != NULL) {
                              memmove(&extended_data[extended_data_offset], &block[block_data_offset], block_length);
                              extended_data_offset += block_length;
                            } else {
                              /* The memory allocation failed, close the connection */
                              if (previous_extended_data != NULL) {
                                free(previous_extended_data);
                              }
                              state = DATA_FRAMING_CLOSE;
                            }
                          }
                          break;
                        case DATA_FRAMING_IN_BINARY_DATA:
#if 0
                          if (type >= 0x80) {
                            /* FIXME */
                            conf->plugin->on_message(plugin_private, &server, type,
                                &block[block_data_offset + 1], block_offset - block_data_offset - 1);
                            type = -1;
                          }
#endif
                          state = DATA_FRAMING_CLOSE;
                          break;
                        case DATA_FRAMING_IN_BINARY_LENGTH:
                          if ((block[block_offset] & 0x80) == 0x80) {
                            /* Encountered end-of-length marker */
                            state = (data_length == 0) ? DATA_FRAMING_READ_TYPE : DATA_FRAMING_IN_BINARY_DATA;
                          } else {
                            data_length = data_length*128 + (block[block_offset] & 0x7F);
                            if ((data_length == 0) && (type == 0xFF)) {
                              /* /type/ is 0xFF, and /length/ is 0 */
                              state = DATA_FRAMING_CLOSE;
                            } else if (data_length > data_limit) {
                              /* Exceeded implementation-specific limit */
                              state = DATA_FRAMING_CLOSE;
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
                  /* Disallow the plugin from writing to the client */
                  server_state.obb = NULL;

                  apr_brigade_destroy(obb);
                }
                /* Tell the plugin that we are disconnecting */
                if (conf->plugin->on_disconnect != NULL) {
                  conf->plugin->on_disconnect(plugin_private, &server);
                }

                /* Close the connection (in case it isn't closed yet) */
                r->connection->keepalive = AP_CONN_CLOSE;

                return OK;
              }
            }
          }
        }
      }
    }
  }
  return DECLINED;
}

static const command_rec websocket_cmds[] =
{
  AP_INIT_TAKE2("WebSocketHandler", mod_websocket_conf_handler, NULL, OR_AUTHCFG,
      "Shared library containing WebSocket implementation followed by function initialization function name"),
  {NULL}
};

/* Declare the handlers for other events. */
static void mod_websocket_register_hooks(apr_pool_t *p)
{
  /* Register for method calls. */
  ap_hook_handler(mod_websocket_method_handler, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA websocket_module =
{
  STANDARD20_MODULE_STUFF,
  mod_websocket_create_dir_config, /* create per-directory config structure */
  NULL,                            /* merge per-directory config structures */
  NULL,                            /* create server config structure */
  NULL,                            /* merge server config structures */
  websocket_cmds,                  /* command table */
  mod_websocket_register_hooks,    /* register hooks */
};
