/*
 * Copyright 2011 self.disconnect
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

#include <stdio.h>
#include "httpd.h"
#include "apr_thread_proc.h"

#include "websocket_plugin.h"

typedef struct _DumbIncrementData {
  const WebSocketServer *server;
  apr_pool_t *pool;
  apr_thread_t *thread;
  int counter;
  int active;
} DumbIncrementData;

void* APR_THREAD_FUNC dumb_increment_run(apr_thread_t *thread, void *data)
{
  char buffer[64];
  DumbIncrementData *dib = (DumbIncrementData *) data;

  if (dib != NULL) {
    /* Keep sending messages as long as the connection is active */
    while (dib->active) {
      apr_sleep(50000); /* 50ms */
      sprintf(buffer,"%d", dib->counter++);
      dib->server->send(dib->server, MESSAGE_TYPE_TEXT, (unsigned char *)buffer, strlen(buffer));
    }
  }
  return NULL;
}

void * CALLBACK dumb_increment_on_connect(const WebSocketServer *server)
{
  DumbIncrementData *dib = NULL;

  if ((server != NULL) && (server->version == WEBSOCKET_SERVER_VERSION_1)) {
    /* Get access to the request_rec strucure for this connection */
    request_rec *r = server->request(server);

    if (r != NULL) {
      apr_pool_t *pool = NULL;
      size_t i, count = server->protocol_count(server);

      /* Only support "dumb-increment-protocol" */
      for (i = 0; i < count; i++) {
        const char *protocol = server->protocol_index(server, i);

        if ((protocol != NULL) &&
            (strcmp(protocol, "dumb-increment-protocol") == 0)) {
          /* If the client can speak the protocol, set it in the response */
          server->protocol_set(server, protocol);
          break;
        }
      }
      /* If the protocol negotiation worked, create a new memory pool */
      if ((i < count) &&
          (apr_pool_create(&pool, r->pool) == APR_SUCCESS)) {
        /* Allocate memory to hold the dumb increment state */
        if ((dib = (DumbIncrementData *) apr_palloc(pool, sizeof(DumbIncrementData))) != NULL) {
          apr_thread_t *thread = NULL;
          apr_threadattr_t *thread_attr = NULL;

          dib->server = server;
          dib->pool = pool;
          dib->thread = NULL;
          dib->counter = 0;
          dib->active = 1;

          /* Create a non-detached thread that will perform the work */
          if ((apr_threadattr_create(&thread_attr, pool) == APR_SUCCESS) &&
              (apr_threadattr_detach_set(thread_attr, 0) == APR_SUCCESS) &&
              (apr_thread_create(&thread, thread_attr, dumb_increment_run, dib, pool) == APR_SUCCESS)) {
            dib->thread = thread;
            /* Success */
            pool = NULL;
          } else {
            dib = NULL;
          }
        }
        if (pool != NULL) {
          apr_pool_destroy(pool);
        }
      }
    }
  }
  return dib;
}

static size_t CALLBACK dumb_increment_on_message(void *plugin_private, const WebSocketServer *server,
    const int type, unsigned char *buffer, const size_t buffer_size)
{
  DumbIncrementData *dib = (DumbIncrementData *) plugin_private;

  if ((dib != 0) &&
      (buffer != 0) && (buffer_size == 6) &&
      (buffer[0] == 'r') &&
      (buffer[1] == 'e') &&
      (buffer[2] == 's') &&
      (buffer[3] == 'e') &&
      (buffer[4] == 't') &&
      (buffer[5] == '\n')) {
    /* If a message containing "reset\n" is received, reset the counter */
    dib->counter = 0;
  }
  return 0;
}

void CALLBACK dumb_increment_on_disconnect(void *plugin_private, const WebSocketServer *server)
{
  DumbIncrementData *dib = (DumbIncrementData *) plugin_private;

  if (dib != 0) {
    /* When disconnecting, inform the thread that it is time to stop */
    dib->active = 0;
    if (dib->thread) {
      apr_status_t status;

      /* Wait for the thread to finish */
      status = apr_thread_join(&status, dib->thread);
    }
    apr_pool_destroy(dib->pool);
  }
}

/*
 * Since we are returning a pointer to static memory, there is no need for a
 * "destroy" function.
 */

static WebSocketPlugin s_plugin = {
  sizeof(WebSocketPlugin),
  WEBSOCKET_PLUGIN_VERSION_0,
  NULL, /* destroy */
  dumb_increment_on_connect,
  dumb_increment_on_message,
  dumb_increment_on_disconnect
};

extern EXPORT WebSocketPlugin * CALLBACK dumb_increment_init()
{
  return &s_plugin;
}
