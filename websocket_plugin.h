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

#if !defined(_MOD_WEBSOCKET_H_)
#define _MOD_WEBSOCKET_H_

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#define CALLBACK __stdcall
#else
#define EXPORT
#define CALLBACK
#endif

struct _WebSocketServer;

typedef struct request_rec *(CALLBACK *WS_Request)(const struct _WebSocketServer *server);
typedef const char *(CALLBACK *WS_Header_Get)(const struct _WebSocketServer *server, const char *key);
typedef void (CALLBACK *WS_Header_Set)(const struct _WebSocketServer *server, const char *key, const char *value);
typedef size_t (CALLBACK *WS_Send)(const struct _WebSocketServer *server, const int type, const unsigned char *buffer, const size_t buffer_size);
typedef void (CALLBACK *WS_Close)(const struct _WebSocketServer *server);

typedef struct _WebSocketServer {
  unsigned int size;
  unsigned int version;
  struct _WebSocketState *state;
  WS_Request request;
  WS_Header_Get header_get;
  WS_Header_Set header_set;
  WS_Send send;
  WS_Close close;
} WebSocketServer;

struct _WebSocketPlugin;

typedef struct _WebSocketPlugin *(EXPORT *WS_Init)();
typedef void (CALLBACK *WS_Destroy)(struct _WebSocketPlugin *plugin);

typedef void *(CALLBACK *WS_OnConnect)(const WebSocketServer *server); /* Returns plugin_private */
typedef size_t (CALLBACK *WS_OnMessage)(void *plugin_private, const WebSocketServer *server, const int type, unsigned char *buffer, const size_t buffer_size);
typedef void (CALLBACK *WS_OnDisconnect)(void *plugin_private, const WebSocketServer *server);

typedef struct _WebSocketPlugin {
  unsigned int size;
  unsigned int version;
  WS_Destroy destroy;
  WS_OnConnect on_connect;
  WS_OnMessage on_message;
  WS_OnDisconnect on_disconnect;
} WebSocketPlugin;

#if defined(__cplusplus)
}
#endif

#endif /* _MOD_WEBSOCKET_H_ */
