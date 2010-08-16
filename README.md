# apache-websocket

The apache-websocket module is an Apache 2.x module that may be used to process
requests using the WebSocket protocol. The module consists of a plugin
architecture for handling WebSocket messaging. Doing so does not _require_ any
knowledge of internal Apache structures.

This implementation supports draft-75, draft-76, and draft-77 of the WebSocket
protocol. Support for draft-75 is disabled by default, but it may be enabled
through the configuration.

## Download

    $ git clone git://github.com/disconnect/apache-websocket.git

## Building and Installation

SCons may be used to build the module. However, it is currently only configured
to build under Mac OS X.

    $ scons
    $ sudo scons install

Alternatively, you may use `apxs` to build and install the module.  Under Linux
(at least under Ubuntu 10.04 LTS), use:

    $ sudo apxs2 -i -a -c mod_websocket.c

You probably only want to use the `-a` option the first time you issue the
command, as it may overwrite your configuration each time you execute it (see
below).

You may use `apxs` under Mac OS X as well if you do not want to use SCons. In
that case, use:

    $ sudo apxs -i -a -c mod_websocket.c

## Plugins

While the module is used to handle the WebSocket protocol, plugins are used to
implement the application-specific handling of WebSocket messages.

A plugin need only have one function exported that returns a pointer to an
initialized `WebSocketPlugin` structure. The `WebSocketPlugin` structure
consists of the structure size, structure version, and several function
pointers. The size should be set to the `sizeof` the `WebSocketPlugin`
structure, the version should be set to 0, and the function pointers should be
set to point to the various functions that will service the requests. The only
required function is the `on_message` function for handling incoming messages.

See `examples/echo.c` for a simple example implementation of an "echo" plugin.
A sample `client.html` is included as well. If you try it and you get a message
that says Connection Closed, you are most likely using a client that only
supports draft-75 of the protocol, but you have not enabled support for it.

If you provide an `on_connect` function, return a non-null value to accept the
connection, and null if you wish to decline the connection. The return value
will be passed to your other methods for that connection. During your
`on_connect` function, you may access the Apache `request_rec` structure if you
wish. You will have to include the appropriate Apache include files. If you do
not wish to do that, you may also access the headers (both input and output)
using the provided functions. There are also protocol-specific handling
functions for selecting the desired protocol for this WebSocket session. You
may not access the `send` or `close` functions while connecting, as the
connection will not be completed until you return from the function.

If your plugin does not depend on Apache, you do not need to use `apxs` to
build them. Also, it does not need to be placed in the same directory as the
WebSocket module. You may use SCons (or some other build system) to be build
and install the plugins.

## Configuration

The `http.conf` file is used to configure WebSocket plugins to handle requests
for particular locations. Inside each `Location` block, set the handler, using
the `SetHandler` keyword, to `websocket-handler`. Next, add a
`WebSocketHandler` entry that contains two parameters. The first is the name of
the dynamic plugin library that will service the requests for the specified
location, and the second is the name of the function in the dynamic library
that will initialize the plugin. You may optionally include a flag for
supporting the draft-75 version of the WebSocket protocol (it will default to
"off" if you do not include it). It is enabled using the `SupportDraft75`
keyword, along with a value of `On`.

Here is an example of the configuration changes to `http.conf` that are used to
handle the WebSocket plugin requests directed at `/echo`. The server will
initialize the module by calling the `echo_init` function in
`mod_websocket_echo.so`:

    LoadModule websocket_module   libexec/apache2/mod_websocket.so

    <IfModule mod_websocket.c>
      <Location /echo>
        SetHandler websocket-handler
        WebSocketHandler libexec/apache2/mod_websocket_echo.so echo_init
        SupportDraft75 On
      </Location>
    </IfModule>

Under Linux, the module-specific configuration may be contained in a single
file called `/etc/apache2/mods-available/websocket.load` (your version of Linux
may vary). Since the directory containing the module is different from Mac OS
X, it may look more like this:

    LoadModule websocket_module   /usr/lib/apache2/modules/mod_websocket.so

    <IfModule mod_websocket.c>
      <Location /echo>
        SetHandler websocket-handler
        WebSocketHandler /usr/lib/apache2/modules/mod_websocket_echo.so echo_init
        SupportDraft75 On
      </Location>
    </IfModule>

This is the configuration that may be overwritten when the `-a` option is
included using `axps2`, so be careful.

## Authors

* The original code was written by `self.disconnect`.

## License

Please see the file called LICENSE.
