# apache-websocket

The apache-websocket module is an Apache 2.x module that may be used to process
requests using the WebSocket protocol. The module consists of a plugin
architecture for handling WebSocket messaging. Doing so does not require any
knowledge of internal Apache structures.

This implementation supports draft-76 of the WebSocket protocol. It does not
support the older draft-75 protocol. The code should be easy enough to modify
to support the older protocol. Make sure that your client supports the
appropriate protocol. The Stable and Beta channels of Chrome, and the release
version of Safari, do not yet implement the draft-76 protocol. The Dev channel
of Chrome and the nightly WebKit builds (which may be used with Safari) do
support it, however.

## Download

    $ git clone git://github.com/disconnect/apache-websocket.git

## Building and Installation

SCons may be used to build the module. However, it is currently only configured
to build under Mac OS X.

    $ scons
    $ sudo scons install

Alternatively, you may use <code>apxs</code> to build and install the module.
Under Linux (at least under Ubuntu 10.04 LTS), use:

    $ sudo apxs2 -i -a -c mod_websocket.c

You probably only want to use the <code>-a</code> option the first time you
issue the command, as it will overwrite your configuration each time you
execute it (see below).

You may use <code>apxs</code> under Mac OS X as well if you do not want to use
SCons. In that case, use:

    $ sudo apxs -i -a -c mod_websocket.c

## Plugins

While the module is used to handle the WebSocket protocol, plugins are used to
implement the application-specific handling of WebSocket messages.

A plugin need only have one function exported that returns a pointer to an
initialized <code>WebSocketPlugin</code> structure. The
<code>WebSocketPlugin</code> structure consists of the structure size,
structure version, and several function pointers. The size should be set to the
<code>sizeof</code> the <code>WebSocketPlugin</code> structure, the version
should be set to 0, and the function pointers should be set to point to the
various functions that will service the requests. The only required function is
the <code>on_message</code> function for handling incoming messages.

See <code>examples/echo.c</code> for an example implementation of an "echo"
plugin. A sample <code>client.html</code> is included as well. If you try it
and you get a message that says Connection Closed, you are most likely using a
client that does not support draft-76 of the protocol.

Since the plugins do not depend on Apache, you do not need to use
<code>apxs</code> to build them. Also, it does not need to be placed in the same
directory as the WebSocket module. You may use SCons (or some other build
system) to be build and install the plugins.

## Configuration

The <code>http.conf</code> file is used to configure WebSocket plugins to
handle requests for particular locations. Inside each <code>Location</code>
block, set the handler, using the <code>SetHandler</code> keyword, to
<code>websocket-handler</code>. Next, add a <code>WebSocketHandler</code> entry
that contains two parameters. The first is the name of the dynamic plugin
library that will service the requests for the specified location, and the
second is the name of the function in the dynamic library that will initialize
the plugin.

Here is an example of the configuration changes to <code>http.conf</code> that
are used to handle the WebSocket plugin requests directed at
<code>/echo</code>. The server will initialize the module by calling the
<code>echo_init</code> function in <code>mod_websocket_echo.so</code>:

    LoadModule websocket_module   libexec/apache2/mod_websocket.so

    <IfModule mod_websocket.c>
      <Location /echo>
        SetHandler websocket-handler
        WebSocketHandler libexec/apache2/mod_websocket_echo.so echo_init
      </Location>
    </IfModule>

Under Linux, the module-specific configuration may be contained in a single
file called <code>/etc/apache2/mods-available/websocket.load</code> (your
version of Linux may vary). Since the directory containing the module is
different from Mac OS X, it may look more like this:

    LoadModule websocket_module   /usr/lib/apache2/modules/mod_websocket.so

    <IfModule mod_websocket.c>
      <Location /echo>
        SetHandler websocket-handler
        WebSocketHandler /usr/lib/apache2/modules/mod_websocket_echo.so echo_init
      </Location>
    </IfModule>

This is the configuration that may be overwritten when the <code>-a</code>
option is included using <code>axps2</code>, so be careful.

## Authors

* The original code was written by <code>self.disconnect</code>.

## License

Please see the file called LICENSE.
