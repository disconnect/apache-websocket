# apache-websocket

The apache-websocket module is an Apache 2.x module that may be used to process
requests using the WebSocket protocol. The module consists of a plugin
architecture for handling WebSocket messaging. Doing so does not require any
knowledge of internal Apache structures.

This implementation does not support the older draft-75 protocol. The code
should be easy enough to modify to temporarily support the older protocol.

## Download

    $ git clone git://github.com/disconnect/apache-websocket.git

## Build

SCons is used to build the module. In addition, it is currently only configured
to build under Mac OS X. It should work be trivial to add support for Linux,
while it should not be too hard to support Windows.

    $ scons

## Installation

    $ sudo scons install

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
plugin.

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

    LoadModule websocket_module libexec/apache2/mod_websocket.so

    <IfModule mod_websocket.c>
      <Location /echo>
        SetHandler websocket-handler
        WebSocketHandler libexec/apache2/mod_websocket_echo.so echo_init
      </Location>
    </IfModule>

## Authors

* The original code was written by <code>self.disconnect</code>.

Contributors are more than welcome to join the project.

## License

Please see the file called LICENSE.
