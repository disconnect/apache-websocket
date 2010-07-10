import os

env = Environment()

debug = ARGUMENTS.get("debug", 0)

if env["PLATFORM"] == "win32":
    env.Append(CCFLAGS = ["/EHsc", "/W3"])
    if int(debug):
        env.Append(CCFLAGS = ["/Zi", "/Od", "/MDd"],
                   LINKFLAGS = ["/DEBUG"])
    else:
        env.Append(CCFLAGS = ["/O2", "/MD"])
    modulesdir = ""
    shlibprefix = ""
    shlibsuffix = ".so"
else:
    env.Append(CCFLAGS = ["-Wall", "-pipe"])
    if int(debug):
        env.Append(CCFLAGS = ["-g"])
    else:
        env.Append(CCFLAGS = ["-O2"])
    if env["PLATFORM"] == "darwin":
        env.Append(CPPDEFINES = ["DARWIN", "SIGPROCMASK_SETS_THREAD_MASK"],
                   CPPPATH = ["/usr/include/apache2", "/usr/include/apr-1"],
                   SHLINKFLAGS = "-undefined dynamic_lookup")
        modulesdir = "/usr/libexec/apache2"
    else:
        modulesdir = ""
    shlibprefix = ""
    shlibsuffix = ".so"

mod_websocket = env.SharedLibrary(source=["mod_websocket.c"],
                                  SHLIBPREFIX=shlibprefix,
                                  SHLIBSUFFIX=shlibsuffix)

env.Install(dir=modulesdir, source=mod_websocket)

# Install

env.Alias("install", modulesdir)
