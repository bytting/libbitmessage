libbitmessage
=============

C++ bitmessage protocol API

Status: Development

At this point the code only compiles on Linux, partly due to missing implementations of endianness for other platforms (see btypes.h)
There is currently also a hard-coded dependency on the Botan C++ crypto library version 1.11
This library must be installed with prefix /usr/local, which is the default make location (see CMakeLists.txt)
