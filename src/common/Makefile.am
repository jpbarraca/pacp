noinst_LIBRARIES = libcm.a libmath.a libnode.a  libkeymanager.a 

libcm_a_SOURCES = configuration.cc threadFunc.cc debug.cc packet.cc packetHandler.cc

libnode_a_SOURCES = configuration.cc threadFunc.cc debug.cc packetHandler.cc sessionManager.cc proofAttendant.cc routingClient.cc packet.cc timer.cc gwInfoClient.cc a4cClient.cc 

libmath_a_SOURCES = fec.cc hash64.cc hash32.cc

libkeymanager_a_SOURCES = keyManager.cc

LIBADD = ../../lib/openssl/libcrypto.a

AM_CXXFLAGS = -I../../lib/openssl/include -I../../lib/libipq

EXTRA_DIST = packetHandler.h log.h packet.h threadFunc.h sessionManager.h routingClient.h timer.h proofAttendant.h configuration.h gwInfoClient.h exception.h gwInfoClient.h hash.h fec.h a4cClient.h debug.h keyManager.h


