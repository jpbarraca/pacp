bin_PROGRAMS = pacp_ar
pacp_ar_SOURCES= pacp_ar.cc internetworkAdapter.cc
EXTRA_DIST = internetworkAdapter.h ar.conf

AM_CXXFLAGS = -DACCESS_ROUTER -I ../common -I ../../lib/openssl/include

../common/libnode.a:
	cd ../common && ${MAKE} libnode.a

../common/libmath.a:
	cd ../common && ${MAKE} libmath.a

pacp_ar_LDADD=../common/libnode.a ../common/libmath.a ../../lib/libipq/libipq.a  ../common/libkeymanager.a ../../lib/openssl/libcrypto.a -ldl
