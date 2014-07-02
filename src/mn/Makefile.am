bin_PROGRAMS = pacp_mn
pacp_mn_SOURCES = chargingAgent.cc nodeManager.cc pacp_mn.cc qos.cc
EXTRA_DIST = chargingAgent.h node.conf


AM_CXXFLAGS = -I../common -I../../lib/openssl/include -I../../lib/libipq
	 
../common/libnode.a:
	cd ../common && ${MAKE} libnode.a

../common/libmath.a:
	cd ../common && ${MAKE} libmath.a

pacp_mn_LDADD=../common/libkeymanager.a ../common/libnode.a ../common/libmath.a ../../lib/libipq/libipq.a ../../lib/openssl/libcrypto.a  -ldl
