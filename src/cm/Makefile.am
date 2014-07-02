bin_PROGRAMS = pacp_cm
pacp_cm_SOURCES = chargingManager.cc a4cManager.cc flowManager.cc proofManager.cc pacp_cm.cc polSolver.cc db_mysql.cc
EXTRA_DIST = chargingManager.h a4cManager.h flowManager.h proofManager.h polSolver.h db_mysql.h

AM_CXXFLAGS = -I ../common -I ../../lib/openssl/include

all:
	rm -rf pacp_cm && cd ../common && ${MAKE} all && cd - && ${MAKE} pacp_cm
	
../common/libcm.a:
	cd ../common && ${MAKE} libcm.a

../common/libmath.a:
	cd ../common && ${MAKE} libmath.a

../common/libkeymanager.a:
	cd ../common && ${MAKE} libkeymanager.a

pacp_cm_LDFLAGS=../common/libcm.a  ../common/libmath.a ../common/libkeymanager.a ../../lib/libipq/libipq.a  -L../../lib/openssl/
