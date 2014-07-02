/********************************************************************
    PACP - Polynomial assisted Ad-hoc Charging Protocol

    Author: Jo�o Paulo Barraca <jpbarraca@av.it.pt>
    Copyright (c) Jo�o Paulo Barraca

    This file is part of PACP.

    PACP is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    PACP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with PACP.  If not, see <http://www.gnu.org/licenses/>.

 ********************************************************************/


#ifndef _A4CM_ANAGER_H_
#define _A4C_MANAGER_H_

class PacketHandler;
class KeyManager;

typedef struct pktCmn_t;

class A4CManager {
  public:
    A4CManager(PacketHandler*, KeyManager*);
    ~A4CManager();

    void processPacket(pktCmn_t*);

    PacketHandler* _pHandler;
    KeyManager*	_keyManager;


};
#endif
