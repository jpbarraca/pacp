#!/bin/sh
#********************************************************************
#PACP - Polynomial assisted Ad-hoc Charging Protocol
#
#Author: João Paulo Barraca <jpbarraca@av.it.pt>
#Copyright (c) João Paulo Barraca
#
# This file is part of PACP.
#
#    PACP is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    PACP is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with PACP.  If not, see <http://www.gnu.org/licenses/>.
#
# ********************************************************************/


ip6tables --flush
ip6tables --flush -t mangle
modprobe ip6_mqueue

ip6tables -A OUTPUT -t mangle -p icmp6 -j ACCEPT
ip6tables -A OUTPUT -t mangle -p udp --dport 654 -j ACCEPT
ip6tables -A OUTPUT -t mangle -p udp --dport 910 -j ACCEPT
ip6tables -A OUTPUT -t mangle -p udp --dport 9999  -j ACCEPT

ip6tables -A OUTPUT -t mangle -p tcp  -j MARK --set-mark=4
ip6tables -A OUTPUT -t mangle -p udp  -j MARK --set-mark=4
ip6tables -A OUTPUT -t mangle -m mark --mark 4 -j QUEUE


ip6tables -A INPUT -t mangle -p icmp6 -j ACCEPT
ip6tables -A FORWARD -t mangle -p udp --dport 654 --sport 654 -j ACCEPT
ip6tables -A FORWARD -t mangle -p udp --dport 910 --sport 910 -j ACCEPT
ip6tables -A FORWARD -t mangle -p udp --dport 9999  -j ACCEPT
ip6tables -A FORWARD -t mangle -p tcp -j MARK --set-mark=6
ip6tables -A FORWARD -t mangle -p udp -j MARK --set-mark=6
ip6tables -A FORWARD -t mangle -m mark --mark 6 -j QUEUE


ip6tables -A INPUT -t mangle -p icmp6 -j ACCEPT
ip6tables -A INPUT -t mangle -p udp --dport 654 -j ACCEPT
ip6tables -A INPUT -t mangle -p udp --dport 910 -j ACCEPT
ip6tables -A INPUT -t mangle -p udp --dport 9999 -j ACCEPT
ip6tables -A INPUT -t mangle -p tcp  -j MARK --set-mark=5
ip6tables -A INPUT -t mangle -p udp  -j MARK --set-mark=5


ip6tables -A INPUT -t mangle -m mark --mark 5 -j QUEUE
