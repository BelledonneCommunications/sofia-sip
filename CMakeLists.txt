############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2021  Belledonne Communications, Grenoble France
#
############################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
############################################################################

cmake_minimum_required(VERSION 3.2)

# CMP0077 policy is required by Flexisip build. Remove it once the CMake required
# version is higer or equal to 3.13.
if(NOT CMAKE_VERSION VERSION_LESS 3.13)
	cmake_policy(SET CMP0077 NEW)
endif()

project(sofia-sip VERSION 1.13.33 LANGUAGES C)

option(ENABLE_UNIT_TESTS "Build unit test executables (WIP)" OFF)

find_package(OpenSSL REQUIRED)

if(ENABLE_UNIT_TESTS)
	find_path(LIBCHECK_INCLUDE_DIR check.h)
	find_library(LIBCHECK_LIBRARIES check)

	if (LIBCHECK_INCLUDE_DIR AND LIBCHECK_LIBRARIES)
	    set(HAVE_CHECK YES)
	endif()
endif()

check_symbol_exists("clock_getcpuclockid" "time.h" HAVE_CLOCK_GETCPUCLOCKID)
check_include_file("netpacket/packet.h" HAVE_NETPACKET_PACKET_H)
check_include_file("sys/epoll.h" HAVE_EPOLL)
check_c_source_compiles("
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
    	int main(void) {
       		int one = 1;
  		int s = 0;
  		setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &one, sizeof(one));
		return 0;
    	}	"
	HAVE_IP_MTU_DISCOVER	
)
check_c_source_compiles("
	#include <sys/types.h>
	#include <sys/socket.h>
    	int main(void) {
       		int one = 1;
  		int s = 0;
  		setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &one, sizeof(one));
		return 0;
    	}	"
	HAVE_SO_RCVBUFFORCE  
)
check_c_source_compiles("
	#include <sys/types.h>
	#include <sys/socket.h>
    	int main(void) {
       		int one = 1;
  		int s = 0;
  		setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &one, sizeof(one));
		return 0;
    	}	"
	HAVE_SO_SNDBUFFORCE
)
check_c_source_compiles("
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
    	int main(void) {
       		int one = 1;
  		int s = 0;
  		setsockopt(s, SOL_IP, IP_RECVERR, &one, sizeof(one));
		return 0;
    	}	"
	HAVE_IP_RECVERR  
)

check_c_source_compiles("
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
    	int main(void) {
       		int one = 1;
  		int s = 0;
  		setsockopt(s, SOL_IPV6, IPV6_RECVERR, &one, sizeof(one));
		return 0;
    	}	"
	HAVE_IPV6_RECVERR
)
configure_file(config.h.cmake config.h)

include_directories(${PROJECT_BINARY_DIR})

add_subdirectory(libsofia-sip-ua)
if(ENABLE_UNIT_TESTS)
	add_subdirectory(s2check)
endif()
