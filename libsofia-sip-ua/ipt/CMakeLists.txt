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


set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/base64.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/rc4.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/token64.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/uniqueid.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/utf8.h
	PARENT_SCOPE
)

add_library(ipt OBJECT
    base64.c
    rc4.c
    token64.c
    ucs2.c
    ucs4.c
    utf8.c
)
target_compile_options(ipt PRIVATE -fPIC)
target_include_directories(ipt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
)

if(ENABLE_UNIT_TESTS)
	set(TESTERS
	    torture_base64
	    utf8test
	)

	foreach(tester ${TESTERS})
	    add_executable(${tester} ${tester}.c)
	    target_link_libraries(${tester} PRIVATE ipt su)
	endforeach(tester)
endif()
