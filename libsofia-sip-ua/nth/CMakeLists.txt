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


sofia_add_tag_awk_command(nth_tag.c nth_tag_ref.c)

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/nth.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/nth_tag.h
	PARENT_SCOPE
)

add_library(nth OBJECT
    nth_client.c
    nth_server.c
    nth_tag.c
    ${CMAKE_CURRENT_BINARY_DIR}/nth_tag_ref.c
)
target_compile_options(nth PRIVATE -fPIC)
target_include_directories(nth
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:http,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:iptsec,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:msg,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:tport,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
)
add_dependencies(nth http msg)

if(ENABLE_UNIT_TESTS)
	set(TESTERS
	    http-client
	    http-server
	    test_nth
	)

	foreach(tester ${TESTERS})
	    add_executable(${tester} ${tester}.c)
	    target_link_libraries(${tester} PRIVATE bnf http ipt iptsec msg nth sip sresolv stun su tport url)
	endforeach(tester)
endif()
