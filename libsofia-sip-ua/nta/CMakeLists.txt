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


sofia_add_tag_awk_command(nta_tag.c nta_tag_ref.c)

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/nta.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/nta_stateless.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/nta_tag.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/nta_tport.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/sl_utils.h
	PARENT_SCOPE
)

add_library(nta OBJECT
    nta.c
    nta_check.c
    nta_tag.c
    nta_tag_ref.c
    sl_read_payload.c
    sl_utils_log.c
    sl_utils_print.c
)
target_compile_options(nta PRIVATE -fPIC)
target_include_directories(nta
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:features,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:ipt,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:msg,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:sip,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:sresolv,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:tport,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
)
add_dependencies(nta msg sip)

add_executable(portbind portbind.c)
target_link_libraries(portbind PRIVATE nta su sip msg url bnf tport stun sresolv su http)

if(ENABLE_UNIT_TESTS)
	add_executable(check_nta
	    check_nta_api.c
	    check_nta.c
	    check_nta_client.c
	    check_nta_server.c
	)
	target_link_libraries(check_nta PRIVATE nta s2)

	set(TESTERS
	    test_nta_api
	#     test_nta
	)

	foreach(tester ${TESTERS})
	    add_executable(${tester} ${tester}.c)
	    target_link_libraries(${tester} PRIVATE bnf http features msg nta sip sresolv stun su tport url)
	endforeach(tester)
endif()
