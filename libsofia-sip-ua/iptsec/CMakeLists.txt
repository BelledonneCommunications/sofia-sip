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


sofia_add_tag_awk_command(auth_tag.c auth_tag_ref.c)

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/auth_client.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/auth_client_plugin.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/auth_common.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/auth_digest.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/auth_module.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/auth_ntlm.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/auth_plugin.h
	PARENT_SCOPE
)

add_library(iptsec OBJECT
    auth_client.c
#     auth_client_ntlm.c
    auth_common.c
    auth_digest.c
    auth_module.c
    auth_module_http.c
    auth_module_sip.c
#     auth_ntlm.c
    auth_plugin.c
    auth_plugin_delayed.c
#     auth_plugin_ntlm.c
    auth_tag.c
    iptsec_debug.c
    ${CMAKE_CURRENT_BINARY_DIR}/auth_tag_ref.c
)
target_compile_options(iptsec PRIVATE -fPIC)
target_include_directories(iptsec
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:http,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:ipt,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:msg,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:nta,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:sip,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
)
add_dependencies(iptsec http sip msg)

if(ENABLE_UNIT_TESTS)
	add_executable(test_auth_digest test_auth_digest.c)
	target_link_libraries(test_auth_digest PRIVATE bnf http ipt iptsec msg sip su url)
endif()
