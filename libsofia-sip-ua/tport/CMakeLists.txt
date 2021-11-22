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


find_package(OpenSSL REQUIRED)

sofia_add_tag_awk_command(tport_tag.c tport_tag_ref.c)

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/tport.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/tport_plugins.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/tport_tag.h
	PARENT_SCOPE
)

add_library(tport OBJECT
#     test_tport.c
#     tls_test_client.c
#     tls_test_server.c
    tport.c
    tport_logging.c
#     tport_rand.c
#     tport_sigcomp.c
    tport_stub_sigcomp.c
    tport_stub_stun.c
    tport_tag.c
#     tport_threadpool.c
    tport_tls.c
    tport_type_connect.c
    tport_type_sctp.c
    tport_type_stun.c
    tport_type_tcp.c
    tport_type_tls.c
    tport_type_udp.c
    ${CMAKE_CURRENT_BINARY_DIR}/tport_tag_ref.c
)
target_compile_options(tport PRIVATE -fPIC)
target_include_directories(tport
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:http,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:ipt,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:msg,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:stun,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(tport PUBLIC OpenSSL::SSL)
add_dependencies(tport http msg)
