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


sofia_configure_file(sofia-sip/http_protos.h.in
    sofia-sip/http_protos.h
    sofia-sip/http.h PR
    module=http
)

sofia_configure_file(sofia-sip/http_tag.h.in
    sofia-sip/http_tag.h
    sofia-sip/http.h PR
    module=http
)

sofia_configure_file(http_tag.c.in
    http_tag.c
    sofia-sip/http.h PR
    module=http
)

sofia_configure_file(http_parser_table.c.in
    http_parser_table.c
    sofia-sip/http.h PT
    module=http MC_HASH_SIZE=127
)

sofia_add_tag_awk_command(${CMAKE_CURRENT_BINARY_DIR}/http_tag.c http_tag_ref.c)

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/http.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/http_header.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/http_parser.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/http_tag_class.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/http_status.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/http_hclasses.h
	${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/http_protos.h
	${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/http_tag.h
	PARENT_SCOPE
)

add_library(http OBJECT
    http_basic.c
    http_extra.c
    http_header.c
    http_inlined.c
    http_parser.c
    http_status.c
    http_tag_class.c
    ${CMAKE_CURRENT_BINARY_DIR}/http_parser_table.c
    ${CMAKE_CURRENT_BINARY_DIR}/http_tag.c
    ${CMAKE_CURRENT_BINARY_DIR}/http_tag_ref.c
    ${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/http_protos.h
    ${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/http_tag.h
)
target_compile_options(http PRIVATE -fPIC)
target_include_directories(http
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:msg,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
)
add_dependencies(http msg)

if(ENABLE_UNIT_TESTS)
	add_executable(test_http test_http.c)
	target_link_libraries(test_http PRIVATE bnf http msg msg-test su url)
endif()
