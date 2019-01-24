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


sofia_configure_file(sofia-sip/msg_protos.h.in sofia-sip/msg_protos.h sofia-sip/msg_mime.h PR
    module=msg NO_FIRST=1 NO_MIDDLE=1
)

sofia_configure_file(sofia-sip/msg_mime_protos.h.in sofia-sip/msg_mime_protos.h sofia-sip/msg_mime.h PR
    module=msg NO_FIRST=1 NO_LAST=1
)

sofia_configure_file(msg_mime_table.c.in msg_mime_table.c sofia-sip/msg_mime.h PT
    module=msg_multipart tprefix=msg
    prefix=mp MC_HASH_SIZE=127 MC_SHORT_SIZE=26
)

sofia_configure_file(test_protos.h.in test_protos.h test_class.h PR
    module=msg_test NO_MIDDLE=1 NO_LAST=1
)

sofia_configure_file(test_table.c.in test_table.c test_class.h PT
    module=msg_test prefix=msg MC_HASH_SIZE=127 multipart=msg_multipart
)

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg_addr.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg_buffer.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg_date.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg_header.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg_mclass.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg_mclass_hash.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg_mime.h
	${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/msg_mime_protos.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg_parser.h
	${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/msg_protos.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg_tag_class.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/msg_types.h
	PARENT_SCOPE
)

add_library(msg OBJECT
    msg_auth.c
    msg_basic.c
    msg.c
    msg_date.c
    msg_generic.c
    msg_header_copy.c
    msg_header_make.c
    msg_inlined.c
    msg_mclass.c
    msg_mime.c
    msg_parser.c
    msg_parser_util.c
    msg_tag.c
    ${CMAKE_CURRENT_BINARY_DIR}/msg_mime_table.c
    ${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/msg_mime_protos.h
    ${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/msg_protos.h
)
target_compile_options(msg PRIVATE -fPIC)
target_include_directories(msg
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
)

if(ENABLE_UNIT_TESTS)
	add_library(msg-test OBJECT
	    test_class.c
	    test_inlined.c
	    ${CMAKE_CURRENT_BINARY_DIR}/test_protos.h
	    ${CMAKE_CURRENT_BINARY_DIR}/test_table.c
	)
	target_include_directories(msg-test
	    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
	    $<TARGET_PROPERTY:msg,INTERFACE_INCLUDE_DIRECTORIES>
	    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
	    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
	)

	set(TESTERS
	    msg_name_hash
	    test_msg
	)

	foreach(tester ${TESTERS})
	    add_executable(${tester} ${tester}.c)
	    target_link_libraries(${tester} PRIVATE bnf msg msg-test su url)
	endforeach(tester)
endif()
