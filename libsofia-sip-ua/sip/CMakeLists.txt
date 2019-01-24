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


sofia_configure_file(sofia-sip/sip_hclasses.h.in
    sofia-sip/sip_hclasses.h
    sofia-sip/sip.h PR
    module=sip
)

sofia_configure_file(sofia-sip/sip_protos.h.in
    sofia-sip/sip_protos.h
    sofia-sip/sip.h PR
    module=sip
)

sofia_configure_file(sofia-sip/sip_tag.h.in
    sofia-sip/sip_tag.h
    sofia-sip/sip.h PR
    module=sip
)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sip_extra.h
    COMMAND ${AWK_MSG_AWK} module=sip PR=${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sip_extra.h
        NO_FIRST=1 NO_LAST=1
        PACKAGE_NAME="${PACKAGE_NAME}"
        PACKAGE_VERSION="${PACKAGE_VERSION}"
        TEMPLATE1=sofia-sip/sip_hclasses.h.in
        TEMPLATE2=sofia-sip/sip_protos.h.in
        TEMPLATE3=sofia-sip/sip_tag.h.in
        TEMPLATE=sofia-sip/sip_extra.h.in sip_extra_headers.txt
    DEPENDS sofia-sip/sip_hclasses.h.in sofia-sip/sip_protos.h.in sofia-sip/sip_tag.h.in
        sofia-sip/sip_extra.h.in sip_extra_headers.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sip_tag.c
    COMMAND ${AWK_MSG_AWK} module=sip PR=${CMAKE_CURRENT_BINARY_DIR}/sip_tag.c
        TEMPLATE=sip_tag.c.in sofia-sip/sip.h sip_extra_headers.txt
    DEPENDS sip_tag.c.in sofia-sip/sip.h sip_extra_headers.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sip_parser_table.c
    COMMAND ${AWK_MSG_AWK} module=sip PT=${CMAKE_CURRENT_BINARY_DIR}/sip_parser_table.c
        TEMPLATE=sip_parser_table.c.in FLAGFILE=sip_bad_mask
        MC_HASH_SIZE=127 MC_SHORT_SIZE=26 sofia-sip/sip.h sip_extra_headers.txt
    DEPENDS sip_parser_table.c.in sip_bad_mask sofia-sip/sip.h sip_extra_headers.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

sofia_add_tag_awk_command(${CMAKE_CURRENT_BINARY_DIR}/sip_tag.c sip_tag_ref.c)

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sip_extra.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/sip.h
	${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sip_hclasses.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/sip_header.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/sip_parser.h
	${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sip_protos.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/sip_status.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/sip_tag_class.h
	${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sip_tag.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/sip_util.h
	PARENT_SCOPE
)

add_library(sip OBJECT
    sip_basic.c
    sip_caller_prefs.c
    sip_event.c
    sip_extra.c
    sip_feature.c
    sip_header.c
    sip_inlined.c
    sip_mime.c
    sip_parser.c
    sip_prack.c
    sip_pref_util.c
    sip_reason.c
    sip_refer.c
    sip_security.c
    sip_session.c
    sip_status.c
    sip_tag_class.c
    sip_time.c
    sip_util.c
    ${CMAKE_CURRENT_BINARY_DIR}/sip_parser_table.c
    ${CMAKE_CURRENT_BINARY_DIR}/sip_tag.c
    ${CMAKE_CURRENT_BINARY_DIR}/sip_tag_ref.c
    ${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sip_hclasses.h
    ${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sip_protos.h
    ${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sip_tag.h
    ${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sip_extra.h
)
target_compile_options(sip PRIVATE -fPIC)
target_include_directories(sip
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:msg,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
)
add_dependencies(sip msg)

if(ENABLE_UNIT_TESTS)
	set(TESTERS
	    test_date
	    test_sip_msg
	    torture_sip
	    validator
	)
	foreach(tester ${TESTERS})
	    add_executable(${tester} ${tester}.c)
	    target_link_libraries(${tester} PRIVATE sip su msg url bnf)
	endforeach(tester)
endif()
