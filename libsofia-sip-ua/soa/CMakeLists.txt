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


sofia_add_tag_awk_command(${CMAKE_CURRENT_SOURCE_DIR}/soa_tag.c soa_tag_ref.c soa_tag_list)

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/soa_add.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/soa.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/soa_session.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/soa_tag.h
	PARENT_SCOPE
)

add_library(soa OBJECT
    soa.c
    soa_static.c
    soa_tag.c
    soa_tag_ref.c
#     test_soa.c
)
target_compile_options(soa PRIVATE -fPIC)
target_include_directories(soa
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:sdp,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:sip,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
)
add_dependencies(soa sip)
