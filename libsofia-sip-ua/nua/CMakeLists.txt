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


sofia_add_tag_awk_command("${CMAKE_CURRENT_SOURCE_DIR}/nua_tag.c" "nua_tag_ref.c" "nua_tag_list")

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/nua.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/nua_tag.h
	PARENT_SCOPE
)

add_library(nua OBJECT
#     check_etsi.c
#     check_nua.c
#     check_register.c
#     check_session.c
#     check_simple.c
    nua.c
    nua_client.c
    nua_common.c
    nua_dialog.c
    nua_event_server.c
    nua_extension.c
    nua_message.c
    nua_notifier.c
    nua_options.c
    nua_params.c
    nua_publish.c
    nua_register.c
    nua_registrar.c
    nua_server.c
    nua_session.c
    nua_stack.c
    nua_subnotref.c
    nua_tag.c
    nua_tag_ref.c
    outbound.c
)
target_compile_options(nua PRIVATE -fPIC)
target_include_directories(nua
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:ipt,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:iptsec,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:msg,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:nea,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:nta,INTERFACE_INCLUDE_DIRECTORIES>
	$<TARGET_PROPERTY:stun,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:sdp,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:sip,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:soa,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:tport,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
)
add_dependencies(nua msg sip)
