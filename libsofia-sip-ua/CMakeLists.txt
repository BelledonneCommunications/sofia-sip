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


find_program(AWK awk)
find_program(ENV_EXECUTABLE env)
set(MSG_PARSER_AWK ${CMAKE_CURRENT_SOURCE_DIR}/msg/msg_parser.awk)
set(TAG_AWK ${CMAKE_CURRENT_SOURCE_DIR}/su/tag_dll.awk)
set(AWK_MSG_AWK ${ENV_EXECUTABLE} LC_ALL=C ${AWK} -f ${MSG_PARSER_AWK})

macro(sofia_configure_file src dest base type)
	# Ensure the destination directory is created
	get_filename_component(outputdir "${CMAKE_CURRENT_BINARY_DIR}/${dest}" DIRECTORY)
	execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory "${outputdir}")

    add_custom_command(OUTPUT ${dest}
        COMMAND ${AWK_MSG_AWK} ${ARGN}
        ${type}=${CMAKE_CURRENT_BINARY_DIR}/${dest} TEMPLATE=${src} ${base}
        DEPENDS ${base} ${MSG_PARSER_AWK} ${src}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endmacro(sofia_configure_file)

macro(sofia_add_tag_awk_command src dest)
	set(tag_dll_params "NODLL=1")
	if(${ARGC} GREATER 2)
		string(APPEND tag_dll_params " ${ARGV3}")
	endif()
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${dest}
        COMMAND ${AWK} -f ${TAG_AWK} ${tag_dll_params} REF=${CMAKE_CURRENT_BINARY_DIR}/${dest} ${src}
        DEPENDS ${TAG_AWK} ${src}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    unset(tag_dll_params)
endmacro(sofia_add_tag_awk_command)

set(SOFIA_SIP_PUBLIC_HEADERS "")
set(sofia_sip_subprojects "bnf" "features" "http" "ipt" "iptsec" "msg" "nea" "nta" "nth"
	"nua" "sdp" "sip" "soa" "sresolv" "stun" "su" "tport" "url")

add_library(sofia-sip-ua SHARED dummy.c)
foreach(subproject ${sofia_sip_subprojects})
	add_subdirectory("${subproject}")
	list(APPEND sofia_sip_interface_include_dirs $<TARGET_PROPERTY:${subproject},INTERFACE_INCLUDE_DIRECTORIES>)
	target_link_libraries(sofia-sip-ua PRIVATE ${subproject})
endforeach()
set_target_properties(sofia-sip-ua PROPERTIES
	SOVERSION "0"
	VERSION "0.6.0"
	PUBLIC_HEADER "${SOFIA_SIP_PUBLIC_HEADERS}"
	INTERFACE_INCLUDE_DIRECTORIES "${sofia_sip_interface_include_dirs}"
)

include(GNUInstallDirs)
install(TARGETS sofia-sip-ua
	LIBRARY
		DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	PUBLIC_HEADER
		DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/sofia-sip-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}/sofia-sip"
)
