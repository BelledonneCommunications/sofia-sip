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


configure_file(sofia-sip/sofia_features.h.in sofia-sip/sofia_features.h @ONLY)

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	"${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/sofia_features.h"
	PARENT_SCOPE
)

add_library(features OBJECT features.c)
target_include_directories(features
    PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
    PRIVATE $<TARGET_PROPERTY:msg,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:stun,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:tport,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
)
target_compile_options(features PRIVATE "-fPIC")
add_dependencies(features msg)
