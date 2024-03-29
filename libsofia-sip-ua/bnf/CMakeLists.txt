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

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
	"${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/bnf.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/hostdomain.h"
	PARENT_SCOPE
)

add_library(bnf OBJECT
    bnf.c
)
target_compile_options(bnf PRIVATE -fPIC)
target_include_directories(bnf
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
)

if(ENABLE_UNIT_TESTS)
	add_executable(torture_bnf torture_bnf.c)
	target_link_libraries(torture_bnf PRIVATE bnf su)
endif()
