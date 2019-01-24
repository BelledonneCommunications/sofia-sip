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
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/sresolv.h
	${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/sres_sip.h
	PARENT_SCOPE
)

add_library(sresolv OBJECT
#     check_sres_sip.c
#     resolve_sip.c
    sres_blocking.c
    sres.c
    sres_cache.c
    sresolv.c
    sres_sip.c
#     test_sresolv.c
#     torture_sresolv.c
)
target_compile_options(sresolv PRIVATE -fPIC)
target_include_directories(sresolv
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE $<TARGET_PROPERTY:bnf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:su,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:url,INTERFACE_INCLUDE_DIRECTORIES>
)
