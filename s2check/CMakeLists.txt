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


add_library(s2 STATIC
    EXCLUDE_FROM_ALL
    exit77.c
    s2base.c
    s2dns.c
    s2_localinfo.c
    s2sip.c
    s2tcase.c
    s2time.c
)
target_include_directories(s2
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    INTERFACE ${LIBCHECK_INCLUDE_DIR}
)
target_link_libraries(s2
    PUBLIC bnf msg sip sresolv su tport url
    INTERFACE ${LIBCHECK_LIBRARIES}
)
