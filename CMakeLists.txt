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

cmake_minimum_required(VERSION 3.2)

# CMP0077 policy is required by Flexisip build. Remove it once the CMake required
# version is higer or equal to 3.13.
cmake_policy(SET CMP0077 NEW)

project(sofia-sip VERSION 1.13.32 LANGUAGES C)

option(ENABLE_UNIT_TESTS "Build unit test executables (WIP)" OFF)

find_package(OpenSSL REQUIRED)

if(ENABLE_UNIT_TESTS)
	find_path(LIBCHECK_INCLUDE_DIR check.h)
	find_library(LIBCHECK_LIBRARIES check)

	if (LIBCHECK_INCLUDE_DIR AND LIBCHECK_LIBRARIES)
	    set(HAVE_CHECK YES)
	endif()
endif()

configure_file(config.h.cmake config.h)

include_directories(${PROJECT_BINARY_DIR})

add_subdirectory(libsofia-sip-ua)
if(ENABLE_UNIT_TESTS)
	add_subdirectory(s2check)
endif()
