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


configure_file(sofia-sip/su_configure.h.cmake sofia-sip/su_configure.h COPYONLY)

set(SOFIA_SIP_PUBLIC_HEADERS ${SOFIA_SIP_PUBLIC_HEADERS}
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/heap.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/htable2.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/htable.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/rbtree.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/string0.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_addrinfo.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_alloc.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_alloc_stat.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_bm.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_config.h
        ${CMAKE_CURRENT_BINARY_DIR}/sofia-sip/su_configure.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_debug.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_errno.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_localinfo.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_log.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_md5.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_os_nw.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_osx_runloop.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_random.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_string.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_strlst.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_tagarg.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_tag_class.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_tag.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_tag_inline.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_tag_io.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_time.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_types.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_uniqueid.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_vector.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/su_wait.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sofia-sip/tstdef.h
        PARENT_SCOPE
        )

add_library(su OBJECT
        #foo.c
        #getopt.c
        #inet_pton.c
        #memccpy.c
        #memcspn.c
        #memmem.c
        #memspn.c
        #poll.c
        smoothsort.c
        string0.c
        strtoull.c
        su_addrinfo.c
        su_alloc.c
        su_alloc_lock.c
        su_base_port.c
        su_bm.c
        su.c
        su_default_log.c
        su_devpoll_port.c
        su_epoll_port.c
        su_errno.c
        su_global_log.c
        su_kqueue_port.c
        su_localinfo.c
        su_log.c
        su_md5.c
        su_os_nw.c
        #su_perf.c
        su_poll_port.c
        su_port.c
        su_pthread_port.c
        su_root.c
        su_select_port.c
        su_socket_port.c
        su_sprintf.c
        su_strdup.c
        su_string.c
        su_strlst.c
        su_tag.c
        su_tag_io.c
        su_taglist.c
        su_time0.c
        su_time.c
        su_timer.c
        su_uniqueid.c
        su_vector.c
        su_wait.c
        #su_win32_port.c
        )
target_compile_options(su PRIVATE -fPIC)
target_include_directories(su PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(su INTERFACE pthread)

add_executable(addrinfo addrinfo.c)
target_link_libraries(addrinfo PRIVATE su)

add_executable(localinfo localinfo.c)
target_link_libraries(localinfo PRIVATE su)

if (ENABLE_UNIT_TESTS)
    set(CHECK_PROGRAMS
            su_proxy
            test_htable
            test_htable2
            test_memmem
            test_poll
            test_su
            torture_heap
            torture_rbtree
            torture_su
            torture_su_alloc
            #torture_su_bm
            #torture_su_port
            torture_su_root
            torture_su_tag
            torture_su_time
            torture_su_timer
            )
    foreach (program ${CHECK_PROGRAMS})
        add_executable(${program} ${program}.c)
        target_link_libraries(${program} PRIVATE su)
    endforeach (program)
endif ()
