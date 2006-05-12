:: Run test programs
::
:: This file is part of the Sofia-SIP package
::
:: Copyright (C) 2006 Nokia Corporation.
::
:: Contact: Pekka Pessi <pekka.pessi@nokia.com>
::
:: This library is free software; you can redistribute it and/or
:: modify it under the terms of the GNU Lesser General Public License
:: as published by the Free Software Foundation; either version 2.1 of
:: the License, or (at your option) any later version.
::
:: This library is distributed in the hope that it will be useful, but
:: WITHOUT ANY WARRANTY; without even the implied warranty of
:: MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
:: Lesser General Public License for more details.
::
:: You should have received a copy of the GNU Lesser General Public
:: License along with this library; if not, write to the Free Software
:: Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
:: 02110-1301 USA
::
tests\su_alloc_test\Debug\su_alloc_test.exe
@if errorlevel 1 ( echo su_alloc_test: FAIL ) else echo su_alloc_test: PASS

tests\su_root_test\Debug\su_root_test.exe
@if errorlevel 1 ( echo su_root_test: FAIL ) else echo su_root_test: PASS

tests\su_tag_test\Debug\su_tag_test.exe
@if errorlevel 1 ( echo su_tag_test: FAIL ) else echo su_tag_test: PASS

tests\su_test\Debug\su_test.exe
@if errorlevel 1 ( echo su_test: FAIL ) else echo su_test: PASS

tests\su_time_test\Debug\su_time_test.exe
@if errorlevel 1 ( echo su_time_test: FAIL ) else echo su_time_test: PASS

tests\su_timer_test\Debug\su_timer_test.exe
@if errorlevel 1 ( echo su_timer_test: FAIL ) else echo su_timer_test: PASS

tests\su_torture\Debug\su_torture.exe
@if errorlevel 1 ( echo su_torture: FAIL ) else echo su_torture: PASS

tests\test_memmem\Debug\test_memmem.exe
@if errorlevel 1 ( echo test_memmem: FAIL ) else echo test_memmem: PASS

tests\test_tport\Debug\test_tport.exe
@if errorlevel 1 ( echo test_tport: FAIL ) else echo test_tport: PASS

tests\test_nta\Debug\test_nta.exe
@if errorlevel 1 ( echo test_nta: FAIL ) else echo test_nta: PASS

tests\test_nua\Debug\test_nua.exe
@if errorlevel 1 ( echo test_nua: FAIL ) else echo test_nua: PASS

tests\torture_htable\Debug\torture_htable.exe
@if errorlevel 1 ( echo torture_htable: FAIL ) else echo torture_htable: PASS

tests\torture_rbtree\Debug\torture_rbtree.exe
@if errorlevel 1 ( echo torture_rbtree: FAIL ) else echo torture_rbtree: PASS

tests\torture_su_bm\Debug\torture_su_bm.exe
@if errorlevel 1 ( echo torture_su_bm: FAIL ) else echo torture_su_bm: PASS

tests\torture_su_port\Debug\torture_su_port.exe
@if errorlevel 1 ( echo torture_su_port: FAIL ) else echo torture_su_port: PASS
