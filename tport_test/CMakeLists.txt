add_executable(tport_test tport_test.cpp)
target_link_libraries(tport_test PRIVATE sofia-sip-ua)

add_executable(tls_server tls_server.cpp)
target_link_libraries(tls_server PRIVATE OpenSSL::SSL)
