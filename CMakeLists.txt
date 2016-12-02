project(libco)
cmake_minimum_required(VERSION 3.5)
enable_language(C ASM)
set(CXXFLAGS -g -fno-strict-aliasing -O2 -Wall -export-dynamic -Wall -pipe  -D_GNU_SOURCE -D_REENTRANT -fPIC -Wno-deprecated -m64)
set(LINKS -g  -lpthread -ldl)
SET(CMAKE_ASM_FLAGS "${CFLAGS} -x assembler-with-cpp")
add_library(coctx_swap coctx_swap.S)
set(LIB_FILE
        co_closure.h
        co_routine.h
        co_routine_inner.h
        co_routine_specific.h
        co_epoll.cpp
        co_routine.cpp
        co_hook_sys_call.cpp
        coctx.cpp
        )
add_library(colib ${LIB_FILE})
target_link_libraries(colib ${LINKS} coctx_swap)
add_executable(example_echosvr example_echosvr.cpp)
target_link_libraries(example_echosvr colib)
add_executable(example_closure example_closure.cpp)
target_link_libraries(example_closure colib)

add_executable(example_cond example_cond.cpp)
target_link_libraries(example_cond colib)
add_executable(example_poll example_poll.cpp)
target_link_libraries(example_poll colib)
add_executable(example_copystack example_copystack.cpp)
target_link_libraries(example_copystack colib)
add_executable(example_setenv example_setenv.cpp)
target_link_libraries(example_setenv colib)
add_executable(example_specific example_specific.cpp)
target_link_libraries(example_specific colib)
add_executable(example_thread example_thread.cpp)
target_link_libraries(example_thread colib)
add_executable(example_echocli example_echocli.cpp)
target_link_libraries(example_echocli colib)
