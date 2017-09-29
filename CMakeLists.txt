cmake_minimum_required(VERSION 2.8)
project(dlfcn)

add_library(dl        STATIC dlfcn.c dlfcn.h)

add_library(dl-shared SHARED dlfcn.c dlfcn.h)
target_link_libraries(dl-shared dbghelp)
set_target_properties(dl-shared PROPERTIES OUTPUT_NAME "dl" PREFIX "")

install(TARGETS dl dl-shared
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)
install(FILES dlfcn.h DESTINATION include)
