cmake_minimum_required(VERSION 3.10)

project(ckit VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)

configure_file(${CMAKE_CURRENT_LIST_DIR}/version.h.in ${CMAKE_CURRENT_LIST_DIR}/include/${PROJECT_NAME}/version.h)

option(ENABLE_TEST "enable test" ON)

file(GLOB_RECURSE LIB_INC_FILES ${CMAKE_CURRENT_LIST_DIR}/include/${PROJECT_NAME}/*.h)
aux_source_directory(src LIB_SRC_FILES)
add_library(${PROJECT_NAME} STATIC ${LIB_SRC_FILES})
target_include_directories(${PROJECT_NAME} SYSTEM AFTER PUBLIC include/${PROJECT_NAME})

# install
install(TARGETS ${PROJECT_NAME} DESTINATION lib)
install(FILES ${LIB_INC_FILES} DESTINATION include)

# testing 
if (${ENABLE_TEST})
    add_subdirectory(test)
endif()