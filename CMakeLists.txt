cmake_minimum_required(VERSION 3.1)
project("vdens"
    DESCRIPTION "create user namespaces connected to vde networks"
    HOMEPAGE_URL "https://github.com/rd235/vdens"
		VERSION 0.1
    LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFile)
set(CMAKE_REQUIRED_QUIET TRUE)
set(LIBS_REQUIRED vdeplug cap execs)
set(HEADERS_REQUIRED libvdeplug.h sys/capability.h execs.h)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
	find_library(LIB${THISLIB}_OK ${THISLIB})
	if(NOT LIB${THISLIB}_OK)
		message(FATAL_ERROR "library lib${THISLIB} not found")
	endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
	check_include_file(${HEADER} ${HEADER}_OK)
	if(NOT ${HEADER}_OK)
		message(FATAL_ERROR "header file ${HEADER} not found")
	endif()
endforeach(HEADER)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(vdens vdens.c)
target_link_libraries(vdens cap execs vdeplug)

install(TARGETS vdens DESTINATION ${CMAKE_INSTALL_BINDIR})

file(GLOB MAN1_PAGES ${CMAKE_CURRENT_SOURCE_DIR}/*.1)

install(FILES ${MAN1_PAGES} DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")
