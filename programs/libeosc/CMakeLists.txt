

if( UNIX AND NOT APPLE )
  set(rt_library rt )
endif()
configure_file(config.hpp.in config.hpp ESCAPE_QUOTES)

add_library( eosc STATIC libeos.cpp httpc.cpp localize.hpp config.hpp )
target_include_directories(eosc PUBLIC ${Intl_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries( eosc
                       PRIVATE appbase version chain_api_plugin producer_plugin chain_plugin http_plugin eosio_chain fc ${CMAKE_DL_LIBS} ${PLATFORM_SPECIFIC_LIBS} ${Intl_LIBRARIES} )


FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

FIND_PACKAGE(PythonLibs)
INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH} ${Intl_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_SWIG_FLAGS "")

set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH "@loader_path")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

SET_SOURCE_FILES_PROPERTIES(eos.i PROPERTIES CPLUSPLUS ON)
#SET_SOURCE_FILES_PROPERTIES(eos.i PROPERTIES INCLUDE_DIRECTORIES "${Intl_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}")

SWIG_ADD_LIBRARY(eospy LANGUAGE python SOURCES eos.i libeos.cpp httpc.cpp localize.hpp)
SWIG_LINK_LIBRARIES(eospy ${PYTHON_LIBRARIES} eosc appbase version chain_api_plugin producer_plugin chain_plugin http_plugin eosio_chain fc ${CMAKE_DL_LIBS} ${PLATFORM_SPECIFIC_LIBS} ${Intl_LIBRARIES} )
