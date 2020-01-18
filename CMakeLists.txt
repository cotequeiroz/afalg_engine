#  Copyright 2019 Eneas Ulir de Queiroz
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 2.6 FATAL_ERROR)
project(afalg_engine LANGUAGES C)

find_package(OpenSSL 1.1.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Remove when https://gitlab.kitware.com/cmake/cmake/issues/18525 is addressed
set(OPENSSL_ENGINES_DIR "" CACHE PATH "OpenSSL Engines Directory")
if ("${OPENSSL_ENGINES_DIR}" STREQUAL "")
	include(FindPkgConfig)
	pkg_get_variable(OPENSSL_ENGINES_DIR libcrypto enginesdir)
	if ("${OPENSSL_ENGINES_DIR}" STREQUAL "")
		message( FATAL_ERROR "Unable to discover the OpenSSL engines directory. Provide the path using -DOPENSSL_ENGINES_DIR" )
	endif()
endif()

option(USE_ZERO_COPY "Use zero-copy AF_ALG interface" OFF)
if (USE_ZERO_COPY)
	add_definitions(-DAFALG_ZERO_COPY)
endif()

option(UPDATE_CTR_IV "Don't rely on kernel driver to update CTR-mode IV" ON)
if (NOT UPDATE_CTR_IV)
	add_definitions(-DAFALG_KERNEL_UPDATES_CTR_IV)
endif()

add_library(afalg_engine MODULE afalg.c)
set_target_properties(afalg_engine PROPERTIES PREFIX "" OUTPUT_NAME "afalg")
target_link_libraries(afalg_engine ${OPENSSL_CRYPTO_LIBRARY})

install(TARGETS afalg_engine LIBRARY DESTINATION ${OPENSSL_ENGINES_DIR})
