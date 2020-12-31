########### next target ###############

cmake_minimum_required(VERSION 3.1.0)
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
project(kde2-kio-sftp)

find_package(Qt2 REQUIRED)

find_package(ZLIB REQUIRED)
find_package(kdelibs2 REQUIRED)
find_package(DCOP REQUIRED)
find_package(kdecore REQUIRED)
find_package(kdeui REQUIRED)
find_package(kssl REQUIRED)
find_package(kdesu REQUIRED)
find_package(kio REQUIRED)
find_package(ksycoca REQUIRED)

set(kio_sftp_PART_SRCS
   kio_sftp.cpp
)

include_directories(${LIBSSH_INCLUDE_DIRS})

kde2_module(kio_sftp SOURCES ${kio_sftp_PART_SRCS} LIBS kde2::kio kde2::ksycoca)

install(FILES sftp.protocol DESTINATION "${KDE2_SERVICESDIR}")

