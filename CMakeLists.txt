cmake_minimum_required(VERSION 3.25)

project(AES_Block_Cipher
    VERSION 1.0.0
    LANGUAGES C
)

if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
    message(WARNING
        "This project targets GCC 15+ for complete C23 support. "
        "Current compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}. "
        "Behaviour may differ or be incompatible."
    )
elseif(CMAKE_C_COMPILER_VERSION VERSION_LESS "15")
    message(WARNING
        "GCC 15 or later is required for full C23 support. "
        "Detected GCC ${CMAKE_C_COMPILER_VERSION}. "
        "Behaviour may differ or be incompatible."
    )
endif()

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

file(GLOB SOURCES CONFIGURE_DEPENDS
    *.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4
        /WX-
    )
endif()

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE bcrypt)
endif()

add_library(aes SHARED
    aes.c
    rng.c
)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(aes PRIVATE -Wall -Wextra -Wpedantic)
elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(aes PRIVATE /W4 /WX-)
endif()
if(WIN32)
    target_link_libraries(aes PRIVATE bcrypt)
endif()

# ============================================================================
# CTest Integration
# ============================================================================

enable_testing()

# Find Python interpreter for test runner
find_package(Python3 COMPONENTS Interpreter REQUIRED)

# Create virtual environment and install dependencies
set(VENV_DIR "${CMAKE_CURRENT_BINARY_DIR}/.venv")

if(WIN32)
    set(VENV_PYTHON "${VENV_DIR}/Scripts/python.exe")
    set(VENV_PIP "${VENV_DIR}/Scripts/pip.exe")
else()
    set(VENV_PYTHON "${VENV_DIR}/bin/python")
    set(VENV_PIP "${VENV_DIR}/bin/pip")
endif()

# Create custom command to setup virtual environment only when requirements change
add_custom_command(
    OUTPUT ${VENV_DIR}/setup_done.txt
    COMMAND ${Python3_EXECUTABLE} -m venv ${VENV_DIR}
    COMMAND ${VENV_PIP} install -r ${CMAKE_CURRENT_SOURCE_DIR}/test/requirements.txt
    COMMAND ${CMAKE_COMMAND} -E touch ${VENV_DIR}/setup_done.txt
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/test/requirements.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Setting up Python virtual environment with dependencies..."
)
add_custom_target(setup_venv ALL DEPENDS ${VENV_DIR}/setup_done.txt)

set(PDF_PATHS "test/AES_ECB.pdf" "test/AES_CBC.pdf" "test/AES_CFB.pdf")

# Generate nist_vectors.h at build time
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nist_vectors.h
    COMMAND ${VENV_PYTHON} test/export_vectors.py --format c --pdf ${PDF_PATHS}
    DEPENDS setup_venv test/export_vectors.py ${PDF_PATHS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Generating nist_vectors.h..."
)

# Create a target for the generation so the executable can depend on it
add_custom_target(generate_nist_vectors DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/nist_vectors.h)
add_dependencies(${PROJECT_NAME} generate_nist_vectors)

# Test 1: C library test (via direct execution)
add_test(
    NAME C_AES_Implementation
    COMMAND ${PROJECT_NAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

set_tests_properties(C_AES_Implementation PROPERTIES
    TIMEOUT 10
)

# Python tests depend on venv setup
add_test(
    NAME AES_NIST_Vectors_PDF
    COMMAND ${VENV_PYTHON} test/test_runner.py --verbose --pdf-path ${PDF_PATHS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

set_tests_properties(AES_NIST_Vectors_PDF PROPERTIES
    TIMEOUT 30
    DEPENDS "setup_venv"
)

add_test(
    NAME Padding_Oracle_Attack
    COMMAND ${VENV_PYTHON} attacks/padding_oracle_attack.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
set_tests_properties(Padding_Oracle_Attack PROPERTIES
    TIMEOUT 30
    DEPENDS "setup_venv"
)

add_test(
    NAME Bit_Flipping_Attack
    COMMAND ${VENV_PYTHON} attacks/bit_flipping_attack.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
set_tests_properties(Bit_Flipping_Attack PROPERTIES
    TIMEOUT 30
    DEPENDS "setup_venv"
)
