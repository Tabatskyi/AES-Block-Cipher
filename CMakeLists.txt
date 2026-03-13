cmake_minimum_required(VERSION 3.25)

project(AES_Block_Cipher
    VERSION 0.0.1
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

# Create custom target to setup virtual environment
add_custom_target(
    setup_venv ALL
    COMMAND ${Python3_EXECUTABLE} -m venv ${VENV_DIR}
    COMMAND ${VENV_PIP} install -r ${CMAKE_CURRENT_SOURCE_DIR}/test/requirements.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Setting up Python virtual environment with dependencies..."
)

# Ensure the C library is built before tests
add_dependencies(setup_venv ${PROJECT_NAME})

# Test 1: C library test (via direct execution)
# The C binary has its own hardcoded NIST test vectors
add_test(
    NAME C_AES_Implementation
    COMMAND ${PROJECT_NAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

set_tests_properties(C_AES_Implementation PROPERTIES
    TIMEOUT 10
)

# Tests 2-4: Python tests (PDF parsing)
# Uses hardcoded PDF_URL by default, but can be overridden via environment variable:
#   export PDF_URL=current-dir/AES_ModesA_All.pdf
#   ctest

set(DEFAULT_PDF_URL "test/AES_ModesA_All.pdf")

if(DEFINED ENV{PDF_URL})
    set(PDF_PATH "$ENV{PDF_URL}")
else()
    set(PDF_PATH "${DEFAULT_PDF_URL}")
endif()

# Python tests depend on venv setup
add_test(
    NAME AES_NIST_Vectors_PDF
    COMMAND ${VENV_PYTHON} test/test_runner.py --pdf-path "${PDF_PATH}" --verbose
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

set_tests_properties(AES_NIST_Vectors_PDF PROPERTIES
    TIMEOUT 30
    DEPENDS "setup_venv"
)

add_test(
    NAME Export_Vectors_JSON
    COMMAND ${VENV_PYTHON} test/export_vectors.py --pdf "${PDF_PATH}" --format json
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

set_tests_properties(Export_Vectors_JSON PROPERTIES
    TIMEOUT 30
    DEPENDS "setup_venv"
)

add_test(
    NAME Export_Vectors_C_Header
    COMMAND ${VENV_PYTHON} test/export_vectors.py --pdf "${PDF_PATH}" --format c
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

set_tests_properties(Export_Vectors_C_Header PROPERTIES
    TIMEOUT 30
    DEPENDS "setup_venv"
)
