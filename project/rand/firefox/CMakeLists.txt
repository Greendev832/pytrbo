cmake_minimum_required(VERSION 3.16)
project(scanner CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- OpenMP 설정 (Mac Apple Silicon 전용) ---
find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    message(STATUS "OpenMP found via CMake")
else()
    # Apple Clang은 기본적으로 OpenMP를 지원하지 않으므로 Homebrew의 libomp를 수동으로 지정
    execute_process(
        COMMAND brew --prefix libomp
        OUTPUT_VARIABLE LIBOMP_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    message(STATUS "Using manual OpenMP configuration from: ${LIBOMP_PREFIX}")

    # 플래그를 리스트로 분리 (각각의 인자로 전달)
    set(OpenMP_CXX_FLAGS_LIST "-Xpreprocessor" "-fopenmp" "-I${LIBOMP_PREFIX}/include")
    set(OpenMP_CXX_LINK_FLAGS_LIST "-L${LIBOMP_PREFIX}/lib" "-lomp")
endif()

# --- libsecp256k1 설정 ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)

if(NOT SECP256K1_FOUND)
    message(FATAL_ERROR "libsecp256k1 not found. Try: brew install secp256k1 and set PKG_CONFIG_PATH")
endif()

add_executable(scanner scanner.cpp)

# --- include 경로 ---
target_include_directories(scanner PRIVATE ${SECP256K1_INCLUDE_DIRS})
if(NOT OpenMP_CXX_FOUND)
    target_include_directories(scanner PRIVATE ${LIBOMP_PREFIX}/include)
endif()

# --- 라이브러리 경로 ---
target_link_directories(scanner PRIVATE ${SECP256K1_LIBRARY_DIRS})
if(NOT OpenMP_CXX_FOUND)
    target_link_directories(scanner PRIVATE ${LIBOMP_PREFIX}/lib)
endif()

# --- 라이브러리 링크 ---
target_link_libraries(scanner PRIVATE ${SECP256K1_LIBRARIES})
if(OpenMP_CXX_FOUND)
    target_link_libraries(scanner PRIVATE OpenMP::OpenMP_CXX)
else()
    target_link_libraries(scanner PRIVATE omp)
endif()

# --- 컴파일 옵션 ---
target_compile_options(scanner PRIVATE -O3 -march=native)
if(NOT OpenMP_CXX_FOUND)
    target_compile_options(scanner PRIVATE ${OpenMP_CXX_FLAGS_LIST})
endif()

# --- 링커 옵션 ---
if(NOT OpenMP_CXX_FOUND)
    target_link_options(scanner PRIVATE ${OpenMP_CXX_LINK_FLAGS_LIST})
endif()