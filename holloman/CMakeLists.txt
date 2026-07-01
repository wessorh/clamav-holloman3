# Holloman fingerprint library — built from source
# Requires AVX2 CPU support (Intel Haswell 2013+ / AMD Zen 2017+)

set(HOLLOMAN_SOURCES
    holloman_avx2.c
    lanczos_avx2_optimized.c
    hilbert.c
    hilbert_mapping.c
    hilbert_utils.c
    hilbert_external_buffer.c
    arch_detect.c
)

# Assembly sources (AVX2 SIMD)
set(HOLLOMAN_ASM
    hilbert_avx2.s
    hilbert_mapping_avx2.s
    hilbert_mapping_avx2_cache_blocking.s
    hilbert_utils_avx2.s
    hilbert_external_buffer_asm.s
)

# Enable assembly language support
enable_language(ASM)

add_library(holloman_avx2 STATIC
    ${HOLLOMAN_SOURCES}
    ${HOLLOMAN_ASM}
)

target_include_directories(holloman_avx2
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/hilbert-avx2/include
)

target_compile_options(holloman_avx2 PRIVATE
    -O3 -mavx2 -std=c11
    -Wall -Wextra
)

# Link math library
target_link_libraries(holloman_avx2 PRIVATE m)

# Install
install(TARGETS holloman_avx2
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES holloman.h hilbert.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/holloman
)
