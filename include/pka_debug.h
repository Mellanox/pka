//
//   BSD LICENSE
//
//   Copyright(c) 2016 Mellanox Technologies, Ltd. All rights reserved.
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions
//   are met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//     * Neither the name of Mellanox Technologies nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#ifndef __PKA_DEBUG_H__
#define __PKA_DEBUG_H__

// PKA library bitmask. Use those bits to enable debug messages
#define PKA_DRIVER              0x0001
#define PKA_DEV                 0x0002
#define PKA_RING                0x0004
#define PKA_QUEUE               0x0008
#define PKA_MEM                 0x0010
#define PKA_USER                0x0020
#define PKA_TESTS               0x0040
// PKA debug mask. This indicates the debug/verbosity level.
#define PKA_DEBUG_LIB_MASK      0x0040

#ifdef __KERNEL__

#define PKA_PRINT(lib, fmt, args...) \
    ({ pr_info(#lib": "fmt, ##args); })

#define PKA_ERROR(lib, fmt, args...) \
    ({ pr_err(#lib": %s: error: "fmt, __func__, ##args); })

#define PKA_DEBUG(lib, fmt, args...) \
    ({                                                    \
        if (lib & PKA_DEBUG_LIB_MASK)                     \
            pr_debug(#lib": %s: "fmt, __func__, ##args);  \
    })

#define PKA_PANIC(lib, msg, args...) \
    ({ \
        pr_info(#lib": %s: panic: "msg, __func__, ##args); \
        panic(msg, ##args);                                     \
    })

#else

#define PKA_PRINT(lib, fmt, args...) \
    ({ printf(#lib": "fmt, ##args); })

#define PKA_ERROR(lib, fmt, args...) \
    ({ printf(#lib": %s: error: "fmt, __func__, ##args); })

#define PKA_DEBUG(lib, fmt, args...) \
    ({                                                  \
        if (lib & PKA_DEBUG_LIB_MASK)                   \
            printf(#lib": %s: "fmt, __func__, ##args);  \
    })

#define PKA_ASSERT_STR(cond, msg) \
    ({ if (!(cond)) {        \
        printf("%s\n", msg); \
        abort(); }           \
    })

#define PKA_ASSERT(cond) PKA_ASSERT_STR(cond, " assert failed: " #cond)

#endif // __KERNEL__

#endif // __PKA_DEBUG_H__
