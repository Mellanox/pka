// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

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
