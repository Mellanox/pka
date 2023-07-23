// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef __PKA_ATOMIC_H__
#define __PKA_ATOMIC_H__

#include <stdint.h>
#include <stdbool.h>

// ARMv8 Assembler code to implement the locking and atomic_bit operations:


// Atomic integers using relaxed memory ordering
//
// Atomic integer types (pka_atomic32_t and pka_atomic64_t) can be used to
// implement e.g. shared counters. If not otherwise documented, operations in
// this API are implemented using "RELAXED memory ordering" (see memory
// order descriptions in the C11 specification). Relaxed operations do not
// provide synchronization or ordering for other memory accesses (initiated
// before or after the operation), only atomicity of the operation itself is
// guaranteed.

//  Atomic 32-bit unsigned integer
typedef struct
{
    uint32_t v; ///< Actual storage for the atomic variable
} pka_atomic32_t __pka_aligned(sizeof(uint32_t)); // Enforce alignement!

// Atomic 64-bit unsigned integer
typedef struct
{
   uint64_t v; ///< Actual storage for the atomic variable
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
   // Some architectures do not support lock-free operations on 64-bit
   // data types. We use a spin lock to ensure atomicity.
   char lock;  ///< Spin lock (if needed) used to ensure atomic access
#endif
} pka_atomic64_t __pka_aligned(sizeof(uint64_t)); // Enforce alignement!

// 32-bit operations in RELAXED memory ordering

static inline void pka_atomic32_init(pka_atomic32_t *atom, uint32_t val)
{
    __atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

// Load value of atomic uint32 variable. Return Value of the variable
static inline uint32_t pka_atomic32_load(pka_atomic32_t *atom)
{
    return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
}

// Atomic fetch and add of 32-bit atomic variable. Return Value of the atomic
// variable before the addition.
static inline uint32_t _pka_atomic32_fetch_add_relaxed(pka_atomic32_t *atom,
                                                       uint32_t        val)
{
    return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

// Fetch and increment atomic uint32 variable. Return Value of the variable
// before the increment
static inline uint32_t pka_atomic32_fetch_inc_relaxed(pka_atomic32_t *atom)
{
    return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

// Increment atomic uint32 variable
static inline void pka_atomic32_inc(pka_atomic32_t *atom)
{
    (void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}


// Atomic fetch and subtract of 32-bit atomic variable. Return Value of the
// atomic variable before the subtraction
static inline uint32_t _pka_atomic32_fetch_sub_relaxed(pka_atomic32_t *atom,
                                                       uint32_t        val)
{
    return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

static inline uint32_t pka_atomic32_sub(pka_atomic32_t *atom,
                                        uint32_t        val)
{
    return _pka_atomic32_fetch_sub_relaxed(atom, val);
}

// Decrement atomic uint32 variable
static inline void pka_atomic32_dec(pka_atomic32_t *atom)
{
    (void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

// 64-bit operations in RELAXED memory ordering

#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
#define ATOMIC_CAS_OP(ret_ptr, old_val, new_val) \
({ \
    if (atom->v == (old_val)) { \
        atom->v = (new_val); \
        *(ret_ptr) = 1; \
    } else { \
        *(ret_ptr) = 0; \
    } \
})

// Helper macro for lock-based atomic operations on 64-bit integers. Return
// The old value of the variable.
#define ATOMIC_OP(atom, expr) \
({ \
    uint64_t _old_val; \
    /* Loop while lock is already taken, stop when lock becomes clear */ \
    while (__atomic_test_and_set(&(atom)->lock, __ATOMIC_ACQUIRE)) \
        (void)0; \
    _old_val = (atom)->v; \
    (expr); /* Perform whatever update is desired */ \
    __atomic_clear(&(atom)->lock, __ATOMIC_RELEASE); \
    _old_val; /* Return old value */ \
})
#endif

static inline void pka_atomic64_init(pka_atomic64_t *atom, uint64_t val)
{
    atom->v = val;
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
    __atomic_clear(&atom->lock, __ATOMIC_RELAXED);
#endif
}

// Atomic fetch and add of 64-bit atomic variable. Return Value of the atomic
// variable before the addition
static inline uint64_t _pka_atomic64_fetch_add_relaxed(pka_atomic64_t *atom,
                                                       uint64_t        val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
    return ATOMIC_OP(atom, atom->v += val);
#else
    return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

// Increment atomic uint64 variable
static inline void pka_atomic64_inc(pka_atomic64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
    (void)ATOMIC_OP(atom, atom->v++);
#else
    (void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

// Atomic fetch and subtract of 64-bit atomic variable. Return Value of the
// atomic variable before the addition
static inline uint64_t _pka_atomic64_fetch_sub_relaxed(pka_atomic64_t *atom,
                                                       uint64_t        val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
    return ATOMIC_OP(atom, atom->v -= val);
#else
    return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

// Decrement atomic uint64 variable
static inline void pka_atomic64_dec(pka_atomic64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
    (void)ATOMIC_OP(atom, atom->v--);
#else
    (void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}


// Operations with non-relaxed memory ordering
//
// An operation with RELEASE memory ordering (pka_atomic_xxx_rel_xxx())
// ensures that other threads loading the same atomic variable with ACQUIRE
// memory ordering see all stores (from the calling thread) that happened
// before this releasing store.
//
// An operation with ACQUIRE memory ordering (pka_atomic_xxx_acq_xxx())
// ensures that the calling thread sees all stores (done by the releasing
// thread) that happened before a RELEASE memory ordered store to the same
// atomic variable.
//
// An operation with ACQUIRE-and-RELEASE memory ordering
// (pka_atomic_xxx_acq_rel_xxx()) combines the effects of ACQUIRE and RELEASE
// memory orders. A single operation acts as both an acquiring load and
// a releasing store.

// 32-bit operations in non-RELAXED memory ordering

// Compare and swap atomic uint32 variable using ACQUIRE-and-RELEASE memory
// ordering
static inline int pka_atomic32_cas_acq_rel(pka_atomic32_t *atom,
                                           uint32_t       *old_val,
                                           uint32_t        new_val)
{
    return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
                       0 /* strong */,
                       __ATOMIC_ACQ_REL,
                       __ATOMIC_RELAXED);
}

// Compare and swap atomic uint64 variable using ACQUIRE-and-RELEASE memory
// ordering
static inline int pka_atomic64_cas_acq_rel(pka_atomic64_t *atom,
                                           uint64_t       *old_val,
                                           uint64_t        new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
    int ret;
    *old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
    return ret;
#else
    return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
                       0 /* strong */,
                       __ATOMIC_ACQ_REL,
                       __ATOMIC_RELAXED);
#endif
}


typedef enum
{
    LOCK_ACQUIRED     =  1,
    LOCK_RELEASED     = -1,
    LOCK_NOT_ACQUIRED = -1,
    LOCK_BIT_SET      =  0,
} pka_lock_t;

// Functions below are implemented in the assembler file (pka_lock.S)

// The following function will try to acquire the lock by atomically setting the
// bottom byte of the "lock" to its thread number "num + 1" (allowing for the
// possibility that thread number's start at 0). But this will only succeed if
// this bottom byte is zero.  If the lock is already held by another thread
// (bottom byte is non-zero) then based upon the "bit" argument it will
// either (a) return failure or (b) set its dedicated "request" bit in this
// same "lock" so that the current lock owner will know about this request -
// in particular the lock owner will not be able to release this lock while
// any of these request bits are set.
//
// Note that the dedicated thread request bit for "num" N is located at
// "lock" bit N + 8.  This implies a maximum of 56 PK threads per execution
// context.
//
// This function will return 1 if the lock was acquired (in which case the
// thread bit is never set - even if set_bit was TRUE).  This function will
// return 0 if the lock was NOT acquired but the thread bit was set (which
// implies "set_bit" is TRUE).  Finally it will return -1 if the lock was NOT
// acquired AND the thread bit was not set because "set_bit" was FALSE.
int pka_try_acquire_lock(uint64_t *lock_v, uint32_t num, bool set_bit);

// The following function will try to release the lock by atomically setting
// the bottom byte of the lock_word to 0. However this will fail if any of the
// dedicated "request" bits in the upper 7 bytes are set, in which case the
// current lock owner thread MAY still have work to do.
//
// Return -1 if the lock was released.  Otherwise return the thread_num
// corresponding to ONE of the set request bits and clr this bit.
int pka_try_release_lock(uint64_t *lock_v, uint32_t num);

#endif // __PKA_ATOMIC_H__
