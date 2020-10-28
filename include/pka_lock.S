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

// ARMv8 Assembler code to implement the locking and atomic_bit ops:

// The following function will try to acquire the lock by atomically setting
// the bottom byte of the "lock" to its thread number "num + 1" (allowing for
// the possibility that thread number's start at 0). But this will only
// succeed if this bottom byte is zero.  If the lock is already held by
// another thread (bottom byte is non-zero) then based upon the "bit" argument
// it will either (a) return failure or (b) set its dedicated "request" bit in
// this same "lock" so that the current lock owner will know about this request,
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

// int pka_try_acquire_lock(uint64_t *lock,
//                          uint32_t  num),
//                          bool      set_bit);

    .text
    .balign  64
    .global  pka_try_acquire_lock
pka_try_acquire_lock:
    ldaxr  X3, [X0]
    add    X5, X1, #8
    lsl    X4, X2, X5
    orr    X4, X4, X3
    add    X5, X1, #1
    mov    X6, #0xFF
    ands   X6, X3, X6
    orr    X5, X5, X3
    csel   X3, X5, X4, eq
    stlxr  W7, X3, [X0]
    cbnz   W7, acquire_lock_fail

    // Our store exclusive instruction succeeded in changing the lock_word.
    // If we wrote our "num + 1" to the bottom byte we now own the lock
    // so return 1.  Otherwise return 0 when set_bit is TRUE and -1 when
    // set_bit is FALSE.
    beq    lock_acquired
    sub    X0, X2, #1
    ret

lock_acquired:
    mov    X0, #1
    ret

    // When the load exclusive/store exclusive fail (i.e. store doesn't happen),
    // wait a little bit of time before trying again.
acquire_lock_fail:
    mov    X6, #20

acquire_lock_delay_loop:
    sub    X6, X6, #1
    cmp    X6, #0
    ble    pka_try_acquire_lock
    b      acquire_lock_delay_loop


// The following function will try to release the lock by atomically setting
// the bottom byte of the lock_word to 0. However this will fail if any of the
// dedicated "request" bits in the upper 7 bytes are set, in which case the
// current lock owner thread MAY still have work to do.
//
// Return -1 if the lock was released.  Otherwise return the thread_num
// corresponding to ONE of the set request bits and clr this bit.

// int pka_try_release_lock(uint64_t *lock_word, uint32_t thread_num);

    .balign  64
    .global  pka_try_release_lock
pka_try_release_lock:
    ldaxr  X2, [X0]
    mov    X3, #0xFF
    mov    X4, #63
    bic    X3, X2, X3
    clz    X5, X3
    sub    X5, X4, X5
    cmp    X3, #0
    mov    X4, #1
    lsl    X6, X4, X5
    bic    X6, X2, X6
    csel   X2, X3, X6, eq
    stlxr  W7, X2, [X0]
    cbnz   W7, release_lock_fail

    beq    lock_released
    sub    X0, X5, #8
    ret

lock_released:
    mov    X0, #-1
    ret

    // When the load exclusive/store exclusive fail (i.e. store doesn't happen),
    // wait a little bit of time before trying again.
release_lock_fail:
    mov    X6, #20

release_lock_delay_loop:
    sub    X6, X6, #1
    cmp    X6, #0
    ble    pka_try_release_lock
    b      release_lock_delay_loop



// void pka_wait(void)

    .global pka_wait
pka_wait:
    mov  X0, #50

pause_loop:
    sub X0, X0, #1
    cmp X0, #0
    bgt pause_loop

    ret
