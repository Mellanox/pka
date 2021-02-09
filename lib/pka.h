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

///
/// @file
///
/// This file forms an interface to the BlueField PK Accelerator based
/// on EIP-154.   The API is refered to  as "northbound interface" for
/// communication between user application and PKA hardware Rings.
///
/// The PKA hardware makes available a number of basic arithmetic (e.g.,
/// add and multipy) and complex arithmetic (e.g., modular exponentiation
/// and modular inversion) as well as high-level operations such as RSA,
/// Diffie-Hallman, Elliptic Curve Cryptography, and the Federal Digital
/// Signature Algorithm (DSA as documented in FIPS 186) public-private key
/// systems.
///
/// The API consists of an interface which allows user applications to
/// accelerate PK operations. The API allows user application to open and
/// release a PK instance. A PK instance refers to an execution context,
/// i.e. parameters and hardware configuration which allows to process PK
/// operations. It then encapsulates the PK global information structure.
///
/// @note Almost all functions are asynchronous and require a 'handle'
/// argument to be passed to them. Typically, a 'handle' encapsulates
/// all the parameters, status of an execution context of a given user
/// application.
///
/// @note An application running multiple threads has as many handles
/// as threads.
///
/// For example to use this module to do a single RSA encryption, one could
/// do the following:
///
/// @code
/// // 64-bit RSA encryption example.
/// //
/// // Note that the following code does not provide application's function
/// // definition (e.g., from_hex_string(), to_hex_string()). It also omits
/// // macros definition and error checking.
///
/// pka_instance_t  instance;
/// pka_handle_t    handle;
/// pka_operand_t   encrypt_key, n, msg;
/// pka_results_t   results;
/// uint8_t         result_buf[8];
/// char*           key_string     = "0x633649F8F2228670";
/// char*           modulus_string = "0x87C1F8442909789F";
/// char*           plaintext      = "0x4869207468657265"; // hex "Hi there"
/// char            ciphertext[20];
///
/// memset(&encrypt_key, 0, sizeof(pka_operand_t));
/// memset(&n,           0, sizeof(pka_operand_t));
/// memset(&msg,         0, sizeof(pka_operand_t));
/// memset(&results,     0, sizeof(pka_results_t));
/// results.results[0].buf_ptr = result_buf;
/// results.results[0].buf_len = sizeof(result_buf);
///
/// from_hex_string(key_string,     &encrypt_key);
/// from_hex_string(modulus_string, &n);
/// from_hex_string(plaintext,      &msg);
///
/// // Global PKA initialization. This function must be called once per
/// // instance before calling any other PKA API functions.
/// instance = pka_init_global(“pka_app”,
///                 PKA_F_PROCESS_MODE_SINGLE | PKA_F_SYNC_MODE_NONE,
///                 PKA_RING_CNT, PKA_QUEUE_CNT,
///                 CMD_QUEUE_SIZE, RSLT_QUEUE_SIZE);
///
/// // Thread local PKA initialization. The instance parameter specifies which
/// // PKA instance the thread joins. It Returns a valid handle for it.
/// handle = pka_init_local(instance);
///
/// pka_rsa(handle, NULL, &encrypt_key, &n, &msg);
///
/// //
/// // Here we can do other stuff
/// //
///
/// pka_get_rslt(handle, &results);
///
/// //
/// // Here we can process other PK commands
/// //
///
/// // Release the given handle.
/// pka_term_local(handle);
/// // Release the PK instance
/// pka_term_global(instance);
///
/// to_hex_string(&results.results[0], ciphertext, 20);
/// printf("plaintext='%s'\nciphertext='%s'\n", plaintext, ciphertext);
///
/// // ciphertext should be '9F5E3B6F177E25B6'
/// @endcode
///

#ifndef __PKA_H__
#define __PKA_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stdbool.h>
#endif

/// PK instance type.
typedef uint64_t    pka_instance_t;

/// Define value for invalid PK instance.
#define PKA_INSTANCE_INVALID    0

/// PK handle (opaque) type that encapsulates local information.
typedef struct pka_local_info_t*    pka_handle_t;

/// Define value for invalid PK handle.
#define PKA_HANDLE_INVALID      NULL

/// PK flags that are supplied during PK instance initialization.
typedef enum
{
/// Single process mode:
/// A PK instance runs over one process. The process ID is stored as PK global
/// information. A single process instance might create as many worker threads
/// as needed to process PK operations.
    PKA_F_PROCESS_MODE_SINGLE      = 0x1,
///
/// Multi process mode:
/// A PK instance runs over mult-processes. The main process ID is stored as
/// PK global information. Each process might create as many worker threads
/// as needed to process PK operations. Only the main process should call the
/// pka_init_global() and pka_term_global() functions.
///
/// @note Currently multi_process_mode is not fully supported.
    PKA_F_PROCESS_MODE_MULTI       = 0x2,
///
/// None of the PK operations are synchronized :
/// The application will make sure that only one thread will make a PK call
/// at a given time. These calls could come from threads at different times.
/// PK library will ignore synchronization issues.
    PKA_F_SYNC_MODE_DISABLE        = 0x4,
///
/// All PK operations are synchronized :
/// The PK library uses internal lock to ensure that multiple threads making
/// PK calls are properly synchronized.
    PKA_F_SYNC_MODE_ENABLE         = 0x8
} pka_flags_t;

/// Global PKA initialization. This function must be called once (per instance)
/// before calling any other PKA API functions. A successful call creates a new
/// PKA instance into the system and outputs a pointer to it. The pointer is
/// used in other calls (e.g. pka_init_local()) and holds a reference to the
/// PK global information.
///
/// @param name              Name of the PK instance. Also specifies the shared
///                          memory object to be created.
/// @param flags             Flags used to select the processing mode and the
///                          synchronization mechanism. See pka_flags_t above.
/// @param ring_cnt          Number of HW rings requested.
/// @param queue_cnt         Number of queues that will be assigned to the
///                          worker threads. It might also refer to the number
///                          of threads allowed to request PK operation.
/// @param cmd_queue_size    Size of a software request queue (in bytes).
/// @param result_queue_size Size of a software reply queue (in bytes).
///
/// @return                  A valid PK instance on success,
///                          PKA_INSTANCE_INVALID on failure.
pka_instance_t pka_init_global(const char* name,
                               uint8_t     flags,
                               uint32_t    ring_cnt,
                               uint32_t    queue_cnt,
                               uint32_t    cmd_queue_size,
                               uint32_t    result_queue_size);

/// Global PKA termination. This function MUST be the last PKA call made when
/// terminating a PKA application in a controlled way.
///
/// @param instance     A PK instance handle.
void pka_term_global(pka_instance_t instance);

/// Return the number of rings allocated to a PK instance.
///
/// @param instance     A PK instance handle.
///
/// @return             The number of allocated HW rings.
uint32_t pka_get_rings_count(pka_instance_t instance);

/// Return the bitmask of HW rings allocated to a PK instance.
///
/// @param instance     A PK instance handle.
///
/// @return             The bitmask(array of uint8_t) of allocated HW rings.
uint8_t* pka_get_rings_bitmask(pka_instance_t instance);

/// Thread local PKA initialization. All threads must call this function before
/// calling any other PKA API functions. The instance parameter specifies which
/// PKA instance the thread joins. A thread may be part of at most one PKA
/// instance at any given time.
///
/// @param instance     A PK instance handle.
///
/// @return             A valid PK handle on success,
///                     PKA_HANDLE_INVALID on failure.
pka_handle_t pka_init_local(pka_instance_t instance);

/// Thread local PKA termination. This function is the last PKA call made by
/// a given thread, other than the final call to pka_term_global().
///
/// @param handle       An initialized PKA handle.
void pka_term_local(pka_handle_t handle);

/// Return Rings byte order, whether BE(1) or LE(0). This function returns
/// PKA_RING_BYTE_ORDER if the PKA handle is invalid.
///
/// @param handle       An initialized PKA handle.
uint8_t pka_get_rings_byte_order(pka_handle_t handle);

/// MAX_OPERAND_CNT defines the largest number of big integer operands used by
/// any operation in this API.
#define MAX_OPERAND_CNT     11

/// MAX_RESULT_CNT defines the largest number of big integers returned by any
/// operation in this API.  In particular, a given asynchronous request
/// function always returns the same number of result big integers, but
/// depending on the operation this can be either 0, 1 or 2 big integers.
#define MAX_RESULT_CNT      2

/// The MAX_BYTE_LEN constant defines the byte length of the largest operand
/// that the current PKA hardware supports.
#define MAX_BYTE_LEN        520 // 130 * 4 bytes

/// The OTHER_MAX_BYTE_LEN constant defines the byte length of the largest
/// operand supported for certain operations like  "modular exponentiation
/// using the chinese remainder theorem".
#define OTHER_MAX_BYTE_LEN  264 //  66 * 4 bytes

/// Defines the largest number of big integers returned by any operation
/// in this  API.  In particular,  a given asynchronous request function
/// always returns the same number of result big integers, but depending
/// on the operation this can be either 0, 1 or 2 big integers.
#define MAX_RESULT_CNT   2

/// The pka_operand_t is the record type used to represent big integer numbers.
/// Despite its name, it is used to represent all big integers including the
/// results.
typedef struct  // 16 bytes long
{
    uint16_t buf_len;       ///< Size of the buffer holding the big integer.
    uint16_t actual_len;    ///< Actual minimum # of bytes used by the operand.
    uint8_t  is_encrypted;  ///< Reserved for future use.
    uint8_t  big_endian;    ///< Indicates byte order of the big integer operand
    uint8_t  internal_use;  ///< Internal use.  Must be set to 0 by users.
    uint8_t  pad;           ///< Reserved for future use.
    uint8_t* buf_ptr;       ///< Pointer to the buffer holding the big integer.
} pka_operand_t;

/// PKA Command Code Values.
typedef enum
{
    /// Add (basic arithmetic).
    CC_ADD                   = 0x01,
    /// Subtract (basic arithmetic).
    CC_SUBTRACT              = 0x02,
    /// Add/Subtract combination (basic arithmetic).
    CC_ADD_SUBTRACT          = 0x03,
    /// Multiply/Square (basic arithmetic).
    /// @note The Square operation is a Multiply where the inputs 'A' and 'B'
    /// point to the same.
    CC_MULTIPLY              = 0x04,
    /// Divide (basic arithmetic).
    CC_DIVIDE                = 0x05,
    /// Modulo (basic arithmetic).
    CC_MODULO                = 0x06,
    /// Shift left (basic arithmetic).
    CC_SHIFT_LEFT            = 0x07,
    /// Shift right (basic arithmetic).
    CC_SHIFT_RIGHT           = 0x08,
    /// Compare (basic arithmetic).
    CC_COMPARE               = 0x09,
    /// Copy (basic arithmetic).
    CC_COPY                  = 0xA0,
    /// Modular Exponentiation without CRT (complex arithmetic).
    CC_MODULAR_EXP           = 0x10,
    /// Modular Exponentiation with CRT (complex arithmetic).
    CC_MOD_EXP_CRT           = 0x11,
    /// Modular Inversion (complex arithmetic).
    CC_MODULAR_INVERT        = 0x12,
    /// ECC point multiplication on Montgomery Curves (complex arithmetic)
    CC_MONT_ECDH_MULTIPLY    = 0x13,
    /// ECC point addition/doubling (complex arithmetic).
    CC_ECC_PT_ADD            = 0x14,
    /// ECC point multiplication (complex arithmetic).
    CC_ECC_PT_MULTIPLY       = 0x15,
    /// ECDSA signature generation (high-level PKA operations).
    CC_ECDSA_GENERATE        = 0x20,
    /// ECDSA signature verification with r'' write-back (high-level PKA
    /// operations).
    CC_ECDSA_VERIFY          = 0x21,
    /// DSA signature generation (high-level PKA operations).
    CC_DSA_GENERATE          = 0x22,
    /// DSA signature verification with r'' write-back (high-level PKA
    /// operations).
    CC_DSA_VERIFY            = 0x23,
    /// ECDSA signature verification without r'' write-back (high-level
    /// PKA operations).
    CC_ECDSA_VERIFY_NO_WRITE = 0x25,
    /// DSA signature verification without r'' write-back (high-level PKA
    /// operations).
    CC_DSA_VERIFY_NO_WRITE   = 0x27,
} pka_opcode_t;

/// PKA Result Code Values.
typedef enum
{
    /// No error – Normal command completion.
    RC_NO_ERROR              = 0x00,
    /// Modulus was even.
    RC_EVEN_MODULUS          = 0x81,
    /// Exponent was 0 (for a modular exponentiation).
    RC_ZERO_EXPONENT         = 0x82,
    /// Modulus was too short (less than 9 significant bits).
    RC_SHORT_MODULUS         = 0x83,
    /// Exponent was 1 (for a modular exponentiation).
    RC_ONE_EXPONENT          = 0x84,
    /// Odd powers not in range 1 … 16.
    RC_BAD_ODD_POWERS        = 0x85,
    /// Result point of ECC operation is 'at infinity' -not a real error.
    RC_RESULT_IS_PAI         = 0x86,   // Not a real error?
    /// Unknown command
    RC_UNKNOWN_COMMAND       = 0x87,
    /// Intermediate result of ECC operation is 'at infinity' -not a real error.
    RC_INTERMEDIATE_PAI      = 0x89,   // PAI = Point At Infinity
    /// Modular inverse does not exist.
    RC_NO_MODULAR_INVERSE    = 0x8B,
    /// Result of ECC operation is not on the curve.
    RC_ECC_RESULT_OFF_CURVE  = 0x8D,
    /// Operand length error.
    RC_OPERAND_LENGTH_ERR    = 0x8F,
    /// Host used undefined trigger.
    RC_UNDEFINED_TRIGGER     = 0x90,
    /// Invalid argument.
    RC_INVALID_ARGUMENT      = 0x91,
    /// Operand value error.
    RC_OPERAND_VALUE_ERR     = 0xA0,
    /// Calculated value error.
    RC_CALCULATION_ERR       = 0xA1,
    /// Address is invalid.
    RC_INVALID_ADDRESS       = 0xA2,
    /// Illegal encrypted parameter use.
    RC_ENCRYPTED_PARAM_ERR   = 0xA3,
    /// Farm memory too small for operation.
    RC_TOO_LITTLE_MEMORY     = 0xC0,
    /// Memory deadlock error.
    RC_MEMORY_DEADLOCK       = 0xC1
} pka_result_code_t;

/// PKA Compare Result Code Values.
typedef enum
{
    /// Both operands are equal ('A' = 'B').
    RC_COMPARE_EQUAL      = 0x1,
    /// Left operand is smaller than right operand ('A' < 'B').
    RC_LEFT_IS_SMALLER    = 0x2,
    /// Right operand is smaller than left operand ('A' > 'B').
    RC_RIGHT_IS_SMALLER   = 0x4
} pka_cmp_code_t;

/// The pka_results_t record type is used to package up the entire set of
/// output vectors (of which there can be 0, 1 or 2) as well as other result
/// values like the compare_result (only used for compare op), the result_cnt
/// and the overall status.
typedef struct  // 50 bytes long
{
    void*             user_data;       ///< Opaque data pointer.
    pka_opcode_t      opcode;          ///< Opcode of the associated request.
    uint8_t           result_cnt;      ///< Result cnt must be 0, 1 or 2.
    pka_result_code_t status;          ///< Same as result_code.
    pka_cmp_code_t    compare_result;  ///< Result of a comparison.
    pka_operand_t     results[MAX_RESULT_CNT]; ///< Actual result operand descs.
} pka_results_t;

/// Return results pending in queue.
///
/// @param handle       An initialized PKA handle.
/// @param results      The results structure to store the PK results.
///
/// @return             0 on success, and 1 on failure.
int pka_get_result(pka_handle_t handle, pka_results_t* results);

/// Return if there is pending results in queue.
///
/// @param handle       An initialized PKA handle.
///
/// @return             Whether there is an available result.
bool pka_has_avail_result(pka_handle_t handle);

/// Return the number of outstanding command requests.
///
/// @param handle       An initialized PKA handle.
///
/// @return             The number of outstanding requests.
uint32_t pka_request_count(pka_handle_t handle);

/// Big Integer Add function.
///
/// This function computes "value + addend".
///
/// @param handle       An initialized PKA handle to use for this command.
/// @param user_data    Opaque user pointer that is returned with the result.
/// @param value        One of the two big integers whose sum is requested.
/// @param addend       The other of the two big integers whose sum is
///                     requested.
///
/// @return             0 on success, a negative error code on failure.
int pka_add(pka_handle_t   handle,
            void*          user_data,
            pka_operand_t* value,
            pka_operand_t* addend);

/// Big Integer Subtraction function.
///
/// This functions computes "value - subtrahend".
///
/// @note This function must yield a positive result and so the value
/// MUST be >= than the subtrahend.
///
/// @param handle       An initialized PKA handle to use for this command.
/// @param user_data    Opaque user pointer that is returned with the result.
/// @param value        The LARGEST of the two big integers whose difference
///                     is requested.
/// @param subtrahend   The SMALLEST of the two big integers whose difference
///                     is requested.
///
/// @return             0 on success, a negative error code on failure.
int pka_subtract(pka_handle_t   handle,
                 void*          user_data,
                 pka_operand_t* value,
                 pka_operand_t* subtrahend);

/// Big Integer Add/Substract combination.
///
/// This functions computes "value + addend - subtrahend".
///
/// @note The result of this function must be positive, so the value plus the
/// addend MUST be >= than the subtrahend.
///
/// @param handle       An initialized PKA handle to use for this command.
/// @param user_data    Opaque user pointer that is returned with the result.
/// @param value        The LARGEST of the three big integers whose addition
///                     and subtraction are requested.
/// @param addend       The other of the three big integers whose sum is
///                     requested.
/// @param subtrahend   The SMALLEST of the three big integers whose difference
///                     is requested.
///
/// @return             0 on success, a negative error code on failure.
int pka_add_subtract(pka_handle_t   handle,
                     void*          user_data,
                     pka_operand_t* value,
                     pka_operand_t* addend,
                     pka_operand_t* subtrahend);

/// Big Integer Multiply function.
///
/// This function computes "value * multiplier".
///
/// @note To compute a square operation, the inputs, value and multiplier must
/// to the same data.
///
/// @param handle       An initialized PKA handle to use for this command.
/// @param user_data    Opaque user pointer that is returned with the result.
/// @param value        One of the two big integers whose product is requested.
/// @param multiplier   The other of the two big integers whose product is
///                     requested.
///
/// @return             0 on success, a negative error code on failure.
int pka_multiply(pka_handle_t   handle,
                 void*          user_data,
                 pka_operand_t* value,
                 pka_operand_t* multiplier);

/// Big Integer Divide function.
///
/// This function computes BOTH "value / divisor", and "value mod divisor".
///
/// @note the final results returned will always have result_cnt = 2.
///
/// @param handle       An initialized PKA handle to use for this command.
/// @param user_data    Opaque user pointer that is returned with the result.
/// @param value        The big integer whose quotient and remainder is desired.
/// @param divisor      The big integer divisor.  Must not be zero.
///
/// @return             0 on success, a negative error code on failure.
int pka_divide(pka_handle_t   handle,
               void*          user_data,
               pka_operand_t* value,
               pka_operand_t* divisor);

/// Big Integer Modulo function.
///
/// The function implements the modulo function on big integers, i.e. computes
/// "value mod modulus".
///
/// @param handle       An initialized PKA handle to use for this command.
/// @param user_data    Opaque user pointer that is returned with the result.
/// @param value        The big integer whose mod is desired.
/// @param modulus      The big integer modulus.  Must be odd and be larger
///                     than 2^32 (5 bytes).
///
/// @return             0 on success, a negative error code on failure.
int pka_modulo(pka_handle_t   handle,
               void*          user_data,
               pka_operand_t* value,
               pka_operand_t* modulus);

/// Big Integer Shift Left function.
///
/// Computes "value << shift_cnt".
///
/// @param handle       An initialized PKA handle to use for this command.
/// @param user_data    Opaque user pointer that is returned with the result.
/// @param value        The big integer that is to be shifted left.
/// @param shift_cnt    The amount that the big integer 'value' is to be
///                     shifted by (range 0...31 bits).
///
/// @return             0 on success, a negative error code on failure.
int pka_shift_left(pka_handle_t   handle,
                   void*          user_data,
                   pka_operand_t* value,
                   uint32_t       shift_cnt);

/// Big Integer Shift Right function.
///
/// Computes "value >> shift_cnt".
///
/// @param handle       An initialized PKA handle to use for this command.
/// @param user_data    Opaque user pointer that is returned with the result.
/// @param value        The big integer that is to be shifted right.
/// @param shift_cnt    The amount that the big integer 'value' is to be
///                     shifted by (range 0...31 bits).
///
/// @return             0 on success, a negative error code on failure.
int pka_shift_right(pka_handle_t   handle,
                    void*          user_data,
                    pka_operand_t* value,
                    uint32_t       shift_cnt);

/// Traditional Diffie-Hellman(DH).
///
/// This function provide Diffie-Hellman algorithm implementation,
/// which is essentially nothing but Modular Exponentiation without CRT.
///
/// @param handle      An initialized PKA handle to use for this command.
/// @param user_data   Opaque user pointer that is returned with the result.
/// @param private_key The big integer exponent, which is always the local private
///                    key in case of DH.
/// @param modulus     The big integer modulus. Must be an odd prime (i.e. the
///                    LSB must be ONE). Must be larger than 2^32 (5 bytes).
/// @param value       The big integer whose modular power is requested. Must
///                    be inferior to the 'modulus'.
///
/// @return            0 on success, a negative error code on failure.
int pka_dh(pka_handle_t   handle,
           void*          user_data,
           pka_operand_t* private_key,
           pka_operand_t* modulus,
           pka_operand_t* value);

/// Modular Exponentiation function without Chinese Remainder Theorem (CRT).
///
/// This function implements the mathematical expression
/// "value^exponent mod modulus".
///
/// @param handle     An initialized PKA handle to use for this command.
/// @param user_data  Opaque user pointer that is returned with the result.
/// @param exponent   The big integer exponent.
/// @param modulus    The big integer modulus. Must be an odd prime (i.e. the
///                   LSB must be ONE). Must be larger than 2^32 (5 bytes).
/// @param value      The big integer whose modular power is requested. Must
///                   be inferior to the 'modulus'.
///
/// @return           0 on success, a negative error code on failure.
int pka_modular_exp(pka_handle_t   handle,
                    void*          user_data,
                    pka_operand_t* exponent,
                    pka_operand_t* modulus,
                    pka_operand_t* value);

/// Modular Exponentiation with Chinese Remainder Theorem (CRT).
///
/// The function makes use of the Chinese Remainder Theorem in order
/// to implement a modular exponentiation using two smaller (half-sized)
/// modular exponentiation, plus a big integer subtraction, multiplication
/// and addition.
///
/// @param handle     An initialized PKA handle to use for this command.
/// @param user_data  Opaque user pointer that is returned with the result.
/// @param value      A big integer representing the message to be decrypted.
/// @param p          A big integer prime number.
/// @param q          A big integer prime number.
/// @param d_p        The big integer value 'd mod (p-1)' where d is the
///                   private key.
/// @param d_q        The big integer value 'd mod (q-1)' where d is the
///                   private key.
/// @param qinv       The big integer value 'q^-1 mod p' - i.e. the modular
///                   inverse of q, using modulus p.
///
/// @return           0 on success, a negative error code on failure.
int pka_modular_exp_crt(pka_handle_t   handle,
                        void*          user_data,
                        pka_operand_t* value,
                        pka_operand_t* p,
                        pka_operand_t* q,
                        pka_operand_t* d_p,
                        pka_operand_t* d_q,
                        pka_operand_t* qinv);

/// RSA - Modular Exponentiation function.
///
/// This function implements the mathematical
/// expression "value^exponent mod modulus".
///
/// It is the basis for both RSA encryption and decryption. For example RSA
/// is defined by:
///
/// @code
/// // Pick two large distinct random prime numbers p and q.
/// // Pick a random integer e such that 1 < e < (p-1)*(q-1) AND
/// // gcd(e, (p-1)*(q-1)) = 1.
/// n = p * q;
/// d = (e^-1) mod ((p-1)*(q-1));
/// // I.e. find d such that '(e * d) mod ((p-1)*(q-1)) = 1'.
/// // Then publish (e, n) as the public key.  (d, n) is the private key.
/// @endcode
///
/// where the encryption and decryption operations are defined as:
///
/// @code
/// ciphertext = (plaintext^e)  mod n;  // encryption
/// plaintext  = (ciphertext^e) mod n;  // decryption
/// @endcode
///
///
/// @param handle     An initialized PKA handle to use for this command.
/// @param user_data  Opaque user pointer that is returned with the result.
/// @param exponent   The big integer exponent.  For RSA, this exponent could
///                   be either the e or d part of the public or private key.
/// @param modulus    The big integer modulus.  Must be odd. Must be the product
///                   of two big prime numbers.
/// @param value      The big integer whose modular power is requested.
///
/// @return           0 on success, a negative error code on failure.
int pka_rsa(pka_handle_t   handle,
            void*          user_data,
            pka_operand_t* exponent,
            pka_operand_t* modulus,
            pka_operand_t* value);

/// Optimized Modular Exponentiation function for RSA.
///
/// The function makes use of the Chinese Remainder Theorem in order to
/// implement a full RSA modular exponentiation using two smaller (half-sized)
/// modular exponentiation, plus a big integer subtraction, multiplication and
/// addition.
/// Since the performance of the modular exponentiation is very roughly cubic
/// in the size of the operands, each smaller modular exponentation runs roughly
/// 4 times faster (but there are now twice as many of them), and in total can
/// give a 3x speed up.
///
/// @note that this function is only useful to the side that has both the
/// public AND private RSA keys, since it requires as input some of the
/// intermediate values used when creating a RSA public-private key pair.
///
/// In addition, it is assumed that the following values have been precomputed:
///
/// @code
/// d_p  = d mod (p-1);
/// d_q  = d mod (q-1);
/// qinv = q^-1 mod p;   // I.e. Find qinv such that '(qinv * q) mod p = 1'
/// @endcode
///
/// Specifically this function implements the mathematical expression
/// "c^d mod p*q" by doing the following computation:
///
/// @code
/// m1 = (c^d_p) mod p;
/// m2 = (c^d_q) mod q;
/// h  = (q_inv * (m1 - m2)) mod p;
/// return m2 + (h * q);
/// @endcode
///
/// @param handle     An initialized PKA handle to use for this command.
/// @param user_data  Opaque user pointer that is returned with the result.
/// @param p          A big integer prime number.  RSA modulus = 'p*q', where
///                   p is larger than q.
/// @param q          A big integer prime number.  RSA modulus = 'p*q', where
///                   q is smaller than p.
/// @param c          A big integer representing the message to be decrypted.
/// @param d_p        The big integer value 'd mod (p-1)' where d is the private
///                   key.
/// @param d_q        The big integer value 'd mod (q-1)' where d is the private
///                   key.
/// @param qinv       The big integer value 'q^-1 mod p' - i.e. the modular
///                   inverse of q, using modulus p.
///
/// @return           0 on success, a negative error code on failure.
int pka_rsa_crt(pka_handle_t   handle,
                void*          user_data,
                pka_operand_t* p,
                pka_operand_t* q,
                pka_operand_t* c,
                pka_operand_t* d_p,
                pka_operand_t* d_q,
                pka_operand_t* qinv);

/// Modular Inversion Function.
///
/// Implements "value^(-1) mod modulus", i.e. finds a big integer such that
/// when it is multiplied by 'value mod modulus' results in the value 1.
/// If the modulus is a prime, then such an inverse value must exist (as long
/// as value != 0) and must be unique.
///
/// @param handle     An initialized PKA handle to use for this command.
/// @param user_data  Opaque user pointer that is returned with the result.
/// @param value      The big integer whose modular inverse is requested.
/// @param modulus    The big integer modulus.  Must be odd (i.e. the least
///                   significant bit must be ONE). May not have value 1.
///
/// @return           0 on success, a negative error code on failure.
int pka_modular_inverse(pka_handle_t   handle,
                        void*          user_data,
                        pka_operand_t* value,
                        pka_operand_t* modulus);


/// The ecc_point_t record type is used to represent a point on an elliptic
/// curve defined over a finite field.
typedef struct
{
    pka_operand_t x;  ///< big integer x coordinate of a point on a EC curve
    pka_operand_t y;  ///< big integer y coordinate of a point on a EC curve
} ecc_point_t;

/// The ecc_curve_t record type is used to represent an elliptic curve.
///
/// It holds all of the parameters defining an elliptic curve over a large
/// prime number finite field. The prime used as the modulus is called 'p'.
/// The parameters of the general curve are called 'a' and 'b'. The formula
/// defining the curve is:
/// @code
/// // The curve is defined as all possible (x,y) values such that
/// // x,y are integers in the range 0..p-1 (where p must be an odd prime).
/// // and the x,y values also satisfy:
/// y^2 mod p = (x^3 + a*x + b) mod p
/// @endcode
typedef struct
{
    pka_operand_t p;  ///< large integer prime defining the finite field
    pka_operand_t a;  ///< coefficient of x in the defining equation
    pka_operand_t b;  ///< constant coefficient in defining equation
} ecc_curve_t;

typedef enum
{
    PKA_CURVE_NULL = 0,
    PKA_CURVE_25519,
    PKA_CURVE_448
}pka_mont_curve_t;

/// The ecc_mont_curve_t record type is used to represent an elliptic
/// curve in Montgomery form.
///
/// It holds all of the parameters defining an elliptic curve over a large
/// prime number finite field. The prime used as the modulus is called 'p'.
/// The parameter of the general curve is called 'A'. The formula defining
/// the curve is:
/// @code
/// // The curve is defined as all possible (u,v) values such that
/// // u,v are integers in the range 0..p-1 (where p must be an odd prime).
/// // and the u,v values also satisfy:
///   v^2 mod p = (u^3 + A*u^2 + u) mod p
///
/// Note that a more general equation for Montgomery curves is
///   B*v*2 mod p = (u^3 + A*u^2 + u) mod p
/// but for our purposes B will always be 1.
/// @endcode
typedef struct
{
    pka_operand_t    p;    ///< large integer prime defining the finite field
    pka_operand_t    A;    ///< coefficient of u^2 in the defining equation
    pka_mont_curve_t type; ///< type to depict curve.
} ecc_mont_curve_t;

/// Montgomery Elliptic Curve Cryptography (ECC) point multiplication.
///
/// Implements modular elliptic curve multiplication for points on a Montgomery
/// curve like Curve25519 and Curve448. In particular, given a point on a
/// Montgomery elliptic curve and a 'scalar' m, multiply the point by the
/// scalar giving a new result point. Scalar multiplication is defined to be
/// equivalent to repeated elliptic curve addition.  Note that this specific
/// function is ONLY given the x-coordinate of the point, and ONLY returns the
/// x-coordinate of the result point!
///
/// @note: The curve parameter passed in currently MUST be one of curve25519 or
///        curve448!
/// @note: The multiplier is subsequently modified according to RFC7748.
///        For curve25519 the two MSB bits are set to "0b01" and the three LSB
///        bits are cleared. For curve448 the MSB bit is set and the two LSB
///        bits are cleared.  This is done internally and does not change the
///        value the user passed in.
/// @note Elliptic curves using a modulus of 2^m are NOT supported.
///
/// @param handle     An initialized PKA handle to use for this command.
/// @param user_data  Opaque user pointer that is returned with the result.
/// @param curve      A pointer to an ecc_mont_curve_t object, which
///                   supplies the curve parameters A and p where p must be
///                   prime.
/// @param point_x    A pointer to the x coordinate of an ecc_point_t object.
/// @param multiplier A big integer indicating the number of times that point_x
///                   should be added to itself.
///
/// @return           0 on success, a negative error code on failure.
int pka_mont_ecdh_mult(pka_handle_t      handle,
                       void*             user_data,
                       ecc_mont_curve_t* curve,
                       pka_operand_t*    point_x,
                       pka_operand_t*    multiplier);

/// Elliptic Curve Cryptography (ECC) point addition.
///
/// Implements modular elliptic curve addition. In particular, given two points
/// on an elliptic curve defined using a finite field defined by a large prime
/// number, determine their sum.
///
/// @note Elliptic curves using a modulus of 2^m (a.k.a binary fields) are
/// NOT supported.
///
/// The elliptic curve is assumed to be defined by the set
/// of all points '(x,y)' such that x and y are integers in the range 0..p-1
/// and such that they satisfy the equation:
///
/// @code
/// y^2 = x^3 + a*x + b mod p;
/// // where x and y are in the range 0..p-1 and p is a big prime number.
/// @endcode
///
/// The elliptic curve is then defined by the three big integer parameters,
/// a, b and p.  These three parameters are not completely independent.
/// In particular, the discriminant defined below must be non-zero.
///
/// @code
/// // Definition of the discriminant.  Must be non-zero.
/// discriminant = -16 * ((4 * a^3) + (27 * b^2));
/// @endcode
///
/// The definition of elliptic curve point addition leads to the following
/// equations for computing the result point.  Notice that the result from
/// this operation has a result_cnt of 2 because it returns two large integers,
/// namely the x and y coordinate of the result point.
///
/// @code
/// if pointA.x == pointB.x then
///     s        = (3 * pointA.x^2 + curve.a) / (2 * pointA.y) mod curve.p;
///     result.x = s * s - 2 * pointA.x                        mod curve.p;
/// else
///     s        = ((pointA.y - pointB.y) / (pointA.x - pointB.x))  mod curve.p;
///     result.x = s * s - (pointA.x + pointB.x)                    mod curve.p;
/// endif
/// result.y = pointA.y + s * (result.x - pointA.x) mod curve.p;
/// @endcode
///
///
/// @param handle     An initialized PKA handle to use for this command.
/// @param user_data  Opaque user pointer that is returned with the result.
/// @param curve      A pointer to an ecc_curve_t object, which supplies the
///                   curve parameters a, b, and p where p must be prime.
/// @param pointA     A pointer to an ecc_point_t object, which supplies the
///                   x and y coordinates (as big integer) for the first point.
/// @param pointB     A pointer to an ecc_point_t object, which supplies the
///                   x and y coordinates (as big integer) for the second point.
///
/// @return           0 on success, a negative error code on failure.
int pka_ecc_pt_add(pka_handle_t   handle,
                   void*          user_data,
                   ecc_curve_t*   curve,
                   ecc_point_t*   pointA,
                   ecc_point_t*   pointB);

/// Elliptic Curve Cryptography (ECC) point multiplication.
///
/// Implements modular elliptic curve multiplication. In particular, given
/// a point on an elliptic curve and a 'scalar' m, multiply the point by the
/// scalar giving a new result point. Scalar multiplication is defined to be
/// equivalent to repeated elliptic curve addition (see pka_ecc_pt_add above
/// for details of elliptic curve addition).
///
/// @note Elliptic curves using a modulus of 2^m are NOT supported.
///
/// @param handle     An initialized PKA handle to use for this command.
/// @param user_data  Opaque user pointer that is returned with the result.
/// @param curve      A pointer to an ecc_curve_t object, which supplies the
///                   curve parameters a, b, and p where p must be prime.
/// @param pointA     A pointer to an ecc_point_t object, which supplies the
///                   x and y coordinates (as big integer) for the first point.
/// @param multiplier A big integer indicating the number of times that pointA
///                   should be added to itself.
///
/// @return           0 on success, a negative error code on failure.
int pka_ecc_pt_mult(pka_handle_t   handle,
                    void*          user_data,
                    ecc_curve_t*   curve,
                    ecc_point_t*   pointA,
                    pka_operand_t* multiplier);

/// Elliptic Curve Diffie-Hellman (ECDH) on Montgomery curves.
///
/// ECDH is based on ECC point multiplication and essentially uses the
/// API of the same.
///
/// @note: The curve parameter passed in currently MUST be one of curve25519 or
///        curve448!
/// @note Elliptic curves using a modulus of 2^m are NOT supported.
///
/// @param handle      An initialized PKA handle to use for this command.
/// @param user_data   Opaque user pointer that is returned with the result.
/// @param curve       A pointer to an ecc_mont_curve_t object, which supplies
///                    the curve parameters A and p where p must be prime.
///                    MUST be a pointer to either the curve25519 or the
///                    curve448 object.
/// @param point_x     The x coordinate of a point on a Montgomery ECC curve.
///                    This is either a base point for the curve or a remote
///                    public key.
/// @param private_key big integer indicating the number of times that point
///                    should be added to itself. In case of ECDH this the local
///                    private key.
///
/// @return            0 on success, a negative error code on failure.
int pka_mont_ecdh(pka_handle_t      handle,
                  void*             user_data,
                  ecc_mont_curve_t* curve,
                  pka_operand_t*    point_x,
                  pka_operand_t*    private_key);

/// Elliptic Curve Diffie-Hellman (ECDH).
///
/// ECDH is based on ECC point multiplication and essentially uses the
/// API of the same. 
///
/// @note Elliptic curves using a modulus of 2^m are NOT supported.
///
/// @param handle      An initialized PKA handle to use for this command.
/// @param user_data   Opaque user pointer that is returned with the result.
/// @param curve       A pointer to an ecc_curve_t object, which supplies the
///                    curve parameters a, b, and p where p must be prime.
/// @param point       A pointer to an ecc_point_t object, which supplies the
///                    x and y coordinates (as big integer) for the first point.
///                    This is either a base point for the curve or remote public key. 
/// @param private_key big integer indicating the number of times that point
///                    should be added to itself. In case of ECDH this the local
///                    private key.
///
/// @return            0 on success, a negative error code on failure.
int pka_ecdh(pka_handle_t   handle,
             void*          user_data,
             ecc_curve_t*   curve,
             ecc_point_t*   point,
             pka_operand_t* private_key);

/// Elliptic Curve DSA (ECSDA) Signature Generation.
///
/// This function implements the Elliptic Curve DSA Signature Generation
/// algorithm. Specifically, it implements the following equations:
///
/// @code
/// k_inv = k^-1 mod base_pt_order; // Modular inverse of k.
/// KG    = k * base_pt;            // This is an ECC point multiplication.
/// r     = KG.x mod base_pt_order;
/// s     = (k_inv * (hash + private_key * r) mod base_pt_order;
/// @endcode
///
/// @note The final result of this operation is a dsa_signature_t object
/// containing two big integers (hence the result_cnt will be 2) called r
/// and s by the standard.
///
/// @param handle        An initialized PKA handle to use for this command.
/// @param user_data     Opaque user pointer that is returned with the result.
/// @param curve         A pointer to an ecc_curve_t object, which supplies
///                      the curve parameters a, b, and p where p must be prime.
/// @param base_pt       A pointer to an ecc_point_t object, which supplies
///                      the x and y coordinates (as big integer) for the base
///                      point.
/// @param base_pt_order The big integer number such that when base_pt is
///                      multiplied by this number (i.e. using pka_ecc_multiply
///                      above) the result is 1.
/// @param private_key   The big integer used as the private key.  Refered to
///                      as alpha in the FIPS-186 spec.
/// @param hash          The hash (using one of SHA hash algorithms) of the
///                      message. Also called the message digest.
/// @param k             A big integer used an additional random number secret
///                      value in the algorithm,
///
/// @return              0 on success, a negative error code on failure.
int pka_ecdsa_signature_generate(pka_handle_t   handle,
                                 void*          user_data,
                                 ecc_curve_t*   curve,
                                 ecc_point_t*   base_pt,
                                 pka_operand_t* base_pt_order,
                                 pka_operand_t* private_key,
                                 pka_operand_t* hash,
                                 pka_operand_t* k);

/// The dsa_signature_t record type is used to package up the two large
/// integer values (called 'r' and 's' in the DSA standard) into a  DSA
/// signature.
typedef struct
{
    pka_operand_t r;  ///< big integer value called 'r' in the standard
    pka_operand_t s;  ///< big integer value called 's' in the standard
} dsa_signature_t;

/// Elliptic Curve DSA (ECSDA) Signature Verification
///
/// This function implements the Elliptic Curve DSA Signature Verification
/// algorithm. Specifically, it implements the following equations:
///
/// @code
/// // Note that public_key = g^private_key mod p
/// // Check that 0 < r < base_pt_order and 0 < s < base_pt_order
/// s_inv  = s^(-1)                mod base_pt_order;
/// u1     = (hash        * s_inv) mod base_pt_order;
/// u2     = (signature.r * s_inv) mod base_pt_order;
/// sum_pt = (u1 * base_pt) + (u2 * public_key);   // ECC adds and mults.
/// // Check that signature.r == sum_pt.x mod base_pt_order;
/// @endcode
///
/// @note The final result of this operation is a boolean - result_code -
/// and so the result_cnt will be 0.
///
/// @param handle         An initialized PKA handle to use for this command.
/// @param user_data      Opaque user pointer that is returned with the result.
/// @param curve          A pointer to an ecc_curve_t object, which supplies
///                       the curve parameters a, b, and p where p must be
///                       prime.
/// @param base_pt        A pointer to an ecc_point_t object, which supplies
///                       the x and y coordinates (as big integer) for the base
///                       point.
/// @param base_pt_order  The big integer number such that when base_pt is
///                       multiplied by this number (i.e. using
///                       pka_process_ecc_pt_mult above)
/// @param public_key     A pointer to an ecc_point_t object, which represents
///                       the public key of this crypto system.
/// @param hash           The hash (using one of SHA hash algorithms) of the
///                       message. Also called the message digest.
/// @param rcvd_signature A pointer to a dsa_signature object containing
///                       two large integers, called r and s in the standard,
///                       representing a cryptographically secure digital
///                       signature.
/// @param no_write       if 0 process signature verification with write-back,
///                       else process signature verfication without write-back.
///
/// @return              0 on success, a negative error code on failure.
int pka_ecdsa_signature_verify(pka_handle_t     handle,
                               void*            user_data,
                               ecc_curve_t*     curve,
                               ecc_point_t*     base_pt,
                               pka_operand_t*   base_pt_order,
                               ecc_point_t*     public_key,
                               pka_operand_t*   hash,
                               dsa_signature_t* rcvd_signature,
                               uint8_t          no_write);

/// DSA - Signature Generation.
///
/// This function implements the original Digital Signature Generation
/// Algorithm. Specifically, it implements the following equations:
///
/// @code
/// k_inv       = k^-1        mod q;
/// signature.r = (g^k mod p) mod q;
/// signature.s = (k_inv * (hash + private_key * signature.r) mod q;
/// @endcode
///
/// @note The final result of this operation is a dsa_signature_t object
/// containing two big integers (hence the result_cnt will be 2) called r
/// and s by the standard.
///
/// @param handle      An initialized PKA handle to use for this command.
/// @param user_data   Opaque user pointer that is returned with the result.
/// @param p           A big prime number.
/// @param q           A big prime number that divides 'p-1'.
/// @param g           A big integer, also refered to as the generator.
/// @param private_key A big integer used as the private key.  Refered to as
///                    alpha in the FIPS-186 spec.
/// @param hash        The hash (using one of SHA hash algorithms) of the
///                    message. Also called the message digest.
/// @param k           A big integer used an additional random number secret
///                    value in the algorithm,
///
/// @return            0 on success, a negative error code on failure.
int pka_dsa_signature_generate(pka_handle_t   handle,
                               void*          user_data,
                               pka_operand_t* p,
                               pka_operand_t* q,
                               pka_operand_t* g,
                               pka_operand_t* private_key,
                               pka_operand_t* hash,
                               pka_operand_t* k);

/// DSA - Signature Verification.
///
/// This function implements the original Digital Signature Verification
/// Algorithm. Specifically it implements the following equations:
///
/// @code
/// // Note that public_key = g^private_key mod p
/// // Check that 0 < r < q and 0 < s < q
/// s_inv  = signature.s^(-1) mod q;
/// u1     = (hash        * s_inv) mod q;
/// u2     = (signature.r * s_inv) mod q;
/// v      = (((g^u1) * (public_key^u2)) mod p) mod q;
/// // Check that v == signtaure.r
/// @endcode
///
/// @note The final result of this operation is a boolean - result_code -
/// and so the result_cnt will be 0.
///
/// @param handle         An initialized PKA handle to use for this command.
/// @param user_data      Opaque user pointer that is returned with the result.
/// @param p              A big prime number.
/// @param q              A big prime number that divides 'p-1'.
/// @param g              A big integer, also refered to as the generator.
/// @param public_key     A big integer used as the public key.  Refered to as
///                       alpha in the FIPS-186 spec.
/// @param hash           The hash (using one of SHA hash algorithms) of the
///                       message. Also called the message digest.
/// @param rcvd_signature A pointer to a dsa_signature object containing two
///                       large integers, called r and s in the standard,
///                       representing a cryptographically secure digital
///                       signature.
/// @param no_write       if 0 process signature verification with write-back,
///                       else process signature verfication without write-back.
///
/// @return               0 on success, a negative error code on failure.
int pka_dsa_signature_verify(pka_handle_t     handle,
                             void*            user_data,
                             pka_operand_t*   p,
                             pka_operand_t*   q,
                             pka_operand_t*   g,
                             pka_operand_t*   public_key,
                             pka_operand_t*   hash,
                             dsa_signature_t* rcvd_signature,
                             uint8_t          no_write);

/// RANDOM NUMBER GENERATION.
///
/// This function implements the random number generation.
/// Random number generation is carried out by generating random bytes.
///
/// @param handle         An initialized PKA handle to use for this command.
/// @param buf            Buffer to hold the randomly generated bytes.
/// @param buf_len        Length/Number of bytes to be filled in the buffer.
/// @return               Length/Number of random bytes generated.
int pka_get_rand_bytes(pka_handle_t  handle,
                       uint8_t      *buf,
                       uint32_t      buf_len);

#endif // __PKA_H__
