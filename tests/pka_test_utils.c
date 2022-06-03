
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "pka_ring.h"
#include "pka_test_utils.h"

static uint8_t RSA_VERIFY_EXPON[] = { 0x01, 0x00, 0x01 };

ecc_mont_curve_t curve25519;
ecc_mont_curve_t curve448;
 
// All of the following constants are in big-endian format.

//static char P256_p_string[] =
//    "ffffffff 00000001 00000000 00000000 00000000 ffffffff"
//    "ffffffff ffffffff";

static uint8_t P256_p_buf[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

//static char P256_a_string[] =
//    "ffffffff 00000001 00000000 00000000 00000000 ffffffff"
//    "ffffffff fffffffc";

static uint8_t P256_a_buf[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

//static char P256_b_string[] =
//    "5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6"
//    "3bce3c3e 27d2604b";

static uint8_t P256_b_buf[] =
{
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
    0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
};

//static char P256_xg_string[] =
//    "6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0"
//    "f4a13945 d898c296";

// Base_pt:
static uint8_t P256_xg_buf[] =
{
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
};

//static char P256_yg_string[] =
//    "4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece"
//    "cbb64068 37bf51f5";

static uint8_t P256_yg_buf[] =
{
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

//static char P256_n_string[] =
//    "ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84"
//    "f3b9cac2 fc632551";

// Base_pt_order:
static uint8_t P256_n_buf[] =
{
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

//static char P256_d_string[] =
//    "70a12c2d b16845ed 56ff68cf c21a472b 3f04d7d6 851bf634"
//    "9f2d7d5b 3452b38a";

static uint8_t P256_d_buf[] =
{
    0x70, 0xA1, 0x2C, 0x2D, 0xB1, 0x68, 0x45, 0xED,
    0x56, 0xFF, 0x68, 0xCF, 0xC2, 0x1A, 0x47, 0x2B,
    0x85, 0x1B, 0xF6, 0x34, 0x3F, 0x04, 0xD7, 0xD6,
    0x9F, 0x2D, 0xD5, 0x5B, 0x34, 0x52, 0xB3, 0x8A
};

//static char P256_xq_string[] =
//    "8101ece4 7464a6ea d70cf69a 6e2bd3d8 8691a326 2d22cba4"
//    "f7635eaf f26680a8";

static uint8_t P256_xq_buf[] =
{
    0x81, 0x01, 0xec, 0xe4, 0x74, 0x64, 0xa6, 0xea,
    0xd7, 0x0c, 0xf6, 0x9a, 0x6e, 0x2b, 0xd3, 0xd8,
    0x86, 0x91, 0xa3, 0x26, 0x2d, 0x22, 0xcb, 0xa4,
    0xf7, 0x63, 0x5e, 0xaf, 0xf2, 0x66, 0x80, 0xa8
};

//static char P256_yq_string[] =
//    "d8a12ba6 1d599235 f67d9cb4 d58f1783 d3ca43e7 8f0a5aba"
//    "a6240799 36c0c3a9";

static uint8_t P256_yq_buf[] =
{
    0xd8, 0xa1, 0x2b, 0xa6, 0x1d, 0x59, 0x92, 0x35,
    0xf6, 0x7d, 0x9c, 0xb4, 0xd5, 0x8f, 0x17, 0x83,
    0xd3, 0xca, 0x43, 0xe7, 0x8f, 0x0a, 0x5a, 0xba,
    0xa6, 0x24, 0x07, 0x99, 0x36, 0xc0, 0xc3, 0xa9
};

//static char P256_k_string[] =
//    "580ec00d 85643433 4cef3f71 ecaed496 5b12ae37 fa47055b"
//    "1965c7b1 34ee45d0";

static uint8_t P256_k_buf[] =
{
    0x58, 0x0e, 0xc0, 0x0d, 0x85, 0x64, 0x34, 0x33,
    0x4c, 0xef, 0x3f, 0x71, 0xec, 0xae, 0xd4, 0x96,
    0x5b, 0x12, 0xae, 0x37, 0xfa, 0x47, 0x05, 0x5b,
    0x19, 0x65, 0xc7, 0xb1, 0x34, 0xee, 0x45, 0xd0
};

//static char P256_kinv_string[] =
//    "6a664fa1 15356d33 f16331b5 4c4e7ce9 67965386 c7dcbf29"
//    "04604d0c 132b4a74";

static uint8_t P256_kinv_buf[] =
{
    0x6a, 0x66, 0x4f, 0xa1, 0x15, 0x35, 0x6d, 0x33,
    0xf1, 0x63, 0x31, 0xb5, 0x4c, 0x4e, 0x7c, 0xe9,
    0x67, 0x96, 0x53, 0x86, 0xc7, 0xdc, 0xbf, 0x29,
    0x04, 0x60, 0x4d, 0x0c, 0x13, 0x2b, 0x4a, 0x74
};

//static char P256_hash_string[] =
//    "7c3e883d dc8bd688 f96eac5e 9324222c 8f30f9d6 bb59e9c5"
//    "f020bd39 ba2b8377";

static uint8_t P256_hash_buf[] =
{
    0x7c, 0x3e, 0x88, 0x3d, 0xdc, 0x8b, 0xd6, 0x88,
    0xf9, 0x6e, 0xac, 0x5e, 0x93, 0x24, 0x22, 0x2c,
    0x8f, 0x30, 0xf9, 0xd6, 0xbb, 0x59, 0xe9, 0xc5,
    0xf0, 0x20, 0xbd, 0x39, 0xba, 0x2b, 0x83, 0x77
};

//static char P256_s_string[] =
//    "7d1ff961 980f961b daa3233b 6209f401 3317d3e3 f9e14935"
//    "92dbeaa1 af2bc367";

static uint8_t P256_s_buf[] =
{
    0x7d, 0x1f, 0xf9, 0x61, 0x98, 0x0f, 0x96, 0x1b,
    0xda, 0xa3, 0x23, 0x3b, 0x62, 0x09, 0xf4, 0x01,
    0x33, 0x17, 0xd3, 0xe3, 0xf9, 0xe1, 0x49, 0x35,
    0x92, 0xdb, 0xea, 0xa1, 0xaf, 0x2b, 0xc3, 0x67
};

//static char P384_p_string[] =
//    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff"
//    "ffffffff fffffffe ffffffff 00000000 00000000 ffffffff";

static uint8_t P384_p_buf[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

//static char P384_a_string[] =
//    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff"
//    "ffffffff fffffffe ffffffff 00000000 00000000 fffffffc";

static uint8_t P384_a_buf[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC
};

//static char P384_b_string[] =
//    "b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112"
//    "0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef";

static uint8_t P384_b_buf[] =
{
    0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4,
    0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
    0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
    0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
    0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D,
    0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF
};

//static char P384_xg_string[] =
//    "aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98"
//    "59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7";

static uint8_t P384_xg_buf[] =
{
    0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37,
    0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
    0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
    0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38,
    0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c,
    0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7
};

//static char P384_yg_string[] =
//    "3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c"
//    "e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f";

static uint8_t P384_yg_buf[] =
{
    0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f,
    0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
    0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
    0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
    0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d,
    0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f
};

//static char P384_n_string[] =
//    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff"
//    "c7634d81 f4372ddf 581a0db2 48b0a77a ecec196a ccc52973";

// Base_pt_order:
static uint8_t P384_n_buf[] =
{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
    0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73
};

//static char P384_d_string[] =
//    "c838b852 53ef8dc7 394fa580 8a518398 1c7deef5 a69ba8f4"
//    "f2117ffe a39cfcd9 0e95f6cb c854abac ab701d50 c1f3cf24";

static uint8_t P384_d_buf[] =
{
    0xc8, 0x38, 0xb8, 0x52, 0x53, 0xef, 0x8d, 0xc7,
    0x39, 0x4f, 0xa5, 0x80, 0x8a, 0x51, 0x83, 0x98,
    0x1c, 0x7d, 0xee, 0xf5, 0xa6, 0x9b, 0xa8, 0xf4,
    0xf2, 0x11, 0x7f, 0xfe, 0xa3, 0x9c, 0xfc, 0xd9,
    0x0e, 0x95, 0xf6, 0xcb, 0xc8, 0x54, 0xab, 0xac,
    0xab, 0x70, 0x1d, 0x50, 0xc1, 0xf3, 0xcf, 0x24
};

//static char P384_xq_string[] =
//    "1fbac8ee bd0cbf35 640b39ef e0808dd7 74debff2 0a2a329e"
//    "91713baf 7d7f3c3e 81546d88 3730bee7 e48678f8 57b02ca0";

static uint8_t P384_xq_buf[] =
{
    0x1f, 0xba, 0xc8, 0xee, 0xbd, 0x0c, 0xbf, 0x35,
    0x64, 0x0b, 0x39, 0xef, 0xe0, 0x80, 0x8d, 0xd7,
    0x74, 0xde, 0xbf, 0xf2, 0x0a, 0x2a, 0x32, 0x9e,
    0x91, 0x71, 0x3b, 0xaf, 0x7d, 0x7f, 0x3c, 0x3e,
    0x81, 0x54, 0x6d, 0x88, 0x37, 0x30, 0xbe, 0xe7,
    0xe4, 0x86, 0x78, 0xf8, 0x57, 0xb0, 0x2c, 0xa0
};

//static char P384_yq_string[] =
//    "eb213103 bd68ce34 3365a8a4 c3d4555f a385f533 0203bdd7"
//    "6ffad1f3 affb9575 1c132007 e1b24035 3cb0a4cf 1693bdf9";

static uint8_t P384_yq_buf[] =
{
    0xeb, 0x21, 0x31, 0x03, 0xbd, 0x68, 0xce, 0x34,
    0x33, 0x65, 0xa8, 0xa4, 0xc3, 0xd4, 0x55, 0x5f,
    0xa3, 0x85, 0xf5, 0x33, 0x02, 0x03, 0xbd, 0xd7,
    0x6f, 0xfa, 0xd1, 0xf3, 0xaf, 0xfb, 0x95, 0x75,
    0x1c, 0x13, 0x20, 0x07, 0xe1, 0xb2, 0x40, 0x35,
    0x3c, 0xb0, 0xa4, 0xcf, 0x16, 0x93, 0xbd, 0xf9
};

//static char P384_k_string[] =
//    "dc6b4403 6989a196 e39d1cda c000812f 4bdd8b2d b41bb33a"
//    "f5137258 5ebd1db6 3f0ce827 5aa1fd45 e2d2a735 f8749359";

static uint8_t P384_k_buf[] =
{
    0xdc, 0x6b, 0x44, 0x03, 0x69, 0x89, 0xa1, 0x96,
    0xe3, 0x9d, 0x1c, 0xda, 0xc0, 0x00, 0x81, 0x2f,
    0x4b, 0xdd, 0x8b, 0x2d, 0xb4, 0x1b, 0xb3, 0x3a,
    0xf5, 0x13, 0x72, 0x58, 0x5e, 0xbd, 0x1d, 0xb6,
    0x3f, 0x0c, 0xe8, 0x27, 0x5a, 0xa1, 0xfd, 0x45,
    0xe2, 0xd2, 0xa7, 0x35, 0xf8, 0x74, 0x93, 0x59
};

//static char P384_kinv_string[] =
//    "7436f030 88e65c37 ba8e7b33 887fbc87 757514d6 11f7d1fb"
//    "df6d2104 a297ad31 8cdbf740 4e4ba37e 599666df 37b8d8be";

static uint8_t P384_kinv_buf[] =
{
    0x74, 0x36, 0xf0, 0x30, 0x88, 0xe6, 0x5c, 0x37,
    0xba, 0x8e, 0x7b, 0x33, 0x88, 0x7f, 0xbc, 0x87,
    0x75, 0x75, 0x14, 0xd6, 0x11, 0xf7, 0xd1, 0xfb,
    0xdf, 0x6d, 0x21, 0x04, 0xa2, 0x97, 0xad, 0x31,
    0x8c, 0xdb, 0xf7, 0x40, 0x4e, 0x4b, 0xa3, 0x7e,
    0x59, 0x96, 0x66, 0xdf, 0x37, 0xb8, 0xd8, 0xbe
};

//static char P384_hash_string[] =
//    "b9210c9d 7e20897a b8659726 6a9d5077 e8db1b06 f7220ed6"
//    "ee75bd8b 45db3789 1f8ba555 03040041 59f4453d c5b3f5a1";

static uint8_t P384_hash_buf[] =
{
    0xb9, 0x21, 0x0c, 0x9d, 0x7e, 0x20, 0x89, 0x7a,
    0xb8, 0x65, 0x97, 0x26, 0x6a, 0x9d, 0x50, 0x77,
    0xe8, 0xdb, 0x1b, 0x06, 0xf7, 0x22, 0x0e, 0xd6,
    0xee, 0x75, 0xbd, 0x8b, 0x45, 0xdb, 0x37, 0x89,
    0x1f, 0x8b, 0xa5, 0x55, 0x03, 0x04, 0x00, 0x41,
    0x59, 0xf4, 0x45, 0x3d, 0xc5, 0xb3, 0xf5, 0xa1
};

//static char P384_s_string[] =
//    "20ab3f45 b74f10b6 e11f96a2 c8eb694d 206b9dda 86d3c7e3"
//    "31c26b22 c987b753 77265776 67adadf1 68ebbe80 3794a402";

static uint8_t P384_s_buf[] =
{
    0x20, 0xAB, 0x3F, 0x45, 0xB7, 0x4F, 0x10, 0xB6,
    0xE1, 0x1F, 0x96, 0xA2, 0xC8, 0xEB, 0x69, 0x4D,
    0x20, 0x6B, 0x9D, 0xDA, 0x86, 0xD3, 0xC7, 0xE3,
    0x31, 0xC2, 0x6B, 0x22, 0xC9, 0x87, 0xB7, 0x53,
    0x77, 0x26, 0x57, 0x76, 0x67, 0xAD, 0xAD, 0xF1,
    0x68, 0xEB, 0xBE, 0x80, 0x37, 0x94, 0xA4, 0x02
};

// 2^255 - 19 in big-endian
static uint8_t curve25519_p_buf[] =
{
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED
};

// 486662 in big-endian
static uint8_t curve25519_A_buf[] =
{
    0x07, 0x6D, 0x06
};

// In big endian order
uint8_t Curve255_bp_u_buf[] =
{
    0x09
};

// In big endian order
uint8_t Curve255_bp_v_buf[] =
{
    0x20, 0xAE, 0x19, 0xA1, 0xB8, 0xA0, 0x86, 0xB4,
    0xE0, 0x1E, 0xDD, 0x2C, 0x77, 0x48, 0xD1, 0x4C,
    0x92, 0x3D, 0x4D, 0x7E, 0x6D, 0x7C, 0x61, 0xB2,
    0x29, 0xE9, 0xC5, 0xA2, 0x7E, 0xCE, 0xD3, 0xD9
};

// In big endian order
uint8_t Curve255_bp_order_buf[] =
{
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
    0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED
};

static uint8_t curve448_p_buf[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// 156326 in big-endian
static uint8_t curve448_A_buf[] =
{
    0x02, 0x62, 0xA6
};

uint8_t Curve448_bp_u_buf[] =
{
    0x05
};

uint8_t Curve448_bp_v_buf[] =
{
    0x7D, 0x23, 0x5D, 0x12, 0x95, 0xF5, 0xB1, 0xF6,
    0x6C, 0x98, 0xAB, 0x6E, 0x58, 0x32, 0x6F, 0xCE,
    0xCB, 0xAE, 0x5D, 0x34, 0xF5, 0x55, 0x45, 0xD0,
    0x60, 0xF7, 0x5D, 0xC2, 0x8D, 0xF3, 0xF6, 0xED,
    0xB8 ,0x02, 0x7E, 0x23, 0x46, 0x43, 0x0D, 0x21,
    0x13, 0x12, 0xC4, 0xB1, 0x50, 0x67, 0x7A, 0xF7,
    0x6F, 0xD7, 0x22, 0x3D, 0x45, 0x7B, 0x5B, 0x1A
};

uint8_t Curve448_bp_order_buf[] =
{
    0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x7C, 0xCA, 0x23, 0xE9,
    0xC4, 0x4E, 0xDB, 0x49, 0xAE, 0xD6, 0x36, 0x90,
    0x21, 0x6C, 0xC2, 0x72, 0x8D, 0xC5, 0x8F, 0x55,
    0x23, 0x78, 0xC2, 0x92, 0xAB, 0x58, 0x44, 0xF3
};

//static char P521_p_string[] =
//        "01ff ffffffff ffffffff ffffffff ffffffff ffffffff"
//    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff"
//    "ffffffff ffffffff ffffffff ffffffff ffffffff";

static uint8_t P521_p_buf[] =
{
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF
};

//static char P521_a_string[] =
//        "01ff ffffffff ffffffff ffffffff ffffffff ffffffff"
//    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff"
//    "ffffffff ffffffff ffffffff ffffffff fffffffc";

static uint8_t P521_a_buf[] =
{
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFC
};

//static char P521_b_string[] =
//          "51 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b"
//    "99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd"
//    "3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00";

static uint8_t P521_b_buf[] =
{
    0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C, 0x9A,
    0x1F, 0x92, 0x9A, 0x21, 0xA0, 0xB6, 0x85, 0x40,
    0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3, 0x15,
    0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1, 0x09,
    0xE1, 0x56, 0x19, 0x39, 0x51, 0xEC, 0x7E, 0x93,
    0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1, 0xBF,
    0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C, 0x34,
    0xF1, 0xEF, 0x45, 0x1F, 0xD4, 0x6B, 0x50, 0x3F,
    0x00
};

//static char P521_xg_string[] =
//          "c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139"
//    "053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127"
//    "a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66";

static uint8_t P521_xg_buf[] =
{
    0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9,
    0xcd, 0x9e, 0x3e, 0xcb, 0x66, 0x23, 0x95, 0xb4,
    0x42, 0x9c, 0x64, 0x81, 0x39, 0x05, 0x3f, 0xb5,
    0x21, 0xf8, 0x28, 0xaf, 0x60, 0x6b, 0x4d, 0x3d,
    0xba, 0xa1, 0x4b, 0x5e, 0x77, 0xef, 0xe7, 0x59,
    0x28, 0xfe, 0x1d, 0xc1, 0x27, 0xa2, 0xff, 0xa8,
    0xde, 0x33, 0x48, 0xb3, 0xc1, 0x85, 0x6a, 0x42,
    0x9b, 0xf9, 0x7e, 0x7e, 0x31, 0xc2, 0xe5, 0xbd,
    0x66
};

//static char P521_yg_string[] =
//        "0118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449"
//    "579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901"
//    "3fad0761 353c7086 a272c240 88be9476 9fd16650";

static uint8_t P521_yg_buf[] =
{
    0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b,
    0xc0, 0x04, 0x5c, 0x8a, 0x5f, 0xb4, 0x2c, 0x7d,
    0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b,
    0x44, 0x68, 0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e,
    0x66, 0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4,
    0x26, 0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad,
    0x07, 0x61, 0x35, 0x3c, 0x70, 0x86, 0xa2, 0x72,
    0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1,
    0x66, 0x50
};

//static char P521_n_string[] =
//        "01ff ffffffff ffffffff ffffffff ffffffff ffffffff"
//    "ffffffff ffffffff fffffffa 51868783 bf2f966b 7fcc0148"
//    "f709a5d0 3bb5c9b8 899c47ae bb6fb71e 91386409";

// Base_pt_order:
static uint8_t P521_n_buf[] =
{
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f,
    0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
    0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
    0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
    0x64, 0x09
};


static ecc_point_t   *C255_base_pt;
static ecc_point_t   *C448_base_pt;
static pka_operand_t *C255_base_pt_order;
static pka_operand_t *C448_base_pt_order;

static char *TEST_NAME_STRING[] =
{
    [TEST_NOP]                  = "TEST_NOP",
    [TEST_ADD]                  = "TEST_ADD",
    [TEST_SUBTRACT]             = "TEST_SUBTRACT",
    [TEST_MULTIPLY]             = "TEST_MULTIPLY",
    [TEST_DIVIDE]               = "TEST_DIVIDE",
    [TEST_DIV_MOD]              = "TEST_DIV_MOD",
    [TEST_MODULO]               = "TEST_MODULO",
    [TEST_SHIFT_LEFT]           = "TEST_SHIFT_LEFT",
    [TEST_SHIFT_RIGHT]          = "TEST_SHIFT_RIGHT",
    [TEST_MOD_INVERT]           = "TEST_MOD_INVERT",
    [TEST_MOD_EXP]              = "TEST_MOD_EXP",
    [TEST_RSA_MOD_EXP]          = "TEST_RSA_MOD_EXP",
    [TEST_RSA_VERIFY]           = "TEST_RSA_VERIFY",
    [TEST_RSA_MOD_EXP_WITH_CRT] = "TEST_RSA_MOD_EXP_WITH_CRT",
    [TEST_MONT_ECDH_MULTIPLY]   = "TEST_MONT_ECDH_MULTIPLY",
    [TEST_ECC_ADD]              = "TEST_ECC_ADD",
    [TEST_ECC_DOUBLE]           = "TEST_ECC_DOUBLE",
    [TEST_ECC_MULTIPLY]         = "TEST_ECC_MULTIPLY",
    [TEST_MONT_ECDH]            = "TEST_MONT_ECDH",
    [TEST_MONT_ECDHE]           = "TEST_MONT_ECDHE",
    [TEST_ECDH]                 = "TEST_ECDH",
    [TEST_ECDHE]                = "TEST_ECDHE",
    [TEST_ECDSA_GEN]            = "TEST_ECDSA_GEN",
    [TEST_ECDSA_VERIFY]         = "TEST_ECDSA_VERIFY",
    [TEST_ECDSA_GEN_VERIFY]     = "TEST_ECDSA_GEN_VERIFY",
    [TEST_DSA_GEN]              = "TEST_DSA_GEN",
    [TEST_DSA_VERIFY]           = "TEST_DSA_VERIFY",
    [TEST_DSA_GEN_VERIFY]       = "TEST_DSA_GEN_VERIFY"
};

pka_test_name_t lookup_test_name(char *string)
{
    pka_test_name_t test_name;
    uint32_t        len;
    char            new_string[64];

    // First try straight name lookup
    for (test_name = TEST_ADD;  test_name <= TEST_DSA_GEN_VERIFY;  test_name++)
        if (strcasecmp(TEST_NAME_STRING[test_name], string) == 0)
            return test_name;

    // Now try name lookup with additional "TEST_" prefix added.
    strcpy(&new_string[0], "TEST_");
    len = strlen(new_string);
    strcpy(&new_string[len], string);

    for (test_name = TEST_ADD;  test_name <= TEST_DSA_GEN_VERIFY;  test_name++)
        if (strcasecmp(TEST_NAME_STRING[test_name], new_string) == 0)
            return test_name;

    return TEST_NOP;
}

char *test_name_to_string(pka_test_name_t test_name)
{
    if (test_name <= TEST_DSA_GEN_VERIFY)
        return TEST_NAME_STRING[test_name];

    return "TEST_NOP";
}

// ecdsa_key_system_t Curve225;
ecdsa_key_system_t P256_ecdsa;
ecdsa_key_system_t P384_ecdsa;
// ecdsa_key_system_t Curve448;
ecdsa_key_system_t P521_ecdsa;

// static test_ecdsa_t Curve225_test;
static test_ecdsa_t P256_ecdsa_test;
static test_ecdsa_t P384_ecdsa_test;
// static test_ecdsa_t Curve448_test;

static pka_operand_t *P256_kinv;
static pka_operand_t *P384_kinv;

static uint8_t TWO_BUFFER[1]  = { 0x02 };
static uint8_t ONE_BUFFER[1]  = { 0x01 };
static uint8_t ZERO_BUFFER[1] = { 0x00 };

static pka_operand_t TWO =
{
    .buf_len    = 1,
    .actual_len = 1,
    .buf_ptr    = &TWO_BUFFER[0]
};

static pka_operand_t ONE =
{
    .buf_len    = 1,
    .actual_len = 1,
    .buf_ptr    = &ONE_BUFFER[0]
};

static pka_operand_t ZERO =
{
    .buf_len    = 1,
    .actual_len = 1,
    .buf_ptr    = &ZERO_BUFFER[0]
};

//
// Helper functions
//

uint32_t byte_len(uint64_t num)
{
    uint32_t byte_len;

    byte_len = 0;
    while (num != 0)
    {
        num = num >> 8;
        byte_len++;
    }

    return byte_len;
}

uint8_t *append_bytes(uint8_t *buf_ptr, uint64_t num, uint32_t num_len)
{
    uint32_t cnt;

    for (cnt = 1; cnt <= num_len; cnt++)
    {
        *buf_ptr++ = (uint8_t) (num & 0xFF);
        num        = num >> 8;
    }

    return buf_ptr;
}

void byte_swap_copy(uint8_t *dest, uint8_t *src, uint32_t len)
{
    uint32_t idx;

    for (idx = 0; idx < len; idx++)
        dest[idx] = src[(len - 1) - idx];
}

static void set_pka_operand(pka_operand_t *operand,
                     uint8_t       *big_endian_buf_ptr,
                     uint32_t       buf_len,
                     uint8_t        big_endian)
{
    operand->big_endian = big_endian;
    operand->buf_len    = buf_len;
    operand->actual_len = buf_len;
    operand->buf_ptr    = malloc(buf_len);
    memset(operand->buf_ptr, 0, buf_len);

    operand->buf_len    = buf_len;
    operand->actual_len = buf_len;

    // Now fill the operand buf.
    if (big_endian)
        memcpy(operand->buf_ptr, big_endian_buf_ptr, buf_len);
    else
        byte_swap_copy(operand->buf_ptr, big_endian_buf_ptr, buf_len);
}


static uint32_t get_msb_idx(pka_operand_t *operand)
{
    uint32_t byte_len, msb_idx;
    uint8_t *byte_ptr;

    if (operand->big_endian)
    {
        byte_ptr = &operand->buf_ptr[0];
        if (byte_ptr[0] != 0)
            return 0;

        // Move forwards over all zero bytes.
        byte_len = operand->actual_len;
        msb_idx  = 0;
        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            msb_idx++;
            byte_ptr++;
            byte_len--;
        }

        return msb_idx;
    }
    else  // little-endian.
    {
        // First find the most significant byte based upon the actual_len,
        // and then move backwards over all zero bytes, in order to skip
        // leading zeros and find the real msb index.
        byte_len = operand->actual_len;
        byte_ptr = &operand->buf_ptr[byte_len - 1];
        if (byte_ptr[0] != 0)
            return byte_len - 1;

        msb_idx = byte_len - 1;
        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            msb_idx--;
            byte_ptr--;
            byte_len--;
        }
    }

    return msb_idx;
}

static uint32_t bits_in_byte(uint8_t byte)
{
    int32_t bit_num;

    if (byte == 0)
        return 0;

    // Assumes byte != 0;
    for (bit_num = 7; bit_num >= 0; bit_num--)
        if ((byte & (1 << bit_num)) != 0)
            return bit_num + 1;

    // Should never reach here
    return 0;
}

uint32_t operand_bit_len(pka_operand_t *operand)
{
    uint32_t byte_len;
    uint8_t *byte_ptr;

    byte_len = operand->actual_len;
    if (byte_len == 0)
        return 0;

    if (operand->big_endian)
    {
        // Move forwards over all zero bytes.
        byte_ptr = &operand->buf_ptr[0];
        if (byte_ptr[0] != 0)
            return (8 * (byte_len - 1)) + bits_in_byte(byte_ptr[0]);

        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            byte_ptr++;
            byte_len--;
        }
    }
    else // little-endian
    {
        // First find the most significant byte based upon the actual_len,
        // and then move backwards over all zero bytes.
        byte_ptr = &operand->buf_ptr[byte_len - 1];
        if (byte_ptr[0] != 0)
            return (8 * (byte_len - 1)) + bits_in_byte(byte_ptr[0]);

        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            byte_ptr--;
            byte_len--;
        }
    }

    if (byte_len == 0)
        return 0;
    else
        return (8 * (byte_len - 1)) + bits_in_byte(byte_ptr[0]);
}

uint32_t operand_byte_len(pka_operand_t *operand)
{
    uint32_t byte_len;
    uint8_t *byte_ptr;

    byte_len = operand->actual_len;
    if (byte_len == 0)
        return 0;

    if (operand->big_endian)
    {
        byte_ptr = &operand->buf_ptr[0];
        if (byte_ptr[0] != 0)
            return byte_len;

        // Move forwards over all zero bytes.
        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            byte_ptr++;
            byte_len--;
        }
    }
    else // little-endian
    {
        // First find the most significant byte based upon the actual_len, and
        // then move backwards over all zero bytes.
        byte_ptr = &operand->buf_ptr[byte_len - 1];
        if (byte_ptr[0] != 0)
            return byte_len;

        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            byte_ptr--;
            byte_len--;
        }
    }

    return byte_len;
}

uint8_t is_zero(pka_operand_t *operand)
{
    uint32_t len;

    len = operand_byte_len(operand);
    if (len == 0)
        return 1;
    else if (len == 1)
        return operand->buf_ptr[0] == 0;
    else
        return 0;
}

uint8_t is_one(pka_operand_t *operand)
{
    if (operand_byte_len(operand) != 1)
        return 0;

    return operand->buf_ptr[0] == 1;
}

uint8_t is_even(pka_operand_t *operand)
{
    if (operand_byte_len(operand) == 0)
        return 1;
    else
        return (operand->buf_ptr[0] & 0x01) == 0;
}

uint8_t is_odd(pka_operand_t *operand)
{
    if (operand_byte_len(operand) == 0)
        return 0;
    else
        return (operand->buf_ptr[0] & 0x01) != 0;
}

static uint32_t count_leading_zeros(pka_operand_t *operand)
{
    uint32_t byte_len, leading_zeros;
    uint8_t  ms_byte;

    byte_len = operand->actual_len;
    if (is_zero(operand))
        return byte_len - 1;
    else if (byte_len == 0)
        byte_len = operand->buf_len;

    for (leading_zeros = 0; leading_zeros <= byte_len; leading_zeros++)
    {
        if (operand->big_endian)
            ms_byte = operand->buf_ptr[leading_zeros];
        else
            ms_byte = operand->buf_ptr[(byte_len - 1) - leading_zeros];

        if (ms_byte != 0)
            return leading_zeros;
    }

    PKA_ASSERT(false);
    return byte_len - 1;
}

// The following function removes all leading zeros from the operand by
// decrementing the actual length field.
static void adjust_actual_len(pka_operand_t *operand)
{
    uint32_t byte_len, leading_zeros;

    if (is_zero(operand))
    {
        operand->actual_len = 1;
        return;
    }

    leading_zeros = count_leading_zeros(operand);
    if (leading_zeros == 0)
        return;

    byte_len = operand->actual_len;
    if (MAX_BUF < byte_len)
        abort();
    else if (byte_len == 0)
        byte_len = operand->buf_len;

    operand->actual_len = byte_len - leading_zeros;
    if (operand->big_endian)
        operand->buf_ptr += leading_zeros;
}

pka_operand_t *malloc_operand(uint32_t buf_len)
{
    pka_operand_t *operand;

    operand             = calloc(1, sizeof(pka_operand_t));
    operand->buf_ptr    = calloc(1, buf_len);
    operand->buf_len    = buf_len;
    operand->actual_len = 0;
    return operand;
}

static void operand_byte_copy(pka_operand_t *operand,
                              uint8_t       *big_endian_buf_ptr,
                              uint32_t       buf_len)
{
    PKA_ASSERT(buf_len <= operand->buf_len);

    if (operand->big_endian)
    {
        memcpy(operand->buf_ptr, big_endian_buf_ptr, buf_len);
    }
    else // little-endian
    {
        // Now fill the operand buf, but backwards.
        byte_swap_copy(operand->buf_ptr, big_endian_buf_ptr, buf_len);
    }

    operand->actual_len = buf_len;
}

static void make_operand_buf(pka_operand_t *operand,
                             uint8_t       *big_endian_buf_ptr,
                             uint32_t       buf_len)
{
    operand->buf_ptr = malloc(buf_len);
    memset(operand->buf_ptr, 0, buf_len);
    operand->buf_len    = buf_len;
    operand->actual_len = buf_len;
    // Now fill the operand buf.
    operand_byte_copy(operand, big_endian_buf_ptr, buf_len);
}

void free_operand_buf(pka_operand_t *operand)
{
    uint8_t *buf_ptr;

    buf_ptr = operand->buf_ptr;
    if (buf_ptr == NULL)
        PKA_ERROR(PKA_TESTS,  "free_operand_buf called with NULL buf_ptr\n");
    else
        free(buf_ptr);

    operand->buf_ptr      = NULL;
    operand->buf_len      = 0;
    operand->actual_len   = 0;
}

pka_operand_t *make_operand(uint8_t  *big_endian_buf_ptr,
                            uint32_t  buf_len,
                            uint8_t   big_endian)
{
    pka_operand_t *operand;

    operand = malloc(sizeof(pka_operand_t));
    memset(operand, 0, sizeof(pka_operand_t));
    operand->big_endian = big_endian;
    // Now init the operand buf.
    make_operand_buf(operand, big_endian_buf_ptr, buf_len);
    return operand;
}

void free_operand(pka_operand_t *operand)
{
    if (operand == NULL)
    {
        PKA_ERROR(PKA_TESTS,  "free_operand called with NULL operand\n");
        return;
    }

    free_operand_buf(operand);
    operand->internal_use = 0;
    operand->pad          = 0;
    free(operand);
}

void init_operand(pka_operand_t *operand,
                  uint8_t       *buf,
                  uint32_t       buf_len,
                  uint8_t        big_endian)
{
    memset(operand, 0, sizeof(pka_operand_t));
    memset(buf,     0, buf_len);
    operand->buf_ptr    = buf;
    operand->buf_len    = buf_len;
    operand->actual_len = 0;
    operand->big_endian = big_endian;
}

// Operand must be Initialized first (e.g. by calling init_operand).
static void set_operand(pka_operand_t *operand, uint32_t integer)
{
    uint32_t  lsb_idx, idx;
    uint8_t  *buf_ptr;

    if (integer == 0)
        operand->actual_len = 0;
    else if (integer < 0x100)
        operand->actual_len = 1;
    else if (integer < 0x10000)
        operand->actual_len = 2;
    else if (integer < 0x1000000)
        operand->actual_len = 3;
    else
        operand->actual_len = 4;

    lsb_idx = (operand->big_endian) ? (operand->actual_len - 1) : 0;
    buf_ptr = &operand->buf_ptr[lsb_idx];

    // Work from the least significant end to the most significant end.
    for (idx = 0;  idx < operand->actual_len;  idx++)
    {
        *buf_ptr = integer & 0xFF;
        integer  = integer >> 8;
        if (operand->big_endian)
            buf_ptr--;
        else
            buf_ptr++;
    }
}

void copy_operand(pka_operand_t *original, pka_operand_t *copy)
{
    uint8_t *copy_buf_ptr;

    copy_buf_ptr = copy->buf_ptr;
    memcpy(copy, original, sizeof(pka_operand_t));

    copy->buf_ptr = copy_buf_ptr;
    memcpy(copy->buf_ptr, original->buf_ptr, original->actual_len);
}

pka_operand_t *dup_operand(pka_operand_t *src_operand)
{
    pka_operand_t *new_operand;
    uint32_t       leading_zeros, len;
    uint8_t       *src_buf_ptr;

    if (src_operand == NULL)
    {
        PKA_ERROR(PKA_TESTS,  "dup_operand called with src_operand == NULL\n");
        return NULL;
    }

    leading_zeros = count_leading_zeros(src_operand);
    len           = src_operand->actual_len - leading_zeros;
    src_buf_ptr   = src_operand->buf_ptr;
    if (src_operand->big_endian)
        src_buf_ptr += leading_zeros;

    new_operand             = malloc_operand(len);
    new_operand->actual_len = len;
    new_operand->big_endian = src_operand->big_endian;
    memcpy(new_operand->buf_ptr, src_buf_ptr, len);
    return new_operand;
}

pka_operand_t *rand_operand(pka_handle_t  handle,
                            uint32_t      bit_len,
                            bool          make_odd)
{
    pka_operand_t *result;
    uint32_t       byte_len, msb_idx, lsb_idx, num_msb_bits;
    uint8_t        msb_byte;

    byte_len           = (bit_len + 7) / 8;
    result             = malloc_operand(byte_len);
    result->actual_len = byte_len;
    result->big_endian = pka_get_rings_byte_order(handle);

    get_rand_bytes(handle, &result->buf_ptr[0], byte_len);

    // Get the index of the most significant and least significant bytes.
    if (result->big_endian)
    {
        result->big_endian = 1;
        msb_idx            = 0;
        lsb_idx            = byte_len - 1;
    }
    else
    {
        result->big_endian = 0;
        msb_idx            = byte_len - 1;
        lsb_idx            = 0;
    }

    // Make sure the msb byte is non-zero and in fact is of the correct
    // bit len.
    msb_byte     = result->buf_ptr[msb_idx];
    num_msb_bits = bit_len - (8 * (byte_len - 1));
    PKA_ASSERT((1 <= num_msb_bits) && (num_msb_bits <= 8));

    msb_byte |=   1 << (num_msb_bits - 1);
    msb_byte &= ((1 << num_msb_bits) - 1);

    result->buf_ptr[msb_idx] = msb_byte;
    if (make_odd)
        result->buf_ptr[lsb_idx] |= 0x01;

    PKA_ASSERT(operand_bit_len(result) == bit_len);
    return result;
}

static uint32_t operand_to_uint32(pka_operand_t *operand)
{
    uint32_t operand_len, msb_idx, value, idx;
    uint8_t *buf_ptr;

    operand_len = operand_byte_len(operand);
    if (4 < operand_len)
        return 0;  // This should never happen!

    msb_idx = get_msb_idx(operand);
    buf_ptr = &operand->buf_ptr[msb_idx];
    value   = 0;

    // Work from the most significant end to the least significant end.
    for (idx = 0; idx < operand_len; idx++)
    {
        value = (value << 8) | buf_ptr[0];
        if (operand->big_endian)
            buf_ptr++;
        else
            buf_ptr--;
    }

    return value;
}

pka_operand_t *uint32_to_operand(uint32_t value,
                                 uint8_t  big_endian)
{
    pka_operand_t *operand;
    uint32_t       value_len;

    if (value < 0x100)
        value_len = 1;
    else if (value < 0x10000)
        value_len = 2;
    else if (value < 0x1000000)
        value_len = 3;
    else
        value_len = 4;

    operand = malloc_operand(value_len);
    operand->big_endian = big_endian;
    set_operand(operand, value);

    return operand;
}

static uint32_t num_trailing_zeros(pka_operand_t *value)
{
    uint32_t byte_len, trailing_zeros, byte_idx, index, bit_idx;
    uint8_t  byte;

    // Find the number of trailing zero bits in value.
    byte_len       = value->actual_len;
    trailing_zeros = 0;
    for (byte_idx = 0;  byte_idx < byte_len;  byte_idx++)
    {
        if (value->big_endian)
            index = (byte_len - 1) - byte_idx;
        else
            index = byte_idx;

        byte = value->buf_ptr[index];
        if (byte != 0)
        {
            for (bit_idx = 0;  bit_idx < 8;  bit_idx++)
            {
                if ((byte & (1 << bit_idx)) != 0)
                    break;

                trailing_zeros++;
            }

            return trailing_zeros;
        }

        trailing_zeros += 8;
    }

    // If we reach here then value is all zeros.
    return 0;
}

// Return a big number between 1 .. max_plus_1 - 1.

pka_operand_t *rand_non_zero_integer(pka_handle_t   handle,
                                     pka_operand_t *max_plus_1)
{
    pka_operand_t *result;
    uint32_t       byte_len, msb_idx, max_plus_msb, result_msb;

    byte_len           = operand_byte_len(max_plus_1);
    result             = malloc_operand(byte_len);
    result->big_endian = pka_get_rings_byte_order(handle);
    result->actual_len = byte_len;

    do
    {
        get_rand_bytes(handle, &result->buf_ptr[0], byte_len);
    } while (is_zero(result));

    if (pki_compare(result, max_plus_1) == RC_LEFT_IS_SMALLER)
        return result;

    // Need to reduce the most significant byte of the result to be less than
    // the most significant byte of max_plus_1.  First get msb of max_plus_1.
    msb_idx      = get_msb_idx(max_plus_1);
    max_plus_msb = max_plus_1->buf_ptr[msb_idx];
    PKA_ASSERT(max_plus_msb != 0);

    // Next find msb of the result and adjust it.
    msb_idx                  = get_msb_idx(result);
    result_msb               = result->buf_ptr[msb_idx];
    result->buf_ptr[msb_idx] = result_msb % max_plus_msb;
    return result;
}

bool miller_rabin_test(pka_handle_t   handle,
                       pka_operand_t *witness,        // aka a
                       pka_operand_t *prime,
                       pka_operand_t *prime_minus_1,
                       pka_operand_t *odd,            // aka d
                       uint32_t       trailing_zeros,
                       bool           debug)
{
    pka_operand_t *mod_exp, *squared;
    bool           is_one, is_minus_one;
    uint32_t       idx;

    // PKA_ASSERT (1 <= trailing_zeros);
    mod_exp = sync_mod_exp(handle, odd, prime, witness);

    // If mod_exp == 1 || mod_exp == prime_minus_1 then is a probable prime
    // so return true.  Otherwise keep testing the modular squares of mod_exp.
    is_one       = pki_compare(mod_exp, &ONE)          == RC_COMPARE_EQUAL;
    is_minus_one = pki_compare(mod_exp, prime_minus_1) == RC_COMPARE_EQUAL;
    if (is_minus_one || is_one)
    {
        free_operand(mod_exp);
        return true;
    }

    squared = NULL;
    for (idx = 1;  idx < trailing_zeros;  idx++)
    {
        squared      = sync_mod_multiply(handle, mod_exp, mod_exp, prime);
        is_one       = pki_compare(squared, &ONE)          == RC_COMPARE_EQUAL;
        is_minus_one = pki_compare(squared, prime_minus_1) == RC_COMPARE_EQUAL;
        free_operand(mod_exp);
        mod_exp = squared;

        if (is_minus_one || is_one)
        {
            free_operand(mod_exp);
            return is_minus_one;
        }
    }

    free_operand(mod_exp);
    return false;
}

bool is_prime(pka_handle_t   handle,
              pka_operand_t *prime,    // aka possible_prime
              uint32_t       iterations,
              bool           should_be_prime)
{
    pka_operand_t *prime_minus_1, *odd, *witness;
    bool           result, prime_test;
    uint32_t       trailing_zeros, cnt;

    prime_minus_1 = sync_subtract(handle, prime, &ONE);

    // Find the number of trailing zero bits in prime_minus_1.
    trailing_zeros = num_trailing_zeros(prime_minus_1);

    // Divide prime_minus_1 by 2^trailing_zeros, which is equivalent to a
    // right shift by trailing_zeros.  This right shift is done first by
    // dropping the bottom "trailing_zeros/8" bytes and then right shifting
    // this value by "trailing_zeros & 7".
    odd    = sync_shift_right(handle, prime_minus_1, trailing_zeros);
    result = true;

    for (cnt = 1;  cnt <= iterations;  cnt++)
    {
        witness = rand_non_zero_integer(handle, prime_minus_1);

        // g = gcd(b, prime);
        // if (! IsZero(g))
        //     return 0;
        prime_test = miller_rabin_test(handle, witness, prime, prime_minus_1,
                                       odd, trailing_zeros, false);

        if ((prime_test == false) && should_be_prime)
        {
            PKA_PRINT(PKA_TESTS,  "Composite found cnt=%u\n", cnt);
            print_operand("prime       =", prime,   "\n");
            print_operand("witness     =", witness, "\n");
        }

        free_operand(witness);
        if (prime_test == false)
        {
            result = false;
            break;
        }
    }

    free_operand(odd);
    free_operand(prime_minus_1);
    return result;
}

pka_operand_t *rand_prime_operand(pka_handle_t handle, uint32_t bit_len)
{
    pka_operand_t *operand;
    uint32_t       max_attempts, attempts;

    max_attempts  = 16 * bit_len;
    for (attempts = 1;  attempts <= max_attempts;  attempts++)
    {
        operand = rand_operand(handle, bit_len, true);
        if (is_prime(handle, operand, 25, false))
        {
            if ((max_attempts / 2) < attempts)
                PKA_PRINT(PKA_TESTS,
                    "rand_prime required %d attempts for bit_len=%u\n",
                    attempts, bit_len);
            return operand;
        }

        free_operand(operand);
    }

    PKA_ERROR(PKA_TESTS,
        "rand_prime failed to find a prime number after %u attempts\n",
        max_attempts);
    return NULL;
}

static uint8_t HEX_CHARS[] = "0123456789ABCDEF";
static uint8_t FROM_HEX[256] =
{
    ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,
    ['5'] = 5,  ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,
    ['a'] = 10, ['b'] = 11, ['c'] = 12, ['d']  = 13, ['e'] = 14, ['f'] = 15,
    ['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15
};

int to_hex_string(pka_operand_t *value,
                  char          *string_buf,
                  uint32_t       buf_len)
{
    uint32_t byte_len, byte_cnt, byte_value;
    uint8_t *byte_ptr;
    char    *char_ptr;

    byte_len = value->actual_len;
    if (buf_len <= byte_len)
        return -1;

    memset(string_buf, 0, buf_len);

    if (value->big_endian)
    {
        byte_ptr = &value->buf_ptr[0];
        char_ptr = &string_buf[0];
        for (byte_cnt = 0;  byte_cnt < byte_len;  byte_cnt++)
        {
            byte_value  = *byte_ptr++;
            *char_ptr++ = HEX_CHARS[byte_value >> 4];
            *char_ptr++ = HEX_CHARS[byte_value & 0x0F];
        }
    }
    else
    {
        byte_ptr = &value->buf_ptr[byte_len - 1];
        char_ptr = &string_buf[0];
        for (byte_cnt = 0;  byte_cnt < byte_len;  byte_cnt++)
        {
            byte_value  = *byte_ptr--;
            *char_ptr++ = HEX_CHARS[byte_value >> 4];
            *char_ptr++ = HEX_CHARS[byte_value & 0x0F];
        }
    }

    return 0;
}

int from_hex_string(char *hex_string, pka_operand_t *value)
{
    uint32_t string_len, hexDigitCnt, char_idx, byte_len, hexDigitState;
    uint32_t hex_value, hex_value1 = 0;
    uint8_t *big_num_ptr, ch, big_endian, byte_value;

    // Skip the initial 0x, if present
    string_len = strlen(hex_string);
    if ((3 <= string_len) && (hex_string[0] == '0') &&
        (hex_string[1] == 'x'))
    {
        hex_string += 2;
        string_len -= 2;
    }

    // Next count the number of hexadecimal characters in the string (i.e.
    // ignoring things like spaces and underscores).
    hexDigitCnt = 0;
    for (char_idx = 0;  char_idx < string_len;  char_idx++)
    {
        ch = hex_string[char_idx];
        if (isxdigit(ch))
            hexDigitCnt++;
        else if ((! isspace(ch)) && (ch != '_'))
            return -1;
    }

    byte_len = (hexDigitCnt + 1) / 2;
    if (value->buf_ptr == NULL)
    {
        value->buf_ptr = malloc(byte_len);
        value->buf_len = byte_len;
    }
    else if (value->buf_len < byte_len)
        return -1;

    value->actual_len   = byte_len;
    value->is_encrypted = 0;
    big_endian          = value->big_endian;
    if (big_endian)
        big_num_ptr = &value->buf_ptr[0];
    else
        big_num_ptr = &value->buf_ptr[byte_len - 1];

    hexDigitState = 0;
    hex_value1    = 0;
    if ((hexDigitCnt & 0x1) != 0)
        hexDigitState = 1;

    for (char_idx = 0;  char_idx < string_len;  char_idx++)
    {
        ch = hex_string[char_idx];
        if (isxdigit(ch))
        {
            hex_value = FROM_HEX[ch];
            if (hexDigitState == 0)
            {
                hex_value1    = hex_value;
                hexDigitState = 1;
            }
            else
            {
                byte_value    = (hex_value1 << 4) | hex_value;
                hexDigitState = 0;
                if (big_endian)
                    *big_num_ptr++ = byte_value;
                else
                    *big_num_ptr-- = byte_value;
            }
        }
    }

    return 0;
}

pka_operand_t *hex_string_to_operand(char *string, uint8_t big_endian)
{
    pka_operand_t *operand;
    uint32_t       string_len, hex_digits, idx;

    string_len = strlen(string);
    hex_digits = 0;
    for (idx = 0;  idx < string_len;  idx++)
        if (isxdigit(string[idx]))
            hex_digits++;

    operand             = malloc_operand((hex_digits + 1) / 2);
    operand->big_endian = big_endian;
    from_hex_string(string, operand);
    return operand;
}

void print_operand(char *prefix, pka_operand_t *operand, char *suffix)
{
    uint32_t byte_len, byte_cnt, byte_idx;
    uint8_t *byte_ptr;

    if (prefix != NULL)
        printf("%s", prefix);

    byte_len = operand_byte_len(operand);
    printf("0x");
    if ((byte_len == 0) || ((byte_len == 1) && (operand->buf_ptr[0] == 0)))
        printf("0");
    else
    {
        byte_idx = (operand->big_endian) ? 0 : byte_len - 1;
        byte_ptr = &operand->buf_ptr[byte_idx];
        for (byte_cnt = 0; byte_cnt < byte_len; byte_cnt++)
            printf("%02X", (operand->big_endian) ?
                    *byte_ptr++ : *byte_ptr--);
    }

    if (suffix != NULL)
        printf("%s", suffix);
}

ecc_point_t *malloc_ecc_point(uint32_t buf_x_len,
                              uint32_t buf_y_len,
                              uint8_t  big_endian)
{
    ecc_point_t   *ecc_point;
    uint8_t       *buf_x, *buf_y;

    ecc_point = malloc(sizeof(ecc_point_t));
    memset(ecc_point, 0, sizeof(ecc_point_t));

    buf_x = malloc(buf_x_len);
    buf_y = malloc(buf_y_len);

    init_operand(&ecc_point->x, buf_x, buf_x_len, big_endian);
    init_operand(&ecc_point->y, buf_y, buf_y_len, big_endian);

    return ecc_point;
}

void free_ecc_point(ecc_point_t *ecc_point)
{
    if (ecc_point == NULL)
    {
        PKA_ERROR(PKA_TESTS,  "free_ecc_point called with NULL operand\n");
        return;
    }

    free_operand_buf(&ecc_point->x);
    free_operand_buf(&ecc_point->y);
    free(ecc_point);
}

void init_ecc_point(ecc_point_t *ecc_pt,
                    uint8_t     *buf_x,
                    uint8_t     *buf_y,
                    uint32_t     buf_len,
                    uint8_t      big_endian)
{
    init_operand(&ecc_pt->x, buf_x, buf_len, big_endian);
    init_operand(&ecc_pt->y, buf_y, buf_len, big_endian);
}

static void init_mont_curves(void)
{

    // Initialize the two Montgomery curves
    memset(&curve25519, 0, sizeof(curve25519));
    set_pka_operand(&curve25519.p, curve25519_p_buf,
                    sizeof(curve25519_p_buf), 0);
    set_pka_operand(&curve25519.A, curve25519_A_buf,
                    sizeof(curve25519_A_buf), 0);
    curve25519.type = PKA_CURVE_25519;

    memset(&curve448, 0, sizeof(curve448));
    set_pka_operand(&curve448.p, curve448_p_buf,
                    sizeof(curve448_p_buf), 0);
    set_pka_operand(&curve448.A, curve448_A_buf,
                    sizeof(curve448_A_buf), 0);
    curve448.type = PKA_CURVE_448;
}

ecc_point_t *make_mont_ecc_point(ecc_mont_curve_t *curve,
                                 uint8_t     *big_endian_buf_x_ptr,
                                 uint32_t     buf_x_len,
                                 uint8_t     *big_endian_buf_y_ptr,
                                 uint32_t     buf_y_len,
                                 uint8_t      big_endian)
{
    ecc_point_t *ecc_point;

    ecc_point = malloc(sizeof(ecc_point_t));
    memset(ecc_point, 0, sizeof(ecc_point_t));

    ecc_point->x.big_endian = big_endian;
    ecc_point->y.big_endian = big_endian;

    make_operand_buf(&ecc_point->x, big_endian_buf_x_ptr, buf_x_len);
    make_operand_buf(&ecc_point->y, big_endian_buf_y_ptr, buf_y_len);

    return ecc_point;
}

static pka_result_code_t pki_internal_subtract(pka_operand_t *value,
                                               pka_operand_t *subtrahend,
                                               pka_operand_t *result)
{
    uint32_t minuend_byte_len, subtrahend_byte_len, result_byte_len;
    uint32_t borrow, minuend_byte, subtrahend_byte, result_byte;
    uint32_t byte_cnt;
    uint8_t *minuend_ptr, *subtrahend_ptr, *result_ptr;

    minuend_byte_len    = value->actual_len;
    subtrahend_byte_len = subtrahend->actual_len;
    result_byte_len     = minuend_byte_len;
    result->actual_len  = result_byte_len;

    minuend_ptr    = &value->buf_ptr[0];
    subtrahend_ptr = &subtrahend->buf_ptr[0];
    result_ptr     = &result->buf_ptr[0];

    // Subtract subtrahend from minued by proceeding from the least significant
    // bytes to the most significant bytes.
    borrow = 0;
    for (byte_cnt = 0; byte_cnt < minuend_byte_len; byte_cnt++)
    {
        minuend_byte = *minuend_ptr;
        if (byte_cnt < subtrahend_byte_len)
            subtrahend_byte = (*subtrahend_ptr) + borrow;
        else
            subtrahend_byte = borrow;

        if (subtrahend_byte <= minuend_byte)
        {
            result_byte = minuend_byte - subtrahend_byte;
            borrow    = 0;
        }
        else
        {
            result_byte = (256 + minuend_byte) - subtrahend_byte;
            borrow    = 1;
        }

        *result_ptr = result_byte;
        minuend_ptr++;
        subtrahend_ptr++;
        result_ptr++;
    }

    // Finally adjust the actual length by skipping any leading zeros.
    result_byte_len = result->actual_len;
    result_ptr      = &result->buf_ptr[result_byte_len - 1];
    while ((*result_ptr == 0) && (1 <= result_byte_len))
    {
        result_ptr--;
        result_byte_len--;
    }

    result->actual_len = result_byte_len;
    return RC_NO_ERROR;
}

static pka_comparison_t pki_internal_compare(uint8_t *value_buf_ptr,
                                             uint8_t *comparend_buf_ptr,
                                             uint32_t operand_len,
                                             uint8_t  is_big_endian)
{
    uint32_t idx, value_len, comparend_len;

    if (is_big_endian)
    {
        // Start the comparison at the most significant end which is at the
        // lowest idx.  But first we need to skip any leading zeros!
        value_len = operand_len;
        while ((value_buf_ptr[0] == 0) && (2 <= value_len))
        {
            value_buf_ptr++;
            value_len--;
        }

        comparend_len = operand_len;
        while ((comparend_buf_ptr[0] == 0) && (2 <= comparend_len))
        {
            comparend_buf_ptr++;
            comparend_len--;
        }

        if (value_len < comparend_len)
            return PKA_LESS_THAN;
        else if (comparend_len < value_len)
            return PKA_GREATER_THAN;

        operand_len = value_len;
        for (idx = 1;  idx <= operand_len;  idx++)
        {
            if (value_buf_ptr[0] < comparend_buf_ptr[0])
                return PKA_LESS_THAN;
            else if (value_buf_ptr[0] > comparend_buf_ptr[0])
                return PKA_GREATER_THAN;

            value_buf_ptr++;
            comparend_buf_ptr++;
        }
    }
    else
    {
        // Start the comparison at the most significant end which is at the
        // highest idx.  But first we need to skip any leading zeros!
        value_buf_ptr = &value_buf_ptr[operand_len - 1];
        value_len     = operand_len;
        while ((value_buf_ptr[0] == 0) && (2 <= value_len))
        {
            value_buf_ptr--;
            value_len--;
        }

        comparend_buf_ptr = &comparend_buf_ptr[operand_len - 1];
        comparend_len     = operand_len;
        while ((comparend_buf_ptr[0] == 0) && (2 <= comparend_len))
        {
            comparend_buf_ptr--;
            comparend_len--;
        }

        if (value_len < comparend_len)
            return PKA_LESS_THAN;
        else if (comparend_len < value_len)
            return PKA_GREATER_THAN;

        operand_len = value_len;
        for (idx = 1;  idx <= operand_len;  idx++)
        {
            if (value_buf_ptr[0] < comparend_buf_ptr[0])
                return PKA_LESS_THAN;
            else if (value_buf_ptr[0] > comparend_buf_ptr[0])
                return PKA_GREATER_THAN;

            value_buf_ptr--;
            comparend_buf_ptr--;
        }
    }

    return PKA_EQUAL;
}


/// This function, returns 1 if the given value is less than or equal to
/// the curve prime.  Specifically will return 0 for curve25519 iff the value
/// is between 2^255 - 19 and 2^255 - 1.  For curve448, it will return 0 iff
/// the value is between 2^448 - 2^224 - 1 and 2^448 - 1.  Note that it is
/// exceedingly rare for this function to return 0 on random inputs.
static int pki_is_mont_ecdh_canonical(ecc_mont_curve_t* curve,
                                      pka_operand_t*    point_x)
{
    pka_comparison_t rc;
    uint32_t         idx;
    uint8_t          big_endian, ls_byte, ms_byte;

    big_endian = point_x->big_endian;
    if (curve->type == PKA_CURVE_25519)
    {
        if (point_x->actual_len != 32)
            return 1;

        // We want to see if point_x (with a special adjustment of the
        // most significant byte) is < the curve prime.
        // First do a quick test
        ls_byte = point_x->buf_ptr[big_endian ? 31 : 0];
        if (ls_byte < 0xED) // 237 = 256 - 19
            return 1;

        // Loop over the bytes from least significant to most significant
        // looking for a byte != 0xFF.  The most signifcant byte is special.
        if (big_endian)
        {
            for (idx = 1; idx <= 30; idx++)
                if (point_x->buf_ptr[31 - idx] != 0xFF)
                    return 1;

            ms_byte = point_x->buf_ptr[0];
        }
        else
        {
            for (idx = 1; idx <= 30; idx++)
                if (point_x->buf_ptr[idx] != 0xFF)
                    return 1;

            ms_byte = point_x->buf_ptr[31];
        }

        ms_byte &= 0x7F;
        return ms_byte != 0x7F;
    }
    else if (curve->type == PKA_CURVE_448)
    {
        if (point_x->actual_len != 56)
            return 1;

        // Quick test *TBD*
        ms_byte = point_x->buf_ptr[big_endian ? 0 : 55];
        if (ms_byte != 0xFF)
            return 1;

        rc = pki_internal_compare(point_x->buf_ptr, curve->p.buf_ptr, 56,
                                  big_endian);
        if (rc == PKA_LESS_THAN)
            return 1;

        return 0;
    }
    else
        return 1;
}

/// This function will first check if the value is already canonical (by
/// calling pka_is_mont_ecdh_canonical), and if it is not canonical, it will
/// do a modular reduction of value by the curve prime.
static int pki_mont_ecdh_canonicalize(pka_handle_t      handle,
                                      ecc_mont_curve_t* curve,
                                      pka_operand_t*    point_x,
                                      pka_operand_t*    reduced_value)
{
    pka_result_code_t rc;
    pka_operand_t     temp;
    uint8_t           temp_buf[MAX_ECC_BUF];
    int               is_canonical;

    is_canonical = pki_is_mont_ecdh_canonical(curve, point_x);
    if (is_canonical)
        return -1;

    // Make a local copy of point_x first
    memcpy(&temp, point_x, sizeof(temp));
    temp.buf_ptr = &temp_buf[0];
    memcpy(temp.buf_ptr, point_x->buf_ptr, point_x->actual_len);
    if (curve->type == PKA_CURVE_25519)
        temp.buf_ptr[31] &= 0x7F;

    rc = pki_internal_subtract(&temp, &curve->p, reduced_value);
    if (rc == RC_NO_ERROR)
        return 0;
    else
        return -1;
}

static int pki_adjust_mont_ecdh_multiplier(pka_operand_t *dst_operand,
                                           pka_operand_t *src_operand,
                                           pka_operand_t *curve_p)
{
    uint32_t prime_byte_len, src_byte_len, msb_byte_idx;

    // Two different cases: Curve25519 and Cureve448.  Distinguish these cases
    // by looking at the length of the curve prime
    prime_byte_len = curve_p->actual_len;
    src_byte_len   = src_operand->actual_len;
    memset(dst_operand->buf_ptr, 0, dst_operand->buf_len);
    memcpy(dst_operand->buf_ptr, src_operand->buf_ptr, src_byte_len);
    if (prime_byte_len == 32)
    {
        // For curve25519, clear the three least significant bit (bits 0, 1
        // and 2), clear the most significant bit (bit 255), and set the next
        // most significant bit (bit 254).
        PKA_ASSERT(32 <= dst_operand->buf_len);
        msb_byte_idx                        = 31;
        dst_operand->buf_ptr[0]            &= 0xF8;
        dst_operand->buf_ptr[msb_byte_idx] &= 0x7F;
        dst_operand->buf_ptr[msb_byte_idx] |= 0x40;
        dst_operand->actual_len             = 32;
    }
    else if (prime_byte_len == 56)
    {
        // For curve448, clear the two least significant bit (bits 0 and 1),
        // and set the most significant bit (bit 487) to 1.
        PKA_ASSERT(56 <= dst_operand->buf_len);
        msb_byte_idx                        = 55;
        dst_operand->buf_ptr[0]            &= 0xFC;
        dst_operand->buf_ptr[msb_byte_idx] |= 0x80;
        dst_operand->actual_len             = 56;
    }

    return 0;
}

ecc_point_t *make_ecc_point(ecc_curve_t *curve,
                            uint8_t     *big_endian_buf_x_ptr,
                            uint32_t     buf_x_len,
                            uint8_t     *big_endian_buf_y_ptr,
                            uint32_t     buf_y_len,
                            uint8_t      big_endian)
{
    ecc_point_t *ecc_point;

    ecc_point = malloc(sizeof(ecc_point_t));
    memset(ecc_point, 0, sizeof(ecc_point_t));

    ecc_point->x.big_endian = big_endian;
    ecc_point->y.big_endian = big_endian;

    make_operand_buf(&ecc_point->x, big_endian_buf_x_ptr, buf_x_len);
    make_operand_buf(&ecc_point->y, big_endian_buf_y_ptr, buf_y_len);

    return ecc_point;
}

static void set_ecc_point(ecc_point_t   *ecc_point,
                          pka_operand_t *x,
                          pka_operand_t *y)
{
    uint8_t *buf_x, *buf_y;
    uint8_t  big_endian;

    PKA_ASSERT(x->big_endian == y->big_endian);
    big_endian = x->big_endian;

    // Now set the operand buffers.
    buf_x = malloc(MAX_ECC_BUF);
    buf_y = malloc(MAX_ECC_BUF);
    memset(buf_x, 0, MAX_ECC_BUF);
    memset(buf_y, 0, MAX_ECC_BUF);
    init_ecc_point(ecc_point, buf_x, buf_y, MAX_ECC_BUF, big_endian);

    copy_operand(x, &ecc_point->x);
    copy_operand(y, &ecc_point->y);
}

ecc_point_t *create_ecc_point(ecc_curve_t *curve,
                              uint8_t     *big_endian_buf_x_ptr,
                              uint32_t     buf_x_len,
                              uint8_t      big_endian)
{
    pka_operand_t x, x_squared, temp1, temp2, rhs, y, y_squared;
    ecc_point_t  *ecc_point;
    uint32_t      trial;
    uint8_t       bufA[MAX_BUF], bufB[MAX_BUF], bufC[MAX_BUF], bufD[MAX_BUF];
    uint8_t       bufE[MAX_BUF], bufF[MAX_BUF], bufG[MAX_BUF];
    uint8_t      *buf_x, *buf_y;
    pka_result_code_t rc, ret_code;

    init_operand(&x,         bufA, MAX_BUF, big_endian);
    init_operand(&x_squared, bufB, MAX_BUF, big_endian);
    init_operand(&temp1,     bufC, MAX_BUF, big_endian);
    init_operand(&temp2,     bufD, MAX_BUF, big_endian);
    init_operand(&rhs,       bufE, MAX_BUF, big_endian);
    init_operand(&y,         bufF, MAX_BUF, big_endian);
    init_operand(&y_squared, bufG, MAX_BUF, big_endian);

    operand_byte_copy(&x, big_endian_buf_x_ptr, buf_x_len);

    ret_code = RC_NO_MODULAR_INVERSE;
    for (trial = 1; trial <= 20; trial++)
    {
        // Find y such that y^2 mod p = x^3 + a*x + b mod p.
        rc = pki_mod_multiply(&x, &x, &curve->p, &x_squared);
        rc = pki_mod_add(&x_squared, &curve->a, &curve->p, &temp1);
        rc = pki_mod_multiply(&temp1, &x, &curve->p, &temp2);
        rc = pki_mod_add(&temp2, &curve->b, &curve->p, &rhs);
        rc = pki_mod_square_root(&rhs, &curve->p, &y);

        if (rc == RC_NO_ERROR)
        {
            ret_code = RC_NO_ERROR;
            break;
        }

        x.buf_ptr[0]++;
    }

#if PKA_LIB_DEBUG
    pki_mod_multiply(&y, &y, &curve->p, &y_squared);
    print_operand("x         = ", &x,         "\n");
    print_operand("x_squared = ", &x_squared, "\n");
    print_operand("temp1     = ", &temp1,     "\n");
    print_operand("temp2     = ", &temp2,     "\n");
    print_operand("rhs       = ", &rhs,       "\n");
    print_operand("y         = ", &y,         "\n");
    print_operand("y_squared = ", &y_squared, "\n\n");
#endif

    if (ret_code != RC_NO_ERROR)
    {
        PKA_ERROR(PKA_TESTS,  "%s failed\n", __func__);
        return NULL;
    }

    // Now create the ecc_point.
    ecc_point = malloc(sizeof(ecc_point_t));
    memset(ecc_point, 0, sizeof(ecc_point_t));

    buf_x = malloc(MAX_ECC_BUF);
    buf_y = malloc(MAX_ECC_BUF);
    memset(buf_x, 0, MAX_ECC_BUF);
    memset(buf_y, 0, MAX_ECC_BUF);
    init_ecc_point(ecc_point, buf_x, buf_y, MAX_ECC_BUF, big_endian);

    memcpy(buf_x, x.buf_ptr, x.actual_len);
    memcpy(buf_y, y.buf_ptr, y.actual_len);

    ecc_point->x.actual_len = x.actual_len;
    ecc_point->y.actual_len = y.actual_len;

    if (is_point_on_curve(curve, ecc_point) == 0)
        PKA_ERROR(PKA_TESTS,  "point not on curve\n\n");

    return ecc_point;
}

ecc_point_t *dup_ecc_point(ecc_point_t *src_point)
{
    ecc_point_t *new_point;
    uint8_t     *buf_x, *buf_y;

    if (src_point == NULL)
    {
        PKA_ERROR(PKA_TESTS,  "dup_ecc_point called with src_point == NULL\n");
        return NULL;
    }

    new_point = malloc(sizeof(ecc_point_t));
    memset(new_point, 0, sizeof(ecc_point_t));

    buf_x = malloc(MAX_ECC_BUF);
    buf_y = malloc(MAX_ECC_BUF);
    init_ecc_point(new_point, buf_x, buf_y, MAX_ECC_BUF, 0);

    copy_operand(&src_point->x, &new_point->x);
    copy_operand(&src_point->y, &new_point->y);

    return new_point;
}

void init_ecc_curve(ecc_curve_t *ecc_curve,
                    uint8_t     *buf_p,
                    uint8_t     *buf_a,
                    uint8_t     *buf_b,
                    uint32_t     buf_len,
                    uint8_t      big_endian)
{
    init_operand(&ecc_curve->p, buf_p, buf_len, big_endian);
    init_operand(&ecc_curve->a, buf_a, buf_len, big_endian);
    init_operand(&ecc_curve->b, buf_b, buf_len, big_endian);
}

ecc_curve_t *create_ecc_curve(pka_operand_t *prime,
                              pka_operand_t *a,
                              pka_operand_t *b)
{
    ecc_curve_t *curve;
    uint8_t     *buf_p, *buf_a, *buf_b;

    curve = malloc(sizeof(ecc_curve_t));
    buf_p = malloc(MAX_ECC_BUF);
    buf_a = malloc(MAX_ECC_BUF);
    buf_b = malloc(MAX_ECC_BUF);

    init_ecc_curve(curve, buf_p, buf_a, buf_b, MAX_ECC_BUF, 0);
    copy_operand(prime, &curve->p);
    copy_operand(a, &curve->a);
    copy_operand(b, &curve->b);

    return curve;
}

ecc_curve_t *make_ecc_curve(uint8_t *big_endian_buf_p_ptr,
                            uint32_t p_len,
                            uint8_t *big_endian_buf_a_ptr,
                            uint32_t a_len,
                            uint8_t *big_endian_buf_b_ptr,
                            uint32_t b_len,
                            uint8_t  big_endian)
{
    ecc_curve_t *curve;

    curve = malloc(sizeof(ecc_curve_t));
    memset(curve, 0, sizeof(ecc_curve_t));

    curve->p.big_endian = big_endian;
    curve->a.big_endian = big_endian;
    curve->b.big_endian = big_endian;

    make_operand_buf(&curve->p, big_endian_buf_p_ptr, p_len);
    make_operand_buf(&curve->a, big_endian_buf_a_ptr, a_len);
    make_operand_buf(&curve->b, big_endian_buf_b_ptr, b_len);

    return curve;
}

dsa_signature_t *malloc_dsa_signature(uint32_t r_buf_len,
                                      uint32_t s_buf_len,
                                      uint8_t  big_endian)
{
    dsa_signature_t *signature;
    uint8_t         *buf_r, *buf_s;

    signature = malloc(sizeof(dsa_signature_t));
    buf_r = malloc(r_buf_len);
    buf_s = malloc(s_buf_len);
    init_operand(&signature->r, buf_r, r_buf_len, big_endian);
    init_operand(&signature->s, buf_s, s_buf_len, big_endian);

    return signature;
}

void free_dsa_signature(dsa_signature_t *signature)
{
    if (signature == NULL)
    {
        PKA_ERROR(PKA_TESTS,  "free_dsa_signature called with NULL operand\n");
        return;
    }

    free_operand_buf(&signature->r);
    free_operand_buf(&signature->s);
    free(signature);
}

void init_dsa_signature(dsa_signature_t *signature,
                        uint8_t         *buf_r,
                        uint8_t         *buf_s,
                        uint32_t         buf_len,
                        uint8_t          big_endian)
{
    init_operand(&signature->r, buf_r, buf_len, big_endian);
    init_operand(&signature->s, buf_s, buf_len, big_endian);
}

dsa_signature_t *make_dsa_signature(uint8_t *big_endian_buf_r_ptr,
                                    uint32_t r_len,
                                    uint8_t *big_endian_buf_s_ptr,
                                    uint32_t s_len,
                                    uint8_t  big_endian)
{
    dsa_signature_t *signature;

    signature = malloc(sizeof(dsa_signature_t));
    memset(signature, 0, sizeof(dsa_signature_t));

    signature->r.big_endian = big_endian;
    signature->s.big_endian = big_endian;

    make_operand_buf(&signature->r, big_endian_buf_r_ptr, r_len);
    make_operand_buf(&signature->s, big_endian_buf_s_ptr, s_len);

    return signature;
}

dsa_domain_params_t *make_dsa_domain_params(uint8_t *big_endian_buf_p_ptr,
                                            uint32_t p_len,
                                            uint8_t *big_endian_buf_q_ptr,
                                            uint32_t q_len,
                                            uint8_t *big_endian_buf_g_ptr,
                                            uint32_t g_len,
                                            uint8_t  big_endian)
{
    dsa_domain_params_t *dsa_params;

    dsa_params = malloc(sizeof(dsa_domain_params_t));
    memset(dsa_params, 0, sizeof(dsa_domain_params_t));

    dsa_params->p.big_endian = big_endian;
    dsa_params->q.big_endian = big_endian;
    dsa_params->g.big_endian = big_endian;

    make_operand_buf(&dsa_params->p, big_endian_buf_p_ptr, p_len);
    make_operand_buf(&dsa_params->q, big_endian_buf_q_ptr, q_len);
    make_operand_buf(&dsa_params->g, big_endian_buf_g_ptr, g_len);

    return dsa_params;
}

pka_results_t *malloc_results(uint32_t result_cnt, uint32_t buf_len)
{
    pka_results_t *results;
    pka_operand_t *result_ptr;
    uint8_t        result_idx;

    PKA_ASSERT(result_cnt <= MAX_RESULT_CNT);

    results = malloc(sizeof(pka_results_t));
    memset(results, 0, sizeof(pka_results_t));

    for (result_idx = 0; result_idx < result_cnt; result_idx++)
    {
        result_ptr             = &results->results[result_idx];
        result_ptr->buf_ptr    = malloc(buf_len);
        memset(result_ptr->buf_ptr, 0, buf_len);
        result_ptr->buf_len    = buf_len;
        result_ptr->actual_len = 0;
    }

    results->result_cnt = result_cnt;

    return results;
}

//*TBR*
void init_results_buf(pka_results_t *results,
                             uint32_t       result_cnt,
                             uint32_t       result_buf_len)
{
    pka_operand_t *result_ptr;
    uint8_t        result_idx;

    PKA_ASSERT(result_cnt <= MAX_RESULT_CNT);

    for (result_idx = 0; result_idx < result_cnt; result_idx++)
    {
        result_ptr             = &results->results[result_idx];
        result_ptr->buf_ptr    = malloc(result_buf_len);
        memset(result_ptr->buf_ptr, 0, result_buf_len);
        result_ptr->buf_len    = result_buf_len;
        result_ptr->actual_len = 0;
    }

    results->result_cnt = result_cnt;
}

static void init_results_operand(pka_results_t *results,
                                 uint32_t       result_cnt,
                                 uint8_t       *res1_buf,
                                 uint32_t       res1_len,
                                 uint8_t       *res2_buf,
                                 uint32_t       res2_len)
{
    pka_operand_t *result_ptr;

    PKA_ASSERT(result_cnt <= MAX_RESULT_CNT);
    results->result_cnt = result_cnt;

    switch (result_cnt) {
    case 2:
        PKA_ASSERT(res2_buf   != NULL);
        result_ptr             = &results->results[1];
        result_ptr->buf_ptr    = res2_buf;
        memset(result_ptr->buf_ptr, 0, res2_len);
        result_ptr->buf_len    = res2_len;
        result_ptr->actual_len = 0;
        // fall-through
    case 1:
        PKA_ASSERT(res1_buf   != NULL);
        result_ptr             = &results->results[0];
        result_ptr->buf_ptr    = res1_buf;
        memset(result_ptr->buf_ptr, 0, res1_len);
        result_ptr->buf_len    = res1_len;
        result_ptr->actual_len = 0;
    default:
        return;
    }
}

//*TBR*
void free_results_buf(pka_results_t *results)
{
    pka_operand_t *result_ptr;
    uint8_t        result_idx;

    for (result_idx = 0; result_idx < results->result_cnt; result_idx++)
    {
        result_ptr             = &results->results[result_idx];
        free(result_ptr->buf_ptr);
        result_ptr->buf_ptr    = NULL;
        result_ptr->buf_len    = 0;
        result_ptr->actual_len = 0;
    }
}

//*TBR*
void free_results(pka_results_t *results)
{
    if (results == NULL)
    {
        PKA_ERROR(PKA_TESTS,  "free_results called with NULL operand\n");
        return;
    }

    free_results_buf(results);
    free(results);
}

//
// PKI software operations.
// Note that most of these functions assumes that operand buffer bytes are LE.
//

pka_result_code_t pki_copy(pka_operand_t *value, pka_operand_t *result_ptr)
{
    copy_operand(value, result_ptr);
    return RC_NO_ERROR;
}

pka_cmp_code_t pki_compare(pka_operand_t *left, pka_operand_t *right)
{
    uint32_t left_len, right_len, idx;
    uint8_t *left_buf_ptr, *right_buf_ptr;

    if (is_zero(left))
    {
        if (is_zero(right))
            return RC_COMPARE_EQUAL;
        else
            return RC_LEFT_IS_SMALLER;
    }
    else if (is_zero(right))
        return RC_RIGHT_IS_SMALLER;

    left_len      = left->actual_len;
    right_len     = right->actual_len;
    left_buf_ptr  = left->buf_ptr;
    right_buf_ptr = right->buf_ptr;

    // Start the comparison at the most significant end which is at the
    // highest idx.  But first we need to skip any leading zeros!
    left_buf_ptr = &left_buf_ptr[left_len - 1];
    while ((left_buf_ptr[0] == 0) && (2 <= left_len))
    {
        left_buf_ptr--;
        left_len--;
    }

    right_buf_ptr = &right_buf_ptr[right_len - 1];
    while ((right_buf_ptr[0] == 0) && (2 <= right_len))
    {
        right_buf_ptr--;
        right_len--;
    }

    if (left_len < right_len)
        return RC_LEFT_IS_SMALLER;
    else if (right_len < left_len)
        return RC_RIGHT_IS_SMALLER;

    for (idx = 1; idx <= left_len; idx++)
    {
        if (left_buf_ptr[0] < right_buf_ptr[0])
            return  RC_LEFT_IS_SMALLER;
        else if (left_buf_ptr[0] > right_buf_ptr[0])
            return RC_RIGHT_IS_SMALLER;

        left_buf_ptr--;
        right_buf_ptr--;
    }

    return RC_COMPARE_EQUAL;
}

pka_result_code_t pki_add(pka_operand_t *value,
                          pka_operand_t *addend,
                          pka_operand_t *result)
{
    uint32_t value_byte_len, addend_byte_len, result_byte_len;
    uint32_t value_byte, addend_byte, sum_byte, carry, idx, final_len;
    uint8_t *value_buf_ptr, *addend_buf_ptr, *result_buf_ptr;

    value_byte_len  = value->actual_len;
    value_buf_ptr   = value->buf_ptr;
    addend_byte_len = addend->actual_len;
    addend_buf_ptr  = addend->buf_ptr;
    result_byte_len = MAX(value_byte_len, addend_byte_len) + 1;
    result_buf_ptr  = result->buf_ptr;

    carry = 0;
    for (idx = 0; idx < result_byte_len - 1; idx++)
    {
        value_byte  = (idx < value_byte_len)  ? value_buf_ptr[idx]  : 0;
        addend_byte = (idx < addend_byte_len) ? addend_buf_ptr[idx] : 0;
        sum_byte    = value_byte + addend_byte + carry;
        carry       = sum_byte >> 8;
        result_buf_ptr[idx] = (uint8_t) (sum_byte & 0xFF);
    }

    result_buf_ptr[result_byte_len - 1] = carry;

    // Now determine result's actual_len by going backwards (i.e. from MSB
    // to LSB).
    for (idx = result_byte_len - 1; idx != 0; idx--)
        if (result_buf_ptr[idx] != 0)
            break;

    final_len = idx + 1;

    result->actual_len = final_len;
    return RC_NO_ERROR;
}

pka_result_code_t pki_subtract(pka_operand_t *value,
                               pka_operand_t *subtrahend,
                               pka_operand_t *result)
{
    uint32_t minuend_byte_len, subtrahend_byte_len, result_byte_len;
    uint32_t borrow, minuend_byte, subtrahend_byte, result_byte;
    uint32_t byte_cnt;
    uint8_t *minuend_ptr, *subtrahend_ptr, *result_ptr;

    if (pki_compare(value, subtrahend) == RC_LEFT_IS_SMALLER)
        return RC_CALCULATION_ERR;

    minuend_byte_len    = value->actual_len;
    subtrahend_byte_len = subtrahend->actual_len;
    result_byte_len     = minuend_byte_len;
    result->actual_len  = result_byte_len;

    minuend_ptr    = &value->buf_ptr[0];
    subtrahend_ptr = &subtrahend->buf_ptr[0];
    result_ptr     = &result->buf_ptr[0];

    // Subtract subtrahend from minued by proceeding from the least significant
    // bytes to the most significant bytes.
    borrow = 0;
    for (byte_cnt = 0; byte_cnt < minuend_byte_len; byte_cnt++)
    {
        minuend_byte = *minuend_ptr;
        if (byte_cnt < subtrahend_byte_len)
            subtrahend_byte = (*subtrahend_ptr) + borrow;
        else
            subtrahend_byte = borrow;

        if (subtrahend_byte <= minuend_byte)
        {
            result_byte = minuend_byte - subtrahend_byte;
            borrow    = 0;
        }
        else
        {
            result_byte = (256 + minuend_byte) - subtrahend_byte;
            borrow    = 1;
        }

        *result_ptr = result_byte;
        minuend_ptr++;
        subtrahend_ptr++;
        result_ptr++;
    }

    adjust_actual_len(result);
    return RC_NO_ERROR;
}

pka_result_code_t pki_add_subtract(pka_operand_t *value,
                                   pka_operand_t *addend,
                                   pka_operand_t *subtrahend,
                                   pka_operand_t *result_ptr)
{
    pka_result_code_t rc;

    rc = pki_add(value, addend, result_ptr);
    if (rc == RC_NO_ERROR)
        return rc;

    return pki_subtract(result_ptr, subtrahend, result_ptr);
}

pka_result_code_t pki_multiply(pka_operand_t *value,
                               pka_operand_t *multiplier,
                               pka_operand_t *result)
{
    uint32_t val_byte_len, mul_byte_len, result_byte_len;
    uint32_t val_idx, mul_idx, result_idx;
    uint32_t value_byte, mul_byte, result_byte, carry;
    uint8_t *val_buf_ptr, *mul_buf_ptr, *result_buf_ptr;

    val_byte_len       = value->actual_len;
    val_buf_ptr        = value->buf_ptr;
    mul_byte_len       = multiplier->actual_len;
    mul_buf_ptr        = multiplier->buf_ptr;
    result_byte_len    = val_byte_len + mul_byte_len;
    result->actual_len = result_byte_len;
    result_buf_ptr     = result->buf_ptr;

    if ((MAX_BUF < val_byte_len) || (MAX_BUF < mul_byte_len) ||
        (MAX_BUF < result_byte_len))
        abort();

    memset(result_buf_ptr, 0, result_byte_len);
    for (val_idx = 0; val_idx < val_byte_len; val_idx++)
    {
        value_byte = val_buf_ptr[val_idx];
        carry      = 0;

        for (mul_idx = 0; mul_idx < mul_byte_len; mul_idx++)
        {
            mul_byte    = mul_buf_ptr[mul_idx];
            result_idx  = val_idx + mul_idx;
            if (MAX_BUF < result_idx)
                abort();

            result_byte = result_buf_ptr[result_idx];
            result_byte = result_byte + (value_byte * mul_byte) + carry;
            carry       = result_byte >> 8;

            result_buf_ptr[result_idx] = (uint8_t) (result_byte & 0xFF);
        }

        result_idx = val_idx + mul_byte_len;
        result_buf_ptr[result_idx] = carry;
        if (MAX_BUF < result_idx)
            abort();
    }

    adjust_actual_len(result);
    return RC_NO_ERROR;
}

pka_result_code_t pki_shift_left(pka_operand_t *value,
                                 uint32_t       shift_cnt,
                                 pka_operand_t *result)
{
    uint32_t value_bit_len, value_byte_len, result_bit_len, byte_shift;
    uint32_t result_byte_len, bit_shift, cnt, value_idx, result_idx;
    uint32_t value_byte, result_byte, shift_out, temp;

    value_bit_len      = operand_bit_len(value);
    value_byte_len     = (value_bit_len + 7) / 8;
    result_bit_len     = value_bit_len + shift_cnt;
    result_byte_len    = (result_bit_len + 7) / 8;
    result->actual_len = result_byte_len;

    byte_shift = shift_cnt / 8;
    bit_shift  = shift_cnt & 0x7;
    if (bit_shift == 0)
    {
        memcpy(&result->buf_ptr[byte_shift], value->buf_ptr, value_byte_len);
        return RC_NO_ERROR;
    }

    // Loop from LSB to MSB.
    shift_out = 0;
    PKA_ASSERT(value_byte_len != 0);
    for (cnt = 0; cnt < value_byte_len; cnt++)
    {
        value_idx   = cnt;
        result_idx  = cnt + byte_shift;
        value_byte  = value->buf_ptr[value_idx];
        temp        = (value_byte << bit_shift) | shift_out;
        result_byte = temp & 0xFF;
        shift_out   = temp >> 8;
        result->buf_ptr[result_idx] = result_byte;
    }

    if (shift_out != 0)
        result->buf_ptr[result_idx + 1] = shift_out;

    return RC_NO_ERROR;
}

pka_result_code_t pki_shift_right(pka_operand_t *value,
                                  uint32_t       shift_cnt,
                                  pka_operand_t *result)
{
    uint32_t value_bit_len, value_byte_len, result_bit_len, byte_shift;
    uint32_t result_byte_len, bit_shift, copy_len, acc, acc_mask;
    uint32_t value_byte, result_byte;
    int32_t  value_idx, result_idx;

    value_bit_len = operand_bit_len(value);
    if (value_bit_len <= shift_cnt)
    {
        set_operand(result, 0);
        return RC_NO_ERROR;
    }

    value_byte_len     = (value_bit_len + 7) / 8;
    result_bit_len     = value_bit_len - shift_cnt;
    result_byte_len    = (result_bit_len + 7) / 8;
    result->actual_len = result_byte_len;

    byte_shift = shift_cnt / 8;
    bit_shift  = shift_cnt & 0x7;
    if (bit_shift == 0)
    {
        copy_len = value_byte_len - byte_shift;
        memcpy(result->buf_ptr, &value->buf_ptr[byte_shift], copy_len);
        return RC_NO_ERROR;
    }

    // Loop from MSB to LSB.
    value_idx  = (value_byte_len  - 1);
    result_idx = (result_byte_len - 1);

    // Initialize the accumulator
    acc = 0;
    if (result_byte_len < value_byte_len)
        acc = value->buf_ptr[value_idx--];

    while (result_idx >= 0)
    {
        // Add the next value byte to the accumulator
        value_byte  = value->buf_ptr[value_idx--];
        acc         = (acc << 8) | value_byte;

        // Remove a shifted result byte
        result_byte = acc >> bit_shift;
        acc_mask    = (0x1 << bit_shift) - 1;
        acc         = acc & acc_mask;
        result->buf_ptr[result_idx--] = result_byte;
    }

    return RC_NO_ERROR;
}

// Update dividend in place with "dividend - (divisor * quotient)",
// where quotient is "quot_byte * 2^(8 * quot_byte_shift)".  Note that
// this routine requires "divisor * quotient <= dividend", i.e. the quotient
// MUST be such that the dividend does not go negative!

static void subtract_product(pka_operand_t *dividend,
                             pka_operand_t *divisor,
                             uint32_t       quot_byte,
                             uint32_t       quot_byte_shift)
{
    uint32_t divisor_byte_len, dividend_byte_len, carry, borrow;
    uint32_t divisor_byte, dividend_byte, product, prod_byte, result_byte;
    uint32_t byte_cnt;
    uint8_t *divisor_byte_ptr, *dividend_byte_ptr;

    divisor_byte_len  = divisor->actual_len;
    dividend_byte_len = dividend->actual_len;
    if ((dividend_byte_len == divisor_byte_len) && (quot_byte == 1))
    {
        // Optimize the case where dividend == divisor.
        if (pki_compare(dividend, divisor) == RC_COMPARE_EQUAL)
        {
            memset(dividend->buf_ptr, 0, dividend->actual_len);
            dividend->actual_len = 1;
            return;
        }
    }

    divisor_byte_ptr  = &divisor->buf_ptr[0];
    dividend_byte_ptr = &dividend->buf_ptr[quot_byte_shift];

    // Now multiply divisor by quot_byte and subtract it from dividend.
    // This code proceeds from least significant byte to most significant
    // byte.
    carry  = 0;
    borrow = 0;
    for (byte_cnt = 0; byte_cnt < divisor_byte_len; byte_cnt++)
    {
        divisor_byte  = *divisor_byte_ptr;
        dividend_byte = *dividend_byte_ptr;

        // Note that since quot_byte, divisor_byte and carry in are all <= 255,
        // this implies that product <= 0xFF00, so carry out <= 255.
        product   = (quot_byte * divisor_byte) + carry;
        prod_byte = (product & 0xFF) + borrow;
        carry     = product >> 8;
        if (prod_byte <= dividend_byte)
        {
            result_byte = dividend_byte - prod_byte;
            borrow      = 0;
        }
        else
        {
            result_byte = (256 + dividend_byte) - prod_byte;
            borrow      = 1;
        }

        *dividend_byte_ptr = result_byte;
        divisor_byte_ptr++;
        dividend_byte_ptr++;
    }

    if ((carry != 0) || (borrow != 0))
    {
        dividend_byte = *dividend_byte_ptr;
        prod_byte     = carry + borrow;
        PKA_ASSERT(prod_byte <= dividend_byte);
        *dividend_byte_ptr = dividend_byte - prod_byte;
    }

    // trim result of leading zeros to have the correct length.
    adjust_actual_len(dividend);
}

// This function returns the most significant two bytes of the operand, as an
// integer in the range 0x100 .. 0xFFFF.  If the operand only has a length
// of 1, return this byte * 0x100 (i.e. act as if the length was 2, with the
// extra byte being zero).

static uint32_t get_two_ms_bytes(pka_operand_t *operand)
{
    uint32_t result, byte_len, msb_idx, next_idx;

    byte_len = operand_byte_len(operand);
    msb_idx  = get_msb_idx(operand);

    PKA_ASSERT(byte_len != 0);
    result = operand->buf_ptr[msb_idx] << 8;
    if (byte_len <= 1)
        return result;

    next_idx = msb_idx - 1;
    result += operand->buf_ptr[next_idx];
    return result;
}

// This function returns the most significant three bytes of the operand, as an
// integer in the range 0x10000 .. 0xFFFFFF.  If the operand only has a length
// of 1, return this byte * 0x10000 (i.e. act as if the length was 3, with the
// extra bytes being zero).  Similarly, if the operand length is 2, then return
// the most significant two bytes * 0x100.

static uint32_t get_three_ms_bytes(pka_operand_t *operand,
                                   uint32_t       two_ms_bytes)
{
  uint32_t result, byte_len, msb_idx, next_idx;

    byte_len = operand_byte_len(operand);
    result   = two_ms_bytes << 8;
    if (byte_len < 3)
        return result;

    msb_idx = get_msb_idx(operand);
    next_idx = msb_idx - 2;

    result += operand->buf_ptr[next_idx];
    return result;
}

static pka_cmp_code_t cmp_ms_dividend_to_ms_divisor(pka_operand_t *dividend,
                                                    pka_operand_t *divisor)
{
    uint32_t divisor_byte_len, divisor_msb_idx, dividend_msb_idx, byte_cnt;
    uint8_t *divisor_ptr, *dividend_ptr, divisor_byte, dividend_byte;

    divisor_byte_len = operand_byte_len(divisor);
    divisor_msb_idx  = get_msb_idx(divisor);
    dividend_msb_idx = get_msb_idx(dividend);

    divisor_ptr  = &divisor->buf_ptr[divisor_msb_idx];
    dividend_ptr = &dividend->buf_ptr[dividend_msb_idx];

    // Compare the most significant "divisor_byte_len" bytes of the dividend
    // to the divisor, starting at the most significant bytes.
    for (byte_cnt = 0; byte_cnt < divisor_byte_len; byte_cnt++)
    {
        divisor_byte  = *divisor_ptr;
        dividend_byte = *dividend_ptr;
        if (dividend_byte < divisor_byte)
            return RC_LEFT_IS_SMALLER;
        else if (dividend_byte > divisor_byte)
            return RC_RIGHT_IS_SMALLER;

        divisor_ptr--;
        dividend_ptr--;
    }

    return RC_COMPARE_EQUAL;
}

static void add_quot_byte(pka_operand_t *quotient,
                          uint32_t       quot_byte,
                          uint32_t       quot_byte_shift)
{
    uint32_t idx, old_quot_byte, new_quot_byte;

    PKA_ASSERT(quot_byte_shift < quotient->actual_len);
    idx = quot_byte_shift;

    // Add carry into subsequently more significant bytes?
    old_quot_byte = quotient->buf_ptr[idx];
    new_quot_byte = old_quot_byte + quot_byte;
    PKA_ASSERT(new_quot_byte <= 255);
    quotient->buf_ptr[idx] = new_quot_byte;
}

static void bignum_div_mod(pka_operand_t *dividend,
                           pka_operand_t *divisor,
                           pka_operand_t *quotient)
{
    pka_cmp_code_t cmp;
    uint32_t divisor_len, ms_divisor, ms_dividend, quot_byte_shift, quot_byte;

    PKA_ASSERT(dividend->actual_len <= (operand_byte_len(dividend) + 4));
    divisor_len = operand_byte_len(divisor);
    ms_divisor  = get_two_ms_bytes(divisor);
    PKA_ASSERT((0x100 <= ms_divisor) && (ms_divisor <= 0xFFFF));

    while (pki_compare(dividend, divisor) != RC_LEFT_IS_SMALLER)
    {
        // Note that quot_byte_idx MUST be >= 0, as a consequence of the test
        // above showing that divisor <= dividend.
        ms_dividend     = get_two_ms_bytes(dividend);
        quot_byte_shift = operand_byte_len(dividend) - divisor_len;
        if (ms_dividend == ms_divisor)
            // Compare the "divisor_len" most significant bytes of dividend
            // to the divisor.
            cmp = cmp_ms_dividend_to_ms_divisor(dividend, divisor);
        else if (ms_dividend < ms_divisor)
            cmp = RC_LEFT_IS_SMALLER;
        else
            cmp = RC_RIGHT_IS_SMALLER;

        if (cmp == RC_LEFT_IS_SMALLER)
        {
            quot_byte_shift--;
            ms_dividend = get_three_ms_bytes(dividend, ms_dividend);
            quot_byte   = ms_dividend / (ms_divisor + 1);
        }
        else if ((cmp == RC_COMPARE_EQUAL) || (ms_dividend == ms_divisor))
            quot_byte = 1;
        else  // cmp == RC_RIGHT_IS_SMALLER, which implies ms_divisor < 0xFFFF.
            quot_byte = ms_dividend / (ms_divisor + 1);

        // quot_byte here is guaranteed to be <= the "real" quotient byte,
        // and probably not more than 1 less than the "real" quotient byte.
        PKA_ASSERT((1 <= quot_byte) && (quot_byte <= 255));
        subtract_product(dividend, divisor, quot_byte, quot_byte_shift);

        add_quot_byte(quotient, quot_byte, quot_byte_shift);
    }
}

static void divide_with_remainder(pka_operand_t *dividend,
                                  pka_operand_t *divisor,
                                  pka_operand_t *quotient,
                                  pka_operand_t *remainder)
{
    pka_operand_t  remain, quot;
    pka_cmp_code_t comparison;
    uint32_t       quot_buf_len, dividend_byte_len, divisor_byte_len;
    uint32_t       dividend_uint32, divisor_uint32;
    uint8_t        remain_buf[MAX_BUF], quot_buf[MAX_BUF];
    uint8_t        big_endian;

    PKA_ASSERT(dividend->big_endian == divisor->big_endian);
    big_endian = dividend->big_endian;

    comparison = pki_compare(dividend, divisor);
    if (comparison == RC_LEFT_IS_SMALLER)
    {
        if (quotient != NULL)
            set_operand(quotient, 0);

        if (remainder != NULL)
            copy_operand(dividend, remainder);

        return;
    }
    else if (comparison == RC_COMPARE_EQUAL)
    {
        if (quotient != NULL)
            set_operand(quotient,  1);

        if (remainder != NULL)
            set_operand(remainder, 0);

        return;
    }
    else if (is_one(divisor))
    {
        if (quotient != NULL)
            copy_operand(dividend, quotient);

        if (remainder != NULL)
            set_operand(remainder, 0);

        return;
    }

    dividend_byte_len = operand_byte_len(dividend);
    divisor_byte_len  = operand_byte_len(divisor);
    if ((dividend_byte_len < 4) && (divisor_byte_len < 4))
    {
        dividend_uint32 = operand_to_uint32(dividend);
        divisor_uint32  = operand_to_uint32(divisor);
        if (quotient != NULL)
            set_operand(quotient,  dividend_uint32 / divisor_uint32);

        if (remainder != NULL)
            set_operand(remainder, dividend_uint32 % divisor_uint32);

        return;
    }

    quot_buf_len = (operand_byte_len(dividend) + 1) -
                    operand_byte_len(divisor);
    init_operand(&remain,  remain_buf, dividend_byte_len, big_endian);
    init_operand(&quot,    quot_buf,   quot_buf_len,      big_endian);
    copy_operand(dividend, &remain);
    set_operand(&quot,     0);
    quot.actual_len = quot_buf_len;  // Needed ??

    bignum_div_mod(&remain, divisor, &quot);

    if (quotient != NULL)
        copy_operand(&quot,   quotient);

    if (remainder != NULL)
        copy_operand(&remain, remainder);
}

pka_result_code_t pki_divide(pka_operand_t *value,
                             pka_operand_t *divisor,
                             pka_operand_t *quotient_ptr,
                             pka_operand_t *remainder_ptr)
{
    divide_with_remainder(value, divisor, quotient_ptr, remainder_ptr);
    return RC_NO_ERROR;
}

pka_result_code_t pki_modulo(pka_operand_t *value,
                             pka_operand_t *modulus,
                             pka_operand_t *result_ptr)
{
    pka_operand_t quotient;
    uint8_t       quot_buf[MAX_BUF];

    PKA_ASSERT(value->big_endian == modulus->big_endian);

    init_operand(&quotient, quot_buf, MAX_BUF, value->big_endian);
    divide_with_remainder(value, modulus, &quotient, result_ptr);
    return RC_NO_ERROR;
}

static uint8_t get_bit(pka_operand_t *operand, uint32_t bit_idx)
{
    uint32_t byte_idx, bit_in_byte_idx;
    uint8_t  byte, bit;

    // PKA_ASSERT((bit_idx / 8) <= (operand->actual_len - 1));
    bit_in_byte_idx = bit_idx & 7;
    byte_idx = bit_idx / 8;

    byte = operand->buf_ptr[byte_idx];
    bit  = (byte >> bit_in_byte_idx) & 0x1;
    return bit;
}

pka_result_code_t pki_mod_multiply(pka_operand_t *value,
                                   pka_operand_t *multiplier,
                                   pka_operand_t *modulus,
                                   pka_operand_t *result)
{
    pka_operand_t product;
    pka_result_code_t rc;
    uint8_t       bufA[MAX_BUF];

    PKA_ASSERT(value->big_endian      == modulus->big_endian);
    PKA_ASSERT(multiplier->big_endian == modulus->big_endian);

    init_operand(&product, bufA, MAX_BUF, value->big_endian);

    rc = pki_multiply(value, multiplier, &product);
    if (rc != RC_NO_ERROR)
        return rc;

    rc = pki_modulo(&product, modulus, result);
    return rc;
}

pka_result_code_t pki_mod_shift_right(pka_operand_t *value,
				      uint32_t       shift_cnt,
				      pka_operand_t *modulus,
				      pka_operand_t *result)
{
    pka_result_code_t rc;
    pka_operand_t     tmp;
    uint8_t           bufA[MAX_BUF];

    PKA_ASSERT(value->big_endian == modulus->big_endian);
    init_operand(&tmp, bufA, MAX_BUF, value->big_endian);

    rc = pki_shift_right(value, shift_cnt, &tmp);
    if (rc != RC_NO_ERROR)
        return rc;

    rc = pki_modulo(&tmp, modulus, result);
    return rc;
}

pka_result_code_t pki_mod_exp(pka_operand_t *value,
                              pka_operand_t *exponent,
                              pka_operand_t *modulus,
                              pka_operand_t *result)
{
    pka_operand_t base, base_sqrd;
    uint32_t      exp_bit_len, exp_bit_idx;
    uint8_t       base_buf[MAX_BUF], base_sqrd_buf[MAX_BUF], result_is_1, bit;
    pka_result_code_t rc;

    PKA_ASSERT(value->big_endian    == modulus->big_endian);
    PKA_ASSERT(exponent->big_endian == modulus->big_endian);

    if (pki_compare(value, modulus) != RC_LEFT_IS_SMALLER)
        return RC_OPERAND_VALUE_ERR;

    // Copy msg into base and get the bit_len of the exponent.
    init_operand(&base,      base_buf,      MAX_BUF, value->big_endian);
    init_operand(&base_sqrd, base_sqrd_buf, MAX_BUF, value->big_endian);
    copy_operand(value, &base);
    exp_bit_len = operand_bit_len(exponent);

    // Initialize result to be 1.
    result_is_1 = 1;

    for (exp_bit_idx = 0; exp_bit_idx < exp_bit_len; exp_bit_idx++)
    {
        bit = get_bit(exponent, exp_bit_idx);
        if (bit != 0)
        {
            // Multiply by result by base.  Special case for the first
            // multiplication, where result is one.
            if (result_is_1)
            {
                copy_operand(&base, result);
                result_is_1 = 0;
            }
            else
                rc = pki_mod_multiply(result, &base, modulus, result);
        }

        // Square base.
        rc = pki_mod_multiply(&base, &base, modulus, &base_sqrd);
        copy_operand(&base_sqrd, &base);
    }

    return RC_NO_ERROR;
}

static pka_result_code_t pki_mod_exp_no_check(pka_operand_t *value,
                                              pka_operand_t *exponent,
                                              pka_operand_t *modulus,
                                              pka_operand_t *result)
{
    pka_operand_t base, base_sqrd;
    uint32_t      exp_bit_len, exp_bit_idx;
    uint8_t       base_buf[MAX_BUF], base_sqrd_buf[MAX_BUF], result_is_1, bit;
    pka_result_code_t rc;

    PKA_ASSERT(value->big_endian    == modulus->big_endian);
    PKA_ASSERT(exponent->big_endian == modulus->big_endian);

    // Copy msg into base and get the bit_len of the exponent.
    init_operand(&base,      base_buf,      MAX_BUF, value->big_endian);
    init_operand(&base_sqrd, base_sqrd_buf, MAX_BUF, value->big_endian);
    copy_operand(value, &base);
    exp_bit_len = operand_bit_len(exponent);

    // Initialize result to be 1.
    result_is_1 = 1;

    for (exp_bit_idx = 0; exp_bit_idx < exp_bit_len; exp_bit_idx++)
    {
        bit = get_bit(exponent, exp_bit_idx);
        if (bit != 0)
        {
            // Multiply by result by base.  Special case for the first
            // multiplication, where result is one.
            if (result_is_1)
            {
                copy_operand(&base, result);
                result_is_1 = 0;
            }
            else
                rc = pki_mod_multiply(result, &base, modulus, result);
        }

        // Square base.
        rc = pki_mod_multiply(&base, &base, modulus, &base_sqrd);
        copy_operand(&base_sqrd, &base);
    }

    return RC_NO_ERROR;
}

pka_result_code_t pki_mod_exp_with_crt(pka_operand_t *value,
                                       pka_operand_t *p,
                                       pka_operand_t *q,
                                       pka_operand_t *d_p,
                                       pka_operand_t *d_q,
                                       pka_operand_t *qinv,
                                       pka_operand_t *result_ptr)
{
    pka_operand_t m1, m2, abs_diff, mdiff, h, h_times_q;
    uint8_t       bufA[MAX_BUF], bufB[MAX_BUF], bufC[MAX_BUF], bufD[MAX_BUF];
    uint8_t       bufE[MAX_BUF], bufF[MAX_BUF], m1_ge_m2;
    pka_result_code_t rc;

    PKA_ASSERT(value->big_endian == p->big_endian);
    PKA_ASSERT(q->big_endian     == p->big_endian);
    PKA_ASSERT(d_p->big_endian   == q->big_endian);
    PKA_ASSERT(d_q->big_endian   == q->big_endian);
    PKA_ASSERT(qinv->big_endian  == value->big_endian);
    // PKA_ASSERT(d_q < q < p);  Assert(d_p < p);  Assert(qinv < p);
    // PKA_ASSERT(c < p*q);
    PKA_ASSERT(pki_compare(q, p) == RC_LEFT_IS_SMALLER);

    init_operand(&m1,        bufA, MAX_BUF, value->big_endian);
    init_operand(&m2,        bufB, MAX_BUF, value->big_endian);
    init_operand(&abs_diff,  bufC, MAX_BUF, value->big_endian);
    init_operand(&mdiff,     bufD, MAX_BUF, value->big_endian);
    init_operand(&h,         bufE, MAX_BUF, value->big_endian);
    init_operand(&h_times_q, bufF, MAX_BUF, value->big_endian);

    // Calculate "m1 = c^d_p mod p", "m2 = c^d_q mod q",
    // "h = (q_inv * (m1 - m2)) mod p" and finally the result is:
    // "result = m2 + h * q".  Note that m1, m2 and abs(m1-m2) are all < p.
    rc       = pki_mod_exp_no_check(value, d_p, p, &m1);
    rc       = pki_mod_exp_no_check(value, d_q, q, &m2);
    m1_ge_m2 = pki_compare(&m1, &m2) != RC_LEFT_IS_SMALLER;

    if (m1_ge_m2)
        rc = pki_subtract(&m1, &m2, &mdiff);
    else
    {
        rc = pki_subtract(&m2, &m1,       &abs_diff);
        rc = pki_subtract(p,   &abs_diff, &mdiff);
    }

    rc = pki_mod_multiply(&mdiff, qinv, p, &h);
    rc = pki_multiply(&h, q, &h_times_q);
    rc = pki_add(&m2, &h_times_q, result_ptr);
    return RC_NO_ERROR;
}

pka_result_code_t pki_mod_inverse(pka_operand_t *value,
                                  pka_operand_t *modulus,
                                  pka_operand_t *result_ptr)
{
    pka_operand_t a, b, quot, abs_x, last_abs_x, temp_abs_x;
    pka_operand_t abs_prod, temp, remain;
    int32_t       x_sign, last_x_sign, temp_x_sign;
    uint8_t       bufA[MAX_BUF], bufB[MAX_BUF], bufC[MAX_BUF], bufD[MAX_BUF];
    uint8_t       bufE[MAX_BUF], bufF[MAX_BUF], bufG[MAX_BUF], bufH[MAX_BUF];
    uint8_t       bufI[MAX_BUF];
    pka_result_code_t rc;
    pka_cmp_code_t    comparison;

    PKA_ASSERT(value->big_endian == modulus->big_endian);

    init_operand(&a,          bufA, MAX_BUF, value->big_endian);
    init_operand(&b,          bufB, MAX_BUF, value->big_endian);
    init_operand(&quot,       bufC, MAX_BUF, value->big_endian);
    init_operand(&abs_x,      bufD, MAX_BUF, value->big_endian);
    init_operand(&last_abs_x, bufE, MAX_BUF, value->big_endian);
    init_operand(&temp_abs_x, bufF, MAX_BUF, value->big_endian);
    init_operand(&abs_prod,   bufG, MAX_BUF, value->big_endian);
    init_operand(&temp,       bufH, MAX_BUF, value->big_endian);
    init_operand(&remain,     bufI, MAX_BUF, value->big_endian);

    comparison = pki_compare(value, modulus);
    if (comparison != RC_LEFT_IS_SMALLER)
        rc = pki_modulo(value, modulus, &a);
    else
        copy_operand(value, &a);

    copy_operand(modulus, &b);
    if (is_zero(&a) || is_zero(&b))
    {
        PKA_ERROR(PKA_TESTS,  "pki_mod_inverse called with zero operands\n");
        return RC_NO_MODULAR_INVERSE;
    }

    // Find x such that a*x - q*b = 1 using the extended euclidean algorithm.
    set_operand(&last_abs_x, 1);
    set_operand(&abs_x,      0);
    last_x_sign = 1;
    x_sign      = 0;

    while (! is_zero(&b))
    {
        divide_with_remainder(&a, &b, &quot, &remain);
        copy_operand(&b,      &a);           // a = b;
        copy_operand(&remain, &b);           // b = remainder;
        copy_operand(&abs_x,  &temp_abs_x);  // temp_abs_x = abs_x;
        temp_x_sign = x_sign;

        // Calculate the next x as "x = last_x - quot * x".  The complications
        // arise, since the bignum arithmetic does not support negative values
        // and we are also careful to prevent multiplication or addition by 0.
        if ((x_sign == 0) || is_zero(&quot))
        {
            copy_operand(&last_abs_x, &abs_x);
            x_sign = last_x_sign;
        }
        else
        {
            rc = pki_multiply(&quot, &abs_x, &abs_prod);
            if (last_x_sign == 0)
            {
                copy_operand(&abs_prod, &abs_x);
                x_sign = -1 * x_sign;
            }
            else if (x_sign != last_x_sign)
            {
                rc     = pki_add(&last_abs_x, &abs_prod, &abs_x);
                x_sign = last_x_sign;
            }
            else
            {
                comparison = pki_compare(&abs_prod, &last_abs_x);
                if (comparison == RC_COMPARE_EQUAL)
                {
                    set_operand(&abs_x, 0);
                    x_sign = 0;
                }
                else if (comparison == RC_LEFT_IS_SMALLER)
                {
                    rc = pki_subtract(&last_abs_x, &abs_prod, &abs_x);
                    // x_sign doesn't change in this case.
                }
                else
                {
                    rc     = pki_subtract(&abs_prod, &last_abs_x, &abs_x);
                    x_sign = -1 * x_sign;
                }
            }
        }

        copy_operand(&temp_abs_x, &last_abs_x);  // last_abs_x  = temp_abs_x;
        last_x_sign = temp_x_sign;
    }

    if (last_x_sign == -1)
        rc = pki_subtract(modulus, &last_abs_x, result_ptr);
    else
        copy_operand(&last_abs_x, result_ptr);

    // Check that inverse is in fact correct:
    rc = pki_mod_multiply(value, result_ptr, modulus, &abs_prod);
    if (is_one(&abs_prod))
        return RC_NO_ERROR;
    else
        return RC_NO_MODULAR_INVERSE;
}

pka_result_code_t pki_mod_square_root(pka_operand_t *value,
                                      pka_operand_t *modulus,
                                      pka_operand_t *result)
{
    pka_operand_t one, five, modulus_plus_1, modulus_minus_5, exponent;
    pka_operand_t value_times_2, v, v_squared, temp1, temp2, temp3, product;
    pka_operand_t modulus_minus_1;
    pka_result_code_t rc;
    uint8_t       bufA[MAX_BUF], bufB[MAX_BUF], bufC[MAX_BUF], bufD[MAX_BUF];
    uint8_t       bufE[MAX_BUF], bufF[MAX_BUF], bufG[MAX_BUF], bufH[MAX_BUF];
    uint8_t       bufI[MAX_BUF], bufJ[MAX_BUF];
    uint8_t       lsb_byte, modulus_mod4, modulus_mod8, big_endian;

    PKA_ASSERT(value->big_endian == modulus->big_endian);
    big_endian = value->big_endian;

    // *TBD* Add special cases for value mod modulus == 0 and modulus == 2.
    // Also check that value^((modulus - 1)/2) mod modulus = 1.
    init_operand(&one,             bufA, 8,       big_endian);
    init_operand(&modulus_minus_1, bufB, MAX_BUF, big_endian);
    init_operand(&exponent,        bufC, MAX_BUF, big_endian);
    set_operand(&one, 1);

    rc = pki_subtract(modulus, &one, &modulus_minus_1);
    rc = pki_shift_right(&modulus_minus_1, 1, &exponent);
    rc = pki_mod_exp(value, &exponent, modulus, result);

    if (! is_one(result))
    {
        PKA_ERROR(PKA_TESTS,  "value^((modulus - 1)/2) mod modulus != 1\n");
        print_operand("value    = ", value,     "\n");
        print_operand("exponent = ", &exponent, "\n");
        print_operand("modulus  = ", modulus,   "\n");
        print_operand("result   = ", result,    "\n");
        PKA_ERROR(PKA_TESTS,  "return RC_NO_MODULAR_INVERSE\n");
        return RC_NO_MODULAR_INVERSE;
    }

    // Three cases (a) modulus mod 4 = 3, (b) modulus mod 8 = 5 and
    // (c) modulus mod 8 = 1.
    lsb_byte     = modulus->buf_ptr[0];
    modulus_mod4 = lsb_byte & 0x3;
    modulus_mod8 = lsb_byte & 0x7;

    if (modulus_mod4 == 3)
    {
        init_operand(&one,            bufA, 8,       big_endian);
        init_operand(&modulus_plus_1, bufB, MAX_BUF, big_endian);
        init_operand(&exponent,       bufC, MAX_BUF, big_endian);
        set_operand(&one, 1);

        rc = pki_add(modulus, &one, &modulus_plus_1);
        rc = pki_shift_right(&modulus_plus_1, 2, &exponent);
        rc = pki_mod_exp(value, &exponent, modulus, result);
    }
    else if (modulus_mod8 == 5)
    {
        init_operand(&one,             bufA, 8,       big_endian);
        init_operand(&five,            bufB, 8,       big_endian);
        init_operand(&modulus_minus_5, bufC, MAX_BUF, big_endian);
        init_operand(&exponent,        bufD, MAX_BUF, big_endian);
        init_operand(&value_times_2,   bufE, MAX_BUF, big_endian);
        init_operand(&v,               bufF, MAX_BUF, big_endian);
        init_operand(&v_squared,       bufG, MAX_BUF, big_endian);
        init_operand(&temp1,           bufH, MAX_BUF, big_endian);
        init_operand(&temp2,           bufI, MAX_BUF, big_endian);
        init_operand(&temp3,           bufJ, MAX_BUF, big_endian);
        set_operand(&one,  1);
        set_operand(&five, 5);

        rc = pki_subtract(modulus, &five, &modulus_minus_5);
        rc = pki_shift_right(&modulus_minus_5, 3, &exponent);
        rc = pki_shift_left(value, 1, &value_times_2);
        rc = pki_mod_exp(&value_times_2, &exponent, modulus, &v);
        rc = pki_mod_multiply(&v, &v, modulus, &v_squared);
        rc = pki_mod_multiply(&value_times_2, &v_squared, modulus, &temp1);
        rc = pki_subtract(&temp1, &one, &temp2);
        rc = pki_mod_multiply(value, &v, modulus, &temp3);
        rc = pki_mod_multiply(&temp2, &temp3, modulus, result);
    }
    else if (modulus_mod8 == 1)
    {
        // Yet to be implemented *TBD*
        abort();
    }
    else
        abort();

    // Verify the result.
    init_operand(&product, bufA, MAX_BUF, big_endian);
    rc = pki_mod_multiply(result, result, modulus, &product);
    // print_operand("\n  result  = ", result, "\n");
    // print_operand("  modulus = ", modulus,  "\n");
    // print_operand("  product = ", &product, "\n");
    // print_operand("  value   = ", value,    "\n\n");

    if (pki_compare(value, &product) == RC_COMPARE_EQUAL)
        return RC_NO_ERROR;
    else
    {
        PKA_ERROR(PKA_TESTS,  "return No Sqrt\n");
        return RC_NO_MODULAR_INVERSE;
    }
}

pka_result_code_t pki_mod_add(pka_operand_t *value,
                              pka_operand_t *addend,
                              pka_operand_t *modulus,
                              pka_operand_t *result)
{
    pka_operand_t     sum;
    pka_result_code_t rc;
    uint8_t           bufA[MAX_BUF];

    PKA_ASSERT(value->big_endian  == modulus->big_endian);
    PKA_ASSERT(addend->big_endian == modulus->big_endian);

    init_operand(&sum, bufA, MAX_BUF, value->big_endian);

    rc = pki_add(value, addend, &sum);
    adjust_actual_len(&sum);
    if (pki_compare(&sum, modulus) == RC_LEFT_IS_SMALLER)
    {
        result->actual_len = sum.actual_len;
        memcpy(result->buf_ptr, sum.buf_ptr, result->actual_len);
        return RC_NO_ERROR;
    }

    rc = pki_subtract(&sum, modulus, result);
    adjust_actual_len(result);
    return rc;
}

pka_result_code_t pki_mod_subtract(pka_operand_t *value,
                                   pka_operand_t *subtrahend,
                                   pka_operand_t *modulus,
                                   pka_operand_t *result)
{
    pka_operand_t     reversed_diff;
    pka_result_code_t rc;
    pka_cmp_code_t    comparison;
    uint8_t           bufA[MAX_BUF];

    PKA_ASSERT(value->big_endian       == modulus->big_endian);
    PKA_ASSERT(subtrahend->big_endian  == modulus->big_endian);

    init_operand(&reversed_diff, bufA, MAX_BUF, value->big_endian);

    comparison = pki_compare(value, subtrahend);
    if (comparison == RC_COMPARE_EQUAL)
      return RC_INVALID_ARGUMENT;
    else if (comparison == RC_RIGHT_IS_SMALLER)
        return pki_subtract(value, subtrahend, result);

    // result is -diff mod modulus which is the same as modulus - diff;
    rc = pki_subtract(subtrahend, value, &reversed_diff);
    rc = pki_subtract(modulus, &reversed_diff, result);

    return RC_NO_ERROR;
}

static void copy_ecc_point(ecc_point_t *original, ecc_point_t *copy)
{
    copy_operand(&original->x, &copy->x);
    copy_operand(&original->y, &copy->y);
}

static pka_result_code_t ecc_double(ecc_curve_t *curve,
                                    ecc_point_t *pointA,
                                    ecc_point_t *result)
{
    pka_operand_t x_squared, temp2, temp3, dbl_y, dbl_y_inv, slope;
    pka_operand_t plus_a, s_squared, dbl_x, ac_xdiff, product;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF], bufH[MAX_ECC_BUF], bufI[MAX_ECC_BUF];
    uint8_t       bufJ[MAX_ECC_BUF], bufK[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    PKA_ASSERT(curve->p.big_endian == curve->a.big_endian);
    PKA_ASSERT(curve->p.big_endian == curve->b.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->y.big_endian);
    big_endian = curve->p.big_endian;

    init_operand(&x_squared, bufA, MAX_ECC_BUF, big_endian);
    init_operand(&temp2,     bufB, MAX_ECC_BUF, big_endian);
    init_operand(&temp3,     bufC, MAX_ECC_BUF, big_endian);
    init_operand(&plus_a,    bufD, MAX_ECC_BUF, big_endian);
    init_operand(&dbl_y,     bufE, MAX_ECC_BUF, big_endian);
    init_operand(&dbl_y_inv, bufF, MAX_ECC_BUF, big_endian);
    init_operand(&slope,     bufG, MAX_ECC_BUF, big_endian);
    init_operand(&s_squared, bufH, MAX_ECC_BUF, big_endian);
    init_operand(&dbl_x,     bufI, MAX_ECC_BUF, big_endian);
    init_operand(&ac_xdiff,  bufJ, MAX_ECC_BUF, big_endian);
    init_operand(&product,   bufK, MAX_ECC_BUF, big_endian);

    // ECC point doubling is accomplished using the following formulas:
    // x_squared     = (pointA->x * pointA->x)    mod p;
    // x_sqrd_times3 = (3 * x_squared)            mod p;
    // numer         = (x_sqrd_times3 + curve->a) mod p;
    // dbl_x         = (pointA->x + pointA->x)    mod p;
    // dbl_y         = (pointA->y + pointA->y)    mod p;
    // slope         = (numer / dbl_y)            mod p;
    // s_squared     = (slope * slope)            mod p;
    // result->x     = (s_squared - dbl_x)        mod p;
    // diff          = (pointA->x - result->x)    mod p;
    // product       = (slope * diff)             mod p;
    // result->y     = (product - pointA->y)      mod p;
    rc = pki_mod_multiply(&pointA->x, &pointA->x, &curve->p, &x_squared);
    rc = pki_mod_add(&x_squared,      &x_squared, &curve->p, &temp2);
    rc = pki_mod_add(&temp2,          &x_squared, &curve->p, &temp3);
    rc = pki_mod_add(&temp3,          &curve->a,  &curve->p, &plus_a);
    rc = pki_mod_add(&pointA->y,      &pointA->y, &curve->p, &dbl_y);
    rc = pki_mod_inverse(&dbl_y,              &curve->p, &dbl_y_inv);
    rc = pki_mod_multiply(&plus_a,    &dbl_y_inv, &curve->p, &slope);
    rc = pki_mod_multiply(&slope,     &slope,     &curve->p, &s_squared);
    rc = pki_mod_add(&pointA->x,      &pointA->x, &curve->p, &dbl_x);
    rc = pki_mod_subtract(&s_squared, &dbl_x,     &curve->p, &result->x);
    rc = pki_mod_subtract(&pointA->x, &result->x, &curve->p, &ac_xdiff);
    rc = pki_mod_multiply(&slope,     &ac_xdiff,  &curve->p, &product);
    rc = pki_mod_subtract(&product,   &pointA->y, &curve->p, &result->y);
    return RC_NO_ERROR;
}

// The following three functions implement Elliptic Curve point multiplication
// for curves in Montgomery form in support of the ECDH key exchange
// algorithm.  This multiplication only uses the x-coordinate of the point,
// even though it looks like both coordinates are involved.  This is because
// instead of using affine coordinates, projective coordinates are used,
// which requires keeping track of the x-coordinate and the z-coordinate.
// For this purpose the ecc_point_t data structure is used to pass the x and z
// coordinates - which are still named x and y - which could be confusing.

static pka_result_code_t pki_mont_ecdh_double(ecc_mont_curve_t *curve,
                                              ecc_point_t      *point,
                                              ecc_point_t      *result)
{
    pka_operand_t v_sum, v_diff, v_sum_sqrd, v_diff_sqrd, U_diff, tmp1, tmp2;
    pka_operand_t A_sub_2, A2_div_4;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF], bufH[MAX_ECC_BUF], bufI[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    big_endian = curve->p.big_endian;
    PKA_ASSERT(big_endian == curve->A.big_endian);
    PKA_ASSERT(big_endian == point->x.big_endian);
    PKA_ASSERT(big_endian == point->y.big_endian);

    init_operand(&v_sum,       bufA, MAX_ECC_BUF, big_endian);
    init_operand(&v_diff,      bufB, MAX_ECC_BUF, big_endian);
    init_operand(&v_sum_sqrd,  bufC, MAX_ECC_BUF, big_endian);
    init_operand(&v_diff_sqrd, bufD, MAX_ECC_BUF, big_endian);
    init_operand(&U_diff,      bufE, MAX_ECC_BUF, big_endian);
    init_operand(&tmp1,        bufF, MAX_ECC_BUF, big_endian);
    init_operand(&tmp2,        bufG, MAX_ECC_BUF, big_endian);
    init_operand(&A_sub_2,     bufH, MAX_ECC_BUF, big_endian);
    init_operand(&A2_div_4,    bufI, MAX_ECC_BUF, big_endian);

    // ECC Montgomery point doubling is done using the following formulas:
    // A24       = (A - 2) / 4;
    // U_diff    = ((x + z)^2 - (x - z)^2)                mod p
    // result->x = ((x + z)^2 * (x - z)^2)                mod p
    // result->z = ((A24 * Udiff) + (x + z)^2) * U_diff   mod p
    //
    // Or in more detail:
    // v_sum       = (point->x     + point->z)    mod p;
    // v_diff      = (point->x     - point->z)    mod p;
    // v_sum_sqrd  = (v_sum        * v_sum)       mod p;
    // v_diff_sqrd = (v_diff       * v_diff)      mod p;
    // U_diff      = (v_sum_sqrd   - v_diff_sqrd) mod p;
    // tmp1        = ((A - 2) / 4) * U_diff       mod p;
    // tmp2        = (tmp1         + v_sum_sqrd)  mod p;
    // result->x   = (v_sum_sqrd   * v_diff_sqrd) mod p;
    // result->z   = (tmp2         * U_diff)      mod p;

    rc = pki_mod_subtract(&curve->A,    &TWO,         &curve->p, &A_sub_2);
    rc = pki_shift_right(&A_sub_2,      2,                       &A2_div_4);

    rc = pki_mod_add(&point->x,         &point->y,    &curve->p, &v_sum);
    rc = pki_mod_subtract(&point->x,    &point->y,    &curve->p, &v_diff);
    rc = pki_mod_multiply(&v_sum,       &v_sum,       &curve->p, &v_sum_sqrd);
    rc = pki_mod_multiply(&v_diff,      &v_diff,      &curve->p, &v_diff_sqrd);
    rc = pki_mod_subtract(&v_sum_sqrd,  &v_diff_sqrd, &curve->p, &U_diff);
    rc = pki_mod_multiply(&A2_div_4,    &U_diff,      &curve->p, &tmp1);
    rc = pki_mod_add(&tmp1,             &v_sum_sqrd,  &curve->p, &tmp2);
    rc = pki_mod_multiply(&v_sum_sqrd,  &v_diff_sqrd, &curve->p, &result->x);
    rc = pki_mod_multiply(&tmp2,        &U_diff,      &curve->p, &result->y);
    return RC_NO_ERROR;
}

pka_result_code_t pki_mont_ecdh_add(ecc_mont_curve_t *curve,
                                    ecc_point_t      *pointP,
                                    ecc_point_t      *pointQ,
                                    pka_operand_t    *point_x,
                                    ecc_point_t      *result_pt)
{
    pka_operand_t vp_sum, vq_sum, vp_diff, vq_diff, tmp1, tmp2;
    pka_operand_t tmp1_add_tmp2, tmp1_sub_tmp2, tmp3, tmp4;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF], bufH[MAX_ECC_BUF], bufI[MAX_ECC_BUF];
    uint8_t       bufJ[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    big_endian = curve->p.big_endian;
    PKA_ASSERT(big_endian == curve->A.big_endian);
    PKA_ASSERT(big_endian == pointP->x.big_endian);
    PKA_ASSERT(big_endian == pointP->y.big_endian);
    PKA_ASSERT(big_endian == pointQ->x.big_endian);
    PKA_ASSERT(big_endian == pointQ->y.big_endian);

    init_operand(&vp_sum,        bufA, MAX_ECC_BUF, big_endian);
    init_operand(&vq_sum,        bufB, MAX_ECC_BUF, big_endian);
    init_operand(&vp_diff,       bufC, MAX_ECC_BUF, big_endian);
    init_operand(&vq_diff,       bufD, MAX_ECC_BUF, big_endian);
    init_operand(&tmp1,          bufE, MAX_ECC_BUF, big_endian);
    init_operand(&tmp2,          bufF, MAX_ECC_BUF, big_endian);
    init_operand(&tmp1_add_tmp2, bufG, MAX_ECC_BUF, big_endian);
    init_operand(&tmp1_sub_tmp2, bufH, MAX_ECC_BUF, big_endian);
    init_operand(&tmp3,          bufI, MAX_ECC_BUF, big_endian);
    init_operand(&tmp4,          bufJ, MAX_ECC_BUF, big_endian);

    // ECC point addition is accomplished using the following formulas:
    // T1        = (pointQ->x - pointQ->z) * (pointP->x + pointP->z)  mod p
    // T2        = (pointP->x - pointP->z) * (pointQ->x + pointQ->z)  mod p
    // result->x = (T1 + T2)^2               mod p
    // result->z = (T1 - T2)^2 * point_x     mod p
    //
    // Or in more detail:
    // vp_sum    = pointP->x + pointP->z     mod p;
    // vq_sum    = pointQ->x + pointQ->z     mod p;
    // vp_diff   = pointP->x - pointP->z     mod p;
    // vq_diff   = pointQ->x - pointQ->z     mod p;
    // tmp1      = (vq_diff  * vp_sum)       mod p;
    // tmp2      = (vp_diff  * vq_sum)       mod p;
    // tmp3      = (tmp1     + tmp2)^2       mod p;
    // tmp4      = (tmp1     - tmp2)^2       mod p;
    // result->x = tmp3;
    // result->z = point_x   * tmp4          mod p;

    rc = pki_mod_add(&pointP->x,      &pointP->y, &curve->p, &vp_sum);
    rc = pki_mod_add(&pointQ->x,      &pointQ->y, &curve->p, &vq_sum);
    rc = pki_mod_subtract(&pointP->x, &pointP->y, &curve->p, &vp_diff);
    rc = pki_mod_subtract(&pointQ->x, &pointQ->y, &curve->p, &vq_diff);
    rc = pki_mod_multiply(&vq_diff,   &vp_sum,    &curve->p, &tmp1);
    rc = pki_mod_multiply(&vp_diff,   &vq_sum,    &curve->p, &tmp2);
    rc = pki_mod_add(&tmp1,           &tmp2,      &curve->p, &tmp1_add_tmp2);
    rc = pki_mod_subtract(&tmp1,      &tmp2,      &curve->p, &tmp1_sub_tmp2);

    rc = pki_mod_multiply(&tmp1_add_tmp2, &tmp1_add_tmp2, &curve->p, &tmp3);
    rc = pki_mod_multiply(&tmp1_sub_tmp2, &tmp1_sub_tmp2, &curve->p, &tmp4);

    copy_operand(&tmp3, &result_pt->x);
    rc = pki_mod_multiply(point_x, &tmp4, &curve->p, &result_pt->y);

    adjust_actual_len(&result_pt->x);
    adjust_actual_len(&result_pt->y);
    return RC_NO_ERROR;
}

static pka_result_code_t pki_mont_ecdh_multiply(ecc_mont_curve_t *curve,
                                                pka_operand_t    *point_x,
                                                pka_operand_t    *multiplier,
                                                pka_operand_t    *result_pt_x)
{
    pka_operand_t inv_z;
    ecc_point_t   r0, r1, r0_add_r1, r0_dbl, r1_dbl;
    uint32_t      multiplier_bit_len, bit_idx, cnt;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF], bufH[MAX_ECC_BUF], bufI[MAX_ECC_BUF];
    uint8_t       bufJ[MAX_ECC_BUF], bufK[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    big_endian = curve->p.big_endian;
    PKA_ASSERT(big_endian == curve->A.big_endian);
    PKA_ASSERT(big_endian == point_x->big_endian);
    PKA_ASSERT(big_endian == multiplier->big_endian);

    init_ecc_point(&r0,        bufA, bufB, MAX_ECC_BUF, big_endian);
    init_ecc_point(&r1,        bufC, bufD, MAX_ECC_BUF, big_endian);
    init_ecc_point(&r0_add_r1, bufE, bufF, MAX_ECC_BUF, big_endian);
    init_ecc_point(&r0_dbl,    bufG, bufH, MAX_ECC_BUF, big_endian);
    init_ecc_point(&r1_dbl,    bufI, bufJ, MAX_ECC_BUF, big_endian);
    init_operand(&inv_z,       bufK,       MAX_ECC_BUF, big_endian);

    // Set r0_x to 1 and leave r0_z as 0.
    // Copy point_x into r1_x and set r1_z to 1 and get multiplier bit length.
    set_operand(&r0.x, 1);
    copy_operand(point_x, &r1.x);
    set_operand(&r1.y, 1);

    multiplier_bit_len = operand_bit_len(multiplier);
    if (multiplier_bit_len < 2)
    {
        PKA_ERROR(PKA_TESTS,  "mult_bit_len=%u\n", multiplier_bit_len);
        return RC_OPERAND_VALUE_ERR;
    }

    for (cnt = 1; cnt <= multiplier_bit_len; cnt++)
    {
        bit_idx = multiplier_bit_len - cnt;
        pki_mont_ecdh_add(curve, &r0, &r1, point_x, &r0_add_r1);
        if (get_bit(multiplier, bit_idx) != 0)
        {
            pki_mont_ecdh_double(curve, &r1, &r1_dbl);
            copy_ecc_point(&r0_add_r1, &r0);
            copy_ecc_point(&r1_dbl,    &r1);
        }
        else
        {
            pki_mont_ecdh_double(curve, &r0, &r0_dbl);
            copy_ecc_point(&r0_add_r1, &r1);
            copy_ecc_point(&r0_dbl,    &r0);
	}
    }

    // Now return X/Z as stored in r0.  First we need to invert Z and then
    // multiply the inverse by X, all modulo p.  The X and Z coordinates we
    // use will always be in r0, not r1.
    rc = pki_mod_inverse(&r0.y,          &curve->p, &inv_z);
    rc = pki_mod_multiply(&r0.x, &inv_z, &curve->p, result_pt_x);

    adjust_actual_len(result_pt_x);
    return RC_NO_ERROR;
}

pka_result_code_t pki_ecc_add(ecc_curve_t *curve,
                              ecc_point_t *pointA,
                              ecc_point_t *pointB,
                              ecc_point_t *result_pt)
{
    pka_operand_t ab_xdiff, ab_ydiff, ab_xdiff_inv, slope, s_squared;
    pka_operand_t ab_xsum, ac_xdiff, product;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF], bufH[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    PKA_ASSERT(curve->p.big_endian == curve->a.big_endian);
    PKA_ASSERT(curve->p.big_endian == curve->b.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->y.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointB->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointB->y.big_endian);
    big_endian = curve->p.big_endian;

    init_operand(&ab_xdiff,      bufA, MAX_ECC_BUF, big_endian);
    init_operand(&ab_ydiff,      bufB, MAX_ECC_BUF, big_endian);
    init_operand(&ab_xdiff_inv,  bufC, MAX_ECC_BUF, big_endian);
    init_operand(&slope,         bufD, MAX_ECC_BUF, big_endian);
    init_operand(&s_squared,     bufE, MAX_ECC_BUF, big_endian);
    init_operand(&ab_xsum,       bufF, MAX_ECC_BUF, big_endian);
    init_operand(&ac_xdiff,      bufG, MAX_ECC_BUF, big_endian);
    init_operand(&product,       bufH, MAX_ECC_BUF, big_endian);

    rc = pki_mod_subtract(&pointA->x, &pointB->x, &curve->p, &ab_xdiff);
    rc = pki_mod_subtract(&pointA->y, &pointB->y, &curve->p, &ab_ydiff);

    if (is_zero(&ab_xdiff) && is_zero(&ab_ydiff))
        return ecc_double(curve, pointA, result_pt);
    else if (is_zero(&ab_xdiff) || is_zero(&ab_ydiff))
        return RC_INTERMEDIATE_PAI;  // *TBD* is this right??

    // ECC point addition is accomplished using the following formulas:
    // ydiff     = (pointA->y - pointB->y) mod p;
    // xdiff     = (pointA->x - pointB->x) mod p;
    // xsum      = (pointA->x + pointB->x) mod p;
    // slope     = (ydiff / xdiff)         mod p;
    // s_squared = (slope * slope)         mod p;
    // result->x = (s_squared - xsum)      mod p;
    // diff      = (pointA->x, result->x)  mod p;
    // product   = (slope * diff)          mod p;
    // result->y = (product - pointA->y)   mod p;
    rc = pki_mod_inverse(&ab_xdiff,              &curve->p, &ab_xdiff_inv);
    rc = pki_mod_multiply(&ab_ydiff,  &ab_xdiff_inv, &curve->p, &slope);
    rc = pki_mod_multiply(&slope,     &slope,        &curve->p, &s_squared);
    rc = pki_mod_add(&pointA->x,      &pointB->x,    &curve->p, &ab_xsum);
    rc = pki_mod_subtract(&s_squared, &ab_xsum,      &curve->p, &result_pt->x);
    rc = pki_mod_subtract(&pointA->x, &result_pt->x, &curve->p, &ac_xdiff);
    rc = pki_mod_multiply(&slope,     &ac_xdiff,     &curve->p, &product);
    rc = pki_mod_subtract(&product,   &pointA->y,    &curve->p, &result_pt->y);

    adjust_actual_len(&result_pt->x);
    adjust_actual_len(&result_pt->y);
    return RC_NO_ERROR;
}

pka_result_code_t pki_ecc_multiply(ecc_curve_t   *curve,
                                   ecc_point_t   *pointA,
                                   pka_operand_t *multiplier,
                                   ecc_point_t   *result_point)
{
    ecc_point_t   result_pt, new_result_pt, base_pt, new_base_pt;
    uint32_t      mult_bit_len, mult_bit_idx;
    uint8_t       result_is_0;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF], bufH[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    PKA_ASSERT(curve->p.big_endian == curve->a.big_endian);
    PKA_ASSERT(curve->p.big_endian == curve->b.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->y.big_endian);
    PKA_ASSERT(curve->p.big_endian == multiplier->big_endian);
    big_endian = curve->p.big_endian;

    init_ecc_point(&result_pt,     bufA, bufB, MAX_ECC_BUF, big_endian);
    init_ecc_point(&new_result_pt, bufC, bufD, MAX_ECC_BUF, big_endian);
    init_ecc_point(&base_pt,       bufE, bufF, MAX_ECC_BUF, big_endian);
    init_ecc_point(&new_base_pt,   bufG, bufH, MAX_ECC_BUF, big_endian);

    // Copy pointA into base_pt and get multiplier bit length.
    copy_ecc_point(pointA, &base_pt);
    mult_bit_len = operand_bit_len(multiplier);
    if (mult_bit_len < 2)
    {
        PKA_ERROR(PKA_TESTS,  "mult_bit_len=%u\n", mult_bit_len);
        return RC_OPERAND_VALUE_ERR;
    }
    // Initialize result to be 0.
    result_is_0 = 1;

    for (mult_bit_idx = 0; mult_bit_idx < mult_bit_len; mult_bit_idx++)
    {
        if (get_bit(multiplier, mult_bit_idx) != 0)
        {
            // Add base_pt to result.  Special case for the first addition,
            // where result is zero.
            if (result_is_0)
            {
                copy_ecc_point(&base_pt, &result_pt);
                result_is_0 = 0;
            }
            else
            {
                rc = pki_ecc_add(curve, &result_pt, &base_pt, &new_result_pt);
                copy_ecc_point(&new_result_pt, &result_pt);
            }
        }

        // Double the base_pt.
        rc = ecc_double(curve, &base_pt, &new_base_pt);
        copy_ecc_point(&new_base_pt, &base_pt);
    }

    copy_ecc_point(&result_pt, result_point);
    adjust_actual_len(&result_point->x);
    adjust_actual_len(&result_point->y);
    return RC_NO_ERROR;
}

pka_result_code_t pki_ecdsa_generate(ecc_curve_t     *curve,
                                     ecc_point_t     *base_pt,
                                     pka_operand_t   *base_pt_order,
                                     pka_operand_t   *private_key,
                                     pka_operand_t   *hash,
                                     pka_operand_t   *k,
                                     dsa_signature_t *signature_result)
{
    pka_operand_t k_inv, product, sum, r, s;
    ecc_point_t   kG;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    PKA_ASSERT(curve->p.big_endian == curve->a.big_endian);
    PKA_ASSERT(curve->p.big_endian == curve->b.big_endian);
    PKA_ASSERT(curve->p.big_endian == base_pt->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == base_pt->y.big_endian);
    PKA_ASSERT(curve->p.big_endian == base_pt_order->big_endian);
    PKA_ASSERT(curve->p.big_endian == private_key->big_endian);
    PKA_ASSERT(hash->big_endian    == private_key->big_endian);
    PKA_ASSERT(k->big_endian       == hash->big_endian);
    big_endian = curve->p.big_endian;

    init_operand(&k_inv,   bufA, MAX_ECC_BUF, big_endian);
    init_operand(&product, bufB, MAX_ECC_BUF, big_endian);
    init_operand(&sum,     bufC, MAX_ECC_BUF, big_endian);
    init_operand(&r,       bufD, MAX_ECC_BUF, big_endian);
    init_operand(&s,       bufE, MAX_ECC_BUF, big_endian);
    init_ecc_point(&kG,    bufF, bufG, MAX_ECC_BUF, big_endian);

    // kG = k * base_pt;             // This is an "ECC" point multiplication.
    // r  = kG.x mod base_pt_order;
    // s  = (k_inv * (hash + private_key * r) mod base_pt_order;
    rc = pki_mod_inverse (k,       base_pt_order, &k_inv);
    rc = pki_ecc_multiply(curve,   base_pt, k,    &kG);
    rc = pki_modulo      (&kG.x,   base_pt_order, &r);

    rc = pki_mod_multiply(private_key, &r,       base_pt_order, &product);
    rc = pki_mod_add     (hash,        &product, base_pt_order, &sum);
    rc = pki_mod_multiply(&k_inv,      &sum,     base_pt_order, &s);

    copy_operand(&r, &signature_result->r);
    copy_operand(&s, &signature_result->s);
    adjust_actual_len(&signature_result->r);
    adjust_actual_len(&signature_result->s);
    return RC_NO_ERROR;
}

pka_result_code_t pki_ecdsa_verify(ecc_curve_t     *curve,
                                   ecc_point_t     *base_pt,
                                   pka_operand_t   *base_pt_order,
                                   ecc_point_t     *public_key,
                                   pka_operand_t   *hash,
                                   dsa_signature_t *rcvd_signature,
                                   dsa_signature_t *calc_signature_ptr,
                                   pka_cmp_code_t  *cmp_code_result_ptr)
{
    pka_operand_t s_inv, u1, u2, v;
    ecc_point_t   u1_times_base_pt, u2_time_public_key, sum_pt;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF], bufH[MAX_ECC_BUF], bufI[MAX_ECC_BUF];
    uint8_t       bufJ[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;
    pka_cmp_code_t    comparison;

    PKA_ASSERT(curve->p.big_endian == curve->a.big_endian);
    PKA_ASSERT(curve->p.big_endian == curve->b.big_endian);
    PKA_ASSERT(curve->p.big_endian == base_pt->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == base_pt->y.big_endian);
    PKA_ASSERT(curve->p.big_endian == base_pt_order->big_endian);
    PKA_ASSERT(curve->p.big_endian == public_key->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == public_key->y.big_endian);
    PKA_ASSERT(curve->p.big_endian == hash->big_endian);
    big_endian = curve->p.big_endian;

    init_operand(&s_inv, bufA, MAX_ECC_BUF, big_endian);
    init_operand(&u1,    bufB, MAX_ECC_BUF, big_endian);
    init_operand(&u2,    bufC, MAX_ECC_BUF, big_endian);
    init_operand(&v,     bufD, MAX_ECC_BUF, big_endian);

    init_ecc_point(&u1_times_base_pt,   bufE, bufF, MAX_ECC_BUF, big_endian);
    init_ecc_point(&u2_time_public_key, bufG, bufH, MAX_ECC_BUF, big_endian);
    init_ecc_point(&sum_pt,             bufI, bufJ, MAX_ECC_BUF, big_endian);

    // Note that public_key = g^private_key mod p
    // Chk that 0 < r < base_pt_order and 0 < s < base_pt_order
    // s_inv  = s^(-1)         mod base_pt_order;
    // u1     = (hash * s_inv) mod base_pt_order;
    // u2     = (r    * s_inv) mod base_pt_order;
    // sum_pt = (u1 * base_pt) + (u2 * public_key);   // ECC adds and mults.
    // Chk that r == sum_pt.x mod base_pt_order;

    rc = pki_mod_inverse(&rcvd_signature->s,      base_pt_order, &s_inv);
    rc = pki_mod_multiply(hash,               &s_inv, base_pt_order, &u1);
    rc = pki_mod_multiply(&rcvd_signature->r, &s_inv, base_pt_order, &u2);

    rc = pki_ecc_multiply(curve, base_pt,    &u1, &u1_times_base_pt);
    rc = pki_ecc_multiply(curve, public_key, &u2, &u2_time_public_key);
    rc = pki_ecc_add(curve, &u1_times_base_pt, &u2_time_public_key, &sum_pt);

    rc         = pki_modulo(&sum_pt.x, base_pt_order, &v);
    comparison = pki_compare(&rcvd_signature->r, &v);

    *cmp_code_result_ptr = comparison;
    return RC_NO_ERROR;
}

pka_result_code_t pki_dsa_generate(pka_operand_t   *p,
                                   pka_operand_t   *q,
                                   pka_operand_t   *g,
                                   pka_operand_t   *private_key,
                                   pka_operand_t   *hash,
                                   pka_operand_t   *k,
                                   dsa_signature_t *signature_result_ptr)
{
    pka_operand_t mod_exp, k_inv, product, sum, r, s;
    uint8_t       bufA[MAX_BUF], bufB[MAX_BUF], bufC[MAX_BUF];
    uint8_t       bufD[MAX_BUF], bufE[MAX_BUF], bufF[MAX_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    PKA_ASSERT(p->big_endian == q->big_endian);
    PKA_ASSERT(p->big_endian == g->big_endian);
    PKA_ASSERT(p->big_endian == private_key->big_endian);
    PKA_ASSERT(p->big_endian == hash->big_endian);
    PKA_ASSERT(p->big_endian == k->big_endian);
    big_endian = p->big_endian;

    init_operand(&mod_exp, bufA, MAX_BUF, big_endian);
    init_operand(&k_inv,   bufB, MAX_BUF, big_endian);
    init_operand(&product, bufC, MAX_BUF, big_endian);
    init_operand(&sum,     bufD, MAX_BUF, big_endian);
    init_operand(&r,       bufE, MAX_BUF, big_endian);
    init_operand(&s,       bufF, MAX_BUF, big_endian);

    // r = (g^k mod p) mod q;
    // s = (k_inv * (hash + private_key * r) mod q.
    rc = pki_mod_exp    (g, k,     p, &mod_exp);
    rc = pki_mod_inverse(k,        q, &k_inv);
    rc = pki_modulo     (&mod_exp, q, &r);

    rc = pki_mod_multiply(private_key, &r,       q, &product);
    rc = pki_mod_add     (hash,        &product, q, &sum);
    rc = pki_mod_multiply(&k_inv,      &sum,     q, &s);

    if (signature_result_ptr != NULL)
    {
        copy_operand(&r, &signature_result_ptr->r);
        copy_operand(&s, &signature_result_ptr->s);
    }

    return RC_NO_ERROR;
}

pka_result_code_t pki_dsa_verify(pka_operand_t   *p,
                                 pka_operand_t   *q,
                                 pka_operand_t   *g,
                                 pka_operand_t   *public_key,
                                 pka_operand_t   *hash,
                                 dsa_signature_t *rcvd_signature,
                                 dsa_signature_t *calc_signature_ptr,
                                 pka_cmp_code_t  *cmp_code_result_ptr)
{
    pka_operand_t s_inv, u1, u2, mod_exp1, mod_exp2, product, v;
    uint8_t       bufA[MAX_BUF], bufB[MAX_BUF], bufC[MAX_BUF], bufD[MAX_BUF];
    uint8_t       bufE[MAX_BUF], bufF[MAX_BUF], bufG[MAX_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;
    pka_cmp_code_t    comparison;

    PKA_ASSERT(p->big_endian == q->big_endian);
    PKA_ASSERT(p->big_endian == g->big_endian);
    PKA_ASSERT(p->big_endian == public_key->big_endian);
    PKA_ASSERT(p->big_endian == hash->big_endian);
    big_endian = p->big_endian;

    init_operand(&s_inv,    bufA, MAX_BUF, big_endian);
    init_operand(&u1,       bufB, MAX_BUF, big_endian);
    init_operand(&u2,       bufC, MAX_BUF, big_endian);
    init_operand(&mod_exp1, bufD, MAX_BUF, big_endian);
    init_operand(&mod_exp2, bufE, MAX_BUF, big_endian);
    init_operand(&product,  bufF, MAX_BUF, big_endian);
    init_operand(&v,        bufG, MAX_BUF, big_endian);

    // Note that public_key = g^private_key mod p
    // Chk that 0 < r < q and 0 < s < q
    // s_inv  = s^(-1) mod q
    // u1     = (hash * s_inv) mod q
    // u2     = (r    * s_inv) mod q
    // v      = (((g^u1) * (public_key^u2)) mod p) mod q
    // Chk that v == r

    rc = pki_mod_inverse(&rcvd_signature->s, q, &s_inv);

    rc = pki_mod_multiply(hash,               &s_inv, q, &u1);
    rc = pki_mod_multiply(&rcvd_signature->r, &s_inv, q, &u2);

    rc = pki_mod_exp(g,          &u1, p,  &mod_exp1);
    rc = pki_mod_exp(public_key, &u2, p, &mod_exp2);

    rc         = pki_mod_multiply(&mod_exp1, &mod_exp2, p, &product);
    rc         = pki_modulo  (&product,             q, &v);
    comparison = pki_compare(&rcvd_signature->r, &v);

    // *TBD* how to handle the case where calc_signature_ptr != NULL?

    if (cmp_code_result_ptr != NULL)
        *cmp_code_result_ptr = comparison;

    return RC_NO_ERROR;
}

bool ecc_points_are_equal(ecc_point_t *pointA, ecc_point_t *pointB)
{
    if (pki_compare(&pointA->x, &pointB->x) != RC_COMPARE_EQUAL)
        return false;

    if (pki_compare(&pointA->y, &pointB->y) != RC_COMPARE_EQUAL)
        return false;

    return true;
}

bool signatures_are_equal(dsa_signature_t *left_sig,
                          dsa_signature_t *right_sig)
{
    if (pki_compare(&left_sig->r, &right_sig->r) != RC_COMPARE_EQUAL)
        return false;

    if (pki_compare(&left_sig->s, &right_sig->s) != RC_COMPARE_EQUAL)
        return false;

    return true;
}

bool is_valid_curve(pka_handle_t handle, ecc_curve_t *curve)
{
    pka_operand_t *const_4, *const_27, *a_squared, *a_cubed, *b_squared;
    pka_operand_t *a_cubed_by_4, *b_sqrd_by_27, *final_sum;
    bool           result;

    // Use bignum arithmetic check the following:
    // verify that "(4*a^3 + 27*b^2) mod p" is not equal to zero.
    const_4              = malloc_operand(1);
    const_4->buf_ptr[0]  = 4;
    const_4->actual_len  = 1;
    const_27             = malloc_operand(1);
    const_27->buf_ptr[0] = 27;
    const_27->actual_len = 1;

    a_squared = sw_mod_multiply(handle, &curve->a, &curve->a, &curve->p);
    a_cubed   = sw_mod_multiply(handle, a_squared, &curve->a, &curve->p);
    b_squared = sw_mod_multiply(handle, &curve->b, &curve->b, &curve->p);

    a_cubed_by_4 = sw_mod_multiply(handle, a_cubed,   const_4,    &curve->p);
    b_sqrd_by_27 = sw_mod_multiply(handle, b_squared, const_27,   &curve->p);
    final_sum    = sw_mod_add(handle, a_cubed_by_4, b_sqrd_by_27, &curve->p);

    if (final_sum != NULL)
        result = final_sum->buf_len != 0;
    else
        result = false;

    free_operand(const_4);
    free_operand(const_27);
    free_operand(a_squared);
    free_operand(a_cubed);
    free_operand(b_squared);
    free_operand(a_cubed_by_4);
    free_operand(b_sqrd_by_27);
    free_operand(final_sum);

    return result;
}

//
// Software PKA calls
//

pka_operand_t *sw_add(pka_handle_t   handle,
                      pka_operand_t *value,
                      pka_operand_t *addend)
{
    pka_result_code_t  rc;
    pka_operand_t     *result;
    uint32_t           value_byte_len, addend_byte_len, result_byte_len;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    if ((value->big_endian != big_endian) ||
            (addend->big_endian != big_endian))
    {
        PKA_ERROR(PKA_TESTS,  "sw_add endian mismatch.\n");
        return NULL;
    }

    value_byte_len     = value->actual_len;
    addend_byte_len    = addend->actual_len;
    result_byte_len    = MAX(value_byte_len, addend_byte_len) + 1;
    result             = malloc_operand(result_byte_len);
    result->big_endian = big_endian;

    rc = pki_add(value, addend, result);
    if (rc == RC_NO_ERROR)
        return result;

    PKA_ERROR(PKA_TESTS,  "sw_add failed rc=%d\n", rc);
    free_operand(result);
    return NULL;
}

pka_operand_t *sw_subtract(pka_handle_t   handle,
                           pka_operand_t *value,
                           pka_operand_t *subtrahend)
{
    pka_result_code_t  rc;
    pka_operand_t     *result;
    uint32_t           diff_byte_len;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    if ((value->big_endian != big_endian) ||
            (subtrahend->big_endian != big_endian))
    {
        PKA_ERROR(PKA_TESTS,  "sw_sub endian mismatch.\n");
        return NULL;
    }

    diff_byte_len      = value->actual_len;
    result             = malloc_operand(diff_byte_len);
    result->big_endian = big_endian;

    rc = pki_subtract(value, subtrahend, result);
    if (rc == RC_NO_ERROR)
        return result;

    PKA_ERROR(PKA_TESTS,  "sw_subtract failed rc=%d\n", rc);
    free_operand(result);
    return NULL;
}

pka_operand_t *sw_multiply(pka_handle_t   handle,
                           pka_operand_t *value,
                           pka_operand_t *multiplier)
{
    pka_result_code_t  rc;
    pka_operand_t     *result;
    uint32_t           product_byte_len, val_byte_len, mul_byte_len;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    if ((value->big_endian != big_endian) ||
            (multiplier->big_endian != big_endian))
    {
        PKA_ERROR(PKA_TESTS,  "sw_mult endian mismatch.\n");
        return NULL;
    }

    val_byte_len       = value->actual_len;
    mul_byte_len       = multiplier->actual_len;
    product_byte_len   = val_byte_len + mul_byte_len;
    result             = malloc_operand(product_byte_len);
    result->big_endian = big_endian;

    rc = pki_multiply(value, multiplier, result);
    if (rc == RC_NO_ERROR)
        return result;

    PKA_ERROR(PKA_TESTS,  "sync_multiply failed rc=%d\n", rc);
    print_operand("  value    =", value,     "\n");
    print_operand("  multipler=", multiplier, "\n");
    free_operand(result);
    return NULL;
}

pka_operand_t *sw_divide(pka_handle_t   handle,
                         pka_operand_t *dividend,
                         pka_operand_t *divisor)
{
    pka_result_code_t  rc;
    pka_operand_t     *quotient, *remainder;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    if ((dividend->big_endian != big_endian) ||
            (divisor->big_endian != big_endian))
    {
        PKA_ERROR(PKA_TESTS,  "sw_div endian mismatch.\n");
        return NULL;
    }

    remainder = malloc_operand(MAX_BUF);
    quotient  = malloc_operand(MAX_BUF);

    remainder->big_endian = big_endian;
    quotient->big_endian  = big_endian;

    rc = pki_divide(dividend, divisor, quotient, remainder);
    if (rc == RC_NO_ERROR)
        return quotient;

    PKA_ERROR(PKA_TESTS,  "sync_divide failed rc=%d\n", rc);
    print_operand("  dividend=", dividend, "\n");
    print_operand("  divisor =", divisor,  "\n");
    free_operand(remainder);
    free_operand(quotient);
    return NULL;
}

pka_operand_t *sw_modulo(pka_handle_t   handle,
                         pka_operand_t *value,
                         pka_operand_t *modulus)
{
    pka_result_code_t  rc;
    pka_operand_t     *result;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    if ((value->big_endian != big_endian) ||
            (modulus->big_endian != big_endian))
    {
        PKA_ERROR(PKA_TESTS,  "sw_modulo endian mismatch.\n");
        return NULL;
    }

    if (pki_compare(value, modulus) == RC_LEFT_IS_SMALLER)
        return dup_operand(value);

    result             = malloc_operand(MAX_BUF);
    result->big_endian = big_endian;

    rc = pki_modulo(value, modulus, result);
    if (rc == RC_NO_ERROR)
        return result;

    PKA_ERROR(PKA_TESTS,  "sw_modulo failed rc=%d\n", rc);
    print_operand("  value  =", value,   "\n");
    print_operand("  modulus=", modulus, "\n");
    free_operand(result);
    return NULL;
}

pka_operand_t *sw_shift_left(pka_handle_t   handle,
                             pka_operand_t *value,
                             uint32_t       shift_cnt)
{
    pka_result_code_t  rc;
    pka_operand_t     *result;
    uint32_t           value_bit_len, result_bit_len;
    uint32_t           result_byte_len, value_byte_len;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    if (value->big_endian != big_endian)
    {
        PKA_ERROR(PKA_TESTS,  "sw_shift_left endian mismatch.\n");
        return NULL;
    }

    value_bit_len      = operand_bit_len(value);
    value_byte_len     = (value_bit_len + 7) / 8;
    result_bit_len     = value_bit_len + shift_cnt;
    result_byte_len    = (result_bit_len + 7) / 8;
    result             = malloc_operand(result_byte_len);
    result->big_endian = big_endian;

    rc = pki_shift_left(value, shift_cnt, result);
    if (rc == RC_NO_ERROR)
        return result;

    PKA_ERROR(PKA_TESTS,  "sync_shift_left failed rc=%d\n", rc);
    free_operand(result);
    return NULL;
}

pka_operand_t *sw_shift_right(pka_handle_t   handle,
                              pka_operand_t *value,
                              uint32_t       shift_cnt)
{
    pka_result_code_t  rc;
    pka_operand_t     *result;
    uint32_t           value_bit_len, result_bit_len;
    uint32_t           result_byte_len, value_byte_len;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    if (value->big_endian != big_endian)
    {
        PKA_ERROR(PKA_TESTS,  "sw_shift_right endian mismatch.\n");
        return NULL;
    }

    value_bit_len = operand_bit_len(value);
    if (value_bit_len <= shift_cnt)
        return dup_operand(&ZERO);

    value_byte_len     = (value_bit_len + 7) / 8;
    result_bit_len     = value_bit_len - shift_cnt;
    result_byte_len    = (result_bit_len + 7) / 8;
    result             = malloc_operand(result_byte_len);
    result->big_endian = big_endian;

    rc = pki_shift_right(value, shift_cnt, result);
    if (rc == RC_NO_ERROR)
        return result;

    PKA_ERROR(PKA_TESTS,  "sync_shift_right failed rc=%d\n", rc);
    free_operand(result);
    return NULL;
}

pka_operand_t *sw_mod_inverse(pka_handle_t   handle,
                              pka_operand_t *value,
                              pka_operand_t *modulus)
{
    pka_result_code_t  rc;
    pka_operand_t     *result;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    if ((value->big_endian != big_endian) ||
            (modulus->big_endian != big_endian))
    {
        PKA_ERROR(PKA_TESTS,  "sw_mod_inverse endian mismatch.\n");
        return NULL;
    }

    result             = malloc_operand(MAX_BUF);
    result->big_endian = big_endian;

    rc = pki_mod_inverse(value, modulus, result);
    if (rc == RC_NO_ERROR)
        return result;

    PKA_ERROR(PKA_TESTS,  "sync_mod_inverse failed rc=%d\n", rc);
    free_operand(result);
    return NULL;
}

pka_operand_t *sw_mod_add(pka_handle_t   handle,
                          pka_operand_t *value,
                          pka_operand_t *addend,
                          pka_operand_t *modulus)
{
    pka_operand_t *sum, *result;

    sum = sw_add(handle, value, addend);
    if (pki_compare(sum, modulus) == RC_LEFT_IS_SMALLER)
        return sum;

    result = sw_subtract(handle, sum, modulus);
    free_operand(sum);
    return result;
}

pka_operand_t *sw_mod_subtract(pka_handle_t   handle,
                               pka_operand_t *value,
                               pka_operand_t *subtrahend,
                               pka_operand_t *modulus)
{
    pka_cmp_code_t  comparison;
    pka_operand_t  *reversed_diff, *result;

    comparison = pki_compare(value, subtrahend);
    if (comparison == RC_COMPARE_EQUAL)
        return NULL;
    else if (comparison == RC_RIGHT_IS_SMALLER)
        return sw_subtract(handle, value, subtrahend);

    // result is -diff mod modulus which is the same as modulus - diff;
    reversed_diff = sw_subtract(handle, subtrahend, value);
    result        = sw_subtract(handle, modulus, reversed_diff);

    free_operand(reversed_diff);
    return result;
}

pka_operand_t *sw_mod_multiply(pka_handle_t   handle,
                               pka_operand_t *value,
                               pka_operand_t *multiplier,
                               pka_operand_t *modulus)
{
    pka_operand_t *product, *result;

    product = sw_multiply(handle, value, multiplier);
    result  = sw_modulo(handle, product, modulus);
    free_operand(product);
    return result;
}

pka_operand_t *sw_mod_exp(pka_handle_t   handle,
                          pka_operand_t *exponent,
                          pka_operand_t *modulus,
                          pka_operand_t *msg)
{
    pka_result_code_t  rc;
    pka_operand_t     *result;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    if ((msg->big_endian != big_endian) ||
          (modulus->big_endian != big_endian) ||
            (exponent->big_endian != big_endian))
    {
        PKA_ERROR(PKA_TESTS,  "sw_mod_exp endian mismatch.\n");
        return NULL;
    }

    result             = malloc_operand(MAX_BUF);
    result->big_endian = big_endian;

    rc = pki_mod_exp(msg, exponent, modulus, result);
    if (rc == RC_NO_ERROR)
        return result;

    PKA_ERROR(PKA_TESTS,  "sw_mod_exp failed rc=%d\n", rc);
    print_operand("  exponent=", exponent, "\n");
    print_operand("  modulus =", modulus,  "\n");
    print_operand("  msg     =", msg,      "\n");
    free_operand(result);
    return NULL;
}

pka_operand_t *sw_mod_exp_with_crt(pka_handle_t   handle,
                                   pka_operand_t *p,
                                   pka_operand_t *q,
                                   pka_operand_t *msg,
                                   pka_operand_t *d_p,
                                   pka_operand_t *d_q,
                                   pka_operand_t *qinv)
{
    pka_result_code_t  rc;
    pka_operand_t     *result;
    uint8_t            big_endian;

    big_endian         = pka_get_rings_byte_order(handle);
    result             = malloc_operand(MAX_BUF);
    result->big_endian = big_endian;

    rc = pki_mod_exp_with_crt(msg, p, q, d_p, d_q, qinv, result);
    if (rc == RC_NO_ERROR)
        return result;

    PKA_ERROR(PKA_TESTS,  "sw_mod_exp_with_crt failed rc=%d\n", rc);
    free_operand(result);
    return NULL;
}

pka_operand_t *sw_mont_ecdh_multiply(pka_handle_t      handle,
                                     ecc_mont_curve_t *curve,
                                     pka_operand_t    *point_x,
                                     pka_operand_t    *multiplier)
{
    pka_result_code_t rc;
    pka_operand_t    *result_pt_x, adjusted_mult, reduced_point_x;
    uint8_t           big_endian, is_canonical, mult_buf[MAX_ECC_BUF];
    uint8_t           reduced_point_buf[MAX_ECC_BUF];

    big_endian              = 0;  // pka_get_rings_byte_order(handle);
    result_pt_x             = malloc_operand(MAX_ECC_BUF);
    result_pt_x->big_endian = big_endian;

    is_canonical = pki_is_mont_ecdh_canonical(curve, point_x);
    if (!is_canonical)
    {
	memset(&reduced_point_x,      0, sizeof(pka_operand_t));
	memset(&reduced_point_buf[0], 0, MAX_ECC_BUF);
	reduced_point_x.buf_len      = MAX_ECC_BUF;
	reduced_point_x.actual_len   = 0;
	reduced_point_x.is_encrypted = 0;
	reduced_point_x.big_endian   = big_endian;
	reduced_point_x.buf_ptr      = &reduced_point_buf[0];

	rc = pki_mont_ecdh_canonicalize(handle, curve, point_x,
                                        &reduced_point_x);
	if (rc == 0)
            point_x = &reduced_point_x;
    }

    // Adjust multiplier
    memcpy(&adjusted_mult, multiplier, sizeof(adjusted_mult));
    adjusted_mult.buf_ptr = &mult_buf[0];
    adjusted_mult.buf_len = MAX_ECC_BUF;
    pki_adjust_mont_ecdh_multiplier(&adjusted_mult, multiplier, &curve->p);

    rc = pki_mont_ecdh_multiply(curve, point_x, &adjusted_mult, result_pt_x);
    if (rc == RC_NO_ERROR)
        return result_pt_x;

    PKA_ERROR(PKA_TESTS, "sw_mont_ecdh_multiply failed rc=%d\n", rc);
    free_operand(result_pt_x);
    return NULL;
}

ecc_point_t *sw_ecc_add(pka_handle_t  handle,
                        ecc_curve_t  *curve,
                        ecc_point_t  *pointA,
                        ecc_point_t  *pointB)
{
    pka_result_code_t  rc;
    ecc_point_t       *result_pt;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    result_pt  = malloc_ecc_point(MAX_ECC_BUF, MAX_ECC_BUF, big_endian);

    rc = pki_ecc_add(curve, pointA, pointB, result_pt);
    if (rc == RC_NO_ERROR)
        return result_pt;

    PKA_ERROR(PKA_TESTS,  "sw_ecc_add failed rc=%d\n", rc);
    free_ecc_point(result_pt);
    return NULL;
}

ecc_point_t *sw_ecc_multiply(pka_handle_t   handle,
                             ecc_curve_t   *curve,
                             ecc_point_t   *pointA,
                             pka_operand_t *multiplier)
{
    pka_result_code_t  rc;
    ecc_point_t       *result_pt;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    result_pt  = malloc_ecc_point(MAX_ECC_BUF, MAX_ECC_BUF, big_endian);

    rc = pki_ecc_multiply(curve, pointA, multiplier, result_pt);
    if (rc == RC_NO_ERROR)
        return result_pt;

    PKA_ERROR(PKA_TESTS,  "sw_ecc_multiply failed rc=%d\n", rc);
    free_ecc_point(result_pt);
    return NULL;
}

dsa_signature_t *sw_ecdsa_gen(pka_handle_t   handle,
                              ecc_curve_t   *curve,
                              ecc_point_t   *base_pt,
                              pka_operand_t *base_pt_order,
                              pka_operand_t *private_key,
                              pka_operand_t *hash,
                              pka_operand_t *k)
{
    dsa_signature_t   *signature;
    pka_result_code_t  rc;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    signature  = malloc_dsa_signature(MAX_ECC_BUF, MAX_ECC_BUF, big_endian);

    rc = pki_ecdsa_generate(curve, base_pt, base_pt_order,
                                private_key, hash, k, signature);
    if (rc == RC_NO_ERROR)
        return signature;

    PKA_ERROR(PKA_TESTS,  "sw_ecdsa_gen failed rc=%d\n", rc);
    free_dsa_signature(signature);
    return NULL;
}

pka_status_t sw_ecdsa_verify(pka_handle_t       handle,
                             ecc_curve_t       *curve,
                             ecc_point_t       *base_pt,
                             pka_operand_t     *base_pt_order,
                             ecc_point_t       *public_key,
                             pka_operand_t     *hash,
                             dsa_signature_t   *signature)
{
    pka_cmp_code_t    comparison;
    pka_result_code_t rc;
    uint8_t           big_endian;

    comparison = 0;

    big_endian = pka_get_rings_byte_order(handle);
    if ((signature->r.big_endian != big_endian) ||
          (signature->s.big_endian != big_endian))
    {
        PKA_ERROR(PKA_TESTS,  "sw_ecdsa_verify endian mismatch.\n");
        return FAILURE;
    }

    rc = pki_ecdsa_verify(curve, base_pt, base_pt_order, public_key,
                            hash, signature, NULL, &comparison);
    if (rc != RC_NO_ERROR)
    {
        PKA_ERROR(PKA_TESTS,  "sw_ecdsa_verify failed rc=%d\n", rc);
        return FAILURE;
    }

    if (comparison == RC_COMPARE_EQUAL)
        return SUCCESS;

    if (comparison == 0)
        PKA_ERROR(PKA_TESTS,  "sw_ecdsa_verify failed comparison=0\n");

    return FAILURE;
}

dsa_signature_t *sw_dsa_gen(pka_handle_t       handle,
                            pka_operand_t     *p,
                            pka_operand_t     *q,
                            pka_operand_t     *g,
                            pka_operand_t     *private_key,
                            pka_operand_t     *hash,
                            pka_operand_t     *k)
{
    dsa_signature_t   *signature;
    pka_result_code_t  rc;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    signature  = malloc_dsa_signature(MAX_BUF, MAX_BUF, big_endian);

    rc = pki_dsa_generate(p, q, g, private_key, hash, k, signature);
    if (rc == RC_NO_ERROR)
        return signature;

    PKA_ERROR(PKA_TESTS,  "sw_dsa_gen failed rc=%d\n", rc);
    free_dsa_signature(signature);
    return NULL;
}

pka_status_t sw_dsa_verify(pka_handle_t       handle,
                           pka_operand_t     *p,
                           pka_operand_t     *q,
                           pka_operand_t     *g,
                           pka_operand_t     *public_key,
                           pka_operand_t     *hash,
                           dsa_signature_t   *signature)
{
    pka_cmp_code_t    comparison;
    pka_result_code_t rc;
    uint8_t           big_endian;

    comparison = 0;

    big_endian = pka_get_rings_byte_order(handle);
    if ((signature->r.big_endian != big_endian) ||
          (signature->s.big_endian != big_endian))
    {
        PKA_ERROR(PKA_TESTS,  "sw_dsa_verify endian mismatch.\n");
        return FAILURE;
    }

    rc = pki_dsa_verify(p, q, g, public_key, hash,
                             signature, NULL, &comparison);
    if (rc != RC_NO_ERROR)
    {
        PKA_ERROR(PKA_TESTS,  "sw_dsa_verify failed rc=%d\n", rc);
        return FAILURE;
    }

    if (comparison == RC_COMPARE_EQUAL)
        return SUCCESS;

    if (comparison == 0)
        PKA_ERROR(PKA_TESTS,  "sw_dsa_verify failed in sync_dsa_verify\n");

    return FAILURE;
}

//
// Synchronous PKA calls
//

void pka_wait_for_results(pka_handle_t handle, pka_results_t *results)
{
    // *TBD*
    // This is weak! We should define a timer here, so that we don't
    // get stuck indefinitely when the test fails to retrieve a result.
    while (true)
    {
        // Wait for a short while between attempts to get the result
        pka_wait();

        if (SUCCESS == pka_get_result(handle, results))
            return;
    }
}

pka_status_t get_results(pka_handle_t   handle,
                         pka_operand_t *result1,
                         pka_operand_t *result2)
{
    pka_results_t  results;
    uint32_t       result1_len, result2_len;
    uint8_t        res1[MAX_BYTE_LEN], res2[MAX_BYTE_LEN];

    memset(&results, 0, sizeof(pka_results_t));
    memset(&res1[0], 0, sizeof(res1));
    memset(&res2[0], 0, sizeof(res2));
    init_results_operand(&results, 2, res1, MAX_BYTE_LEN, res2, MAX_BYTE_LEN);

    pka_wait_for_results(handle, &results);
    if (results.status != RC_NO_ERROR)
    {
        PKA_ERROR(PKA_TESTS,  "get_results status=0x%x\n", results.status);
        return 0;
    }

    if ((2 <= results.results[0].big_endian) || (2 <= results.results[1].big_endian))
        PKA_ERROR(PKA_TESTS, "Bad big_endians=0x%x 0x%x opcode=0x%x\n",
                  results.results[0].big_endian, results.results[1].big_endian,
                  results.opcode);

    if (results.result_cnt != 2)
        PKA_ERROR(PKA_TESTS,  "get_results result_cnt != 2\n");

    if (results.results[0].big_endian != results.results[1].big_endian)
        PKA_ERROR(PKA_TESTS,  "get_results mixed endianness\n");

    if (result1->buf_ptr != NULL)
        free(result1->buf_ptr);

    if (result2->buf_ptr != NULL)
        free(result2->buf_ptr);

    memset(result1, 0, sizeof(pka_operand_t));
    result1_len         = results.results[0].actual_len;
    result1->actual_len = result1_len;
    result1->buf_len    = result1_len;
    result1->buf_ptr    = malloc(result1_len);
    result1->big_endian = results.results[0].big_endian;
    memcpy(result1->buf_ptr, results.results[0].buf_ptr, result1_len);

    memset(result2, 0, sizeof(pka_operand_t));
    result2_len         = results.results[1].actual_len;
    result2->actual_len = result2_len;
    result2->buf_len    = result2_len;
    result2->buf_ptr    = malloc(result2_len);
    result2->big_endian = results.results[1].big_endian;
    memcpy(result2->buf_ptr, results.results[1].buf_ptr, result2_len);

    return SUCCESS;
}

pka_cmp_code_t get_cmp_result(pka_handle_t handle)
{
    pka_cmp_code_t cmp_result;
    pka_results_t  results;
    uint8_t        res1[MAX_BYTE_LEN], res2[MAX_BYTE_LEN];

    memset(&results, 0, sizeof(pka_results_t));
    init_results_operand(&results, 2, res1, MAX_BYTE_LEN, res2, MAX_BYTE_LEN);

    pka_wait_for_results(handle, &results);
    if (results.status != RC_NO_ERROR)
    {
        PKA_ERROR(PKA_TESTS,  "get_cmp_result status=0x%x\n", results.status);
        return 0;
    }

    cmp_result = results.compare_result;
    if (results.result_cnt != 0)
        PKA_ERROR(PKA_TESTS,
                    "get_cmp_result result_cnt should be zero was=%d\n",
               results.result_cnt);

    return cmp_result;
}

pka_operand_t *results_to_operand(pka_handle_t handle)
{
    pka_results_t  results;
    pka_operand_t *result_ptr;
    uint32_t       result_len;
    uint8_t        res1[MAX_BYTE_LEN];

    memset(&results, 0, sizeof(pka_results_t));
    init_results_operand(&results, 1, res1, MAX_BYTE_LEN, NULL, 0);

    pka_wait_for_results(handle, &results);
    if (results.status != RC_NO_ERROR)
    {
        PKA_ERROR(PKA_TESTS,  "pka_get_result status=0x%x\n",
                    results.status);
        return NULL;
    }

    result_len = results.results[0].actual_len;
    result_ptr = malloc_operand(result_len);
    copy_operand(&results.results[0], result_ptr);
    result_ptr->big_endian = 0;
    return result_ptr;
}

pka_operand_t *sync_add(pka_handle_t   handle,
                        pka_operand_t *value,
                        pka_operand_t *addend)
{
    pka_operand_t *hw_result;
    uint32_t       sum_len;

    // See if the size of the result is too large for the HW, and if so use
    // the sw algorithm.
    sum_len = MAX(value->actual_len, addend->actual_len) + 1;
    if (MAX_BYTE_LEN <= sum_len)
        return sw_add(handle, value, addend);

    if (SUCCESS != pka_add(handle, NULL, value, addend))
    {
        PKA_ERROR(PKA_TESTS,  "sync_add failed\n");
        return NULL;
    }

    hw_result = results_to_operand(handle);

    return hw_result;
}

pka_operand_t *sync_subtract(pka_handle_t   handle,
                             pka_operand_t *value,
                             pka_operand_t *subtrahend)
{
    if (SUCCESS != pka_subtract(handle, NULL, value, subtrahend))
    {
        PKA_ERROR(PKA_TESTS,  "sync_subtract failed\n");
        return NULL;
    }

    return results_to_operand(handle);
}

pka_operand_t *sync_multiply(pka_handle_t   handle,
                             pka_operand_t *value,
                             pka_operand_t *multipler)
{
    uint32_t product_len;

    // See if the size of the value + the size of the multipler is too large
    // for the HW, and if so use the sw algorithm.
    product_len = value->actual_len + multipler->actual_len;
    if (MAX_BYTE_LEN <= product_len)
        return sw_multiply(handle, value, multipler);

    if (SUCCESS != pka_multiply(handle, NULL, value, multipler))
    {
        PKA_ERROR(PKA_TESTS,  "sync_multiply failed\n");
        print_operand("  value    =", value,     "\n");
        print_operand("  multipler=", multipler, "\n");
        return NULL;
    }

    return results_to_operand(handle);
}

pka_operand_t *sync_divide(pka_handle_t   handle,
                           pka_operand_t *dividend,
                           pka_operand_t *divisor)
{
    pka_operand_t *quotient, *remainder;

    // See if the size of the dividend or divisor is too large for the HW,
    // and if so use the sw algorithm.
    if ((MAX_BYTE_LEN <= dividend->actual_len) ||
        (MAX_BYTE_LEN <= divisor->actual_len))
        return sw_divide(handle, dividend, divisor);

    if (SUCCESS != pka_divide(handle, NULL, dividend, divisor))
    {
        PKA_ERROR(PKA_TESTS,  "sync_divide failed\n");
        print_operand("  dividend=", dividend, "\n");
        print_operand("  divisor =", divisor,  "\n");
        return NULL;
    }

    remainder = malloc_operand(MAX_BYTE_LEN);
    quotient  = malloc_operand(MAX_BYTE_LEN);
    if (SUCCESS != get_results(handle, remainder, quotient))
    {
        free_operand(remainder);
        free_operand(quotient);
        return NULL;
    }

    free_operand(remainder);
    return quotient;
}

pka_operand_t *sync_modulo(pka_handle_t   handle,
                           pka_operand_t *value,
                           pka_operand_t *modulus)
{
    if (pki_compare(value, modulus) == RC_LEFT_IS_SMALLER)
        return dup_operand(value);

    if (SUCCESS != pka_modulo(handle, NULL, value, modulus))
    {
        PKA_ERROR(PKA_TESTS,  "sync_modulo failed\n");
        print_operand("  value  =", value,   "\n");
        print_operand("  modulus=", modulus, "\n");
        return NULL;
    }

    return results_to_operand(handle);
}

pka_operand_t *sync_shift_left(pka_handle_t   handle,
                               pka_operand_t *value,
                               uint32_t       shift_cnt)
{
    if (SUCCESS != pka_shift_left(handle, NULL, value, shift_cnt))
    {
        PKA_ERROR(PKA_TESTS,  "sync_shift_left failed\n");
        return NULL;
    }

    return results_to_operand(handle);
}

pka_operand_t *sync_shift_right(pka_handle_t   handle,
                                pka_operand_t *value,
                                uint32_t       shift_cnt)
{
    if (SUCCESS != pka_shift_right(handle, NULL, value, shift_cnt))
    {
        PKA_ERROR(PKA_TESTS,  "sync_shift_right failed\n");
        return NULL;
    }

    return results_to_operand(handle);
}

pka_operand_t *sync_mod_inverse(pka_handle_t   handle,
                                pka_operand_t *value,
                                pka_operand_t *modulus)
{
    if (SUCCESS != pka_modular_inverse(handle, NULL, value, modulus))
    {
        PKA_ERROR(PKA_TESTS,  "sync_mod_inverse failed\n");
        return NULL;
    }

    return results_to_operand(handle);
}

pka_operand_t *sync_mod_add(pka_handle_t   handle,
                            pka_operand_t *value,
                            pka_operand_t *addend,
                            pka_operand_t *modulus)
{
    pka_operand_t *sum, *result;

    if ((value == NULL) || (addend == NULL) || (modulus == NULL))
    {
        PKA_ERROR(PKA_TESTS,  "sync_mod_add called with NULL operand\n");
        return NULL;
    }

    sum = sync_add(handle, value, addend);
    if (pki_compare(sum, modulus) == RC_LEFT_IS_SMALLER)
        return sum;

    result = sync_subtract(handle, sum, modulus);
    free_operand(sum);
    return result;
}

pka_operand_t *sync_mod_subtract(pka_handle_t   handle,
                                 pka_operand_t *value,
                                 pka_operand_t *subtrahend,
                                 pka_operand_t *modulus)
{
    pka_cmp_code_t  comparison;
    pka_operand_t  *reversed_diff, *result;

    comparison = pki_compare(value, subtrahend);
    if (comparison == RC_COMPARE_EQUAL)
        return NULL;
    else if (comparison == RC_RIGHT_IS_SMALLER)
        return sync_subtract(handle, value, subtrahend);

    // result is -diff mod modulus which is the same as modulus - diff;
    reversed_diff = sync_subtract(handle, subtrahend, value);
    result        = sync_subtract(handle, modulus, reversed_diff);

    free_operand(reversed_diff);
    return result;
}

pka_operand_t *sync_mod_multiply(pka_handle_t   handle,
                                 pka_operand_t *value,
                                 pka_operand_t *multiplier,
                                 pka_operand_t *modulus)
{
    pka_operand_t *product, *result;

    product = sync_multiply(handle, value, multiplier);
    result  = sync_modulo(handle, product, modulus);
    free_operand(product);
    return result;
}

pka_operand_t *sync_mod_exp(pka_handle_t   handle,
                            pka_operand_t *exponent,
                            pka_operand_t *modulus,
                            pka_operand_t *msg)
{
    // HW (via pka_modular_exp) does not properly handle an exponent of 1.
    if (is_one(exponent))
        return dup_operand(msg);

    if (SUCCESS != pka_modular_exp(handle, NULL, exponent, modulus, msg))
    {
        PKA_ERROR(PKA_TESTS,  "sync_mod_exp failed\n");
        print_operand("  exponent=", exponent, "\n");
        print_operand("  modulus =", modulus,  "\n");
        print_operand("  msg     =", msg,      "\n");
        return NULL;
    }

    return results_to_operand(handle);
}

pka_operand_t *sync_mod_exp_with_crt(pka_handle_t   handle,
                                     pka_operand_t *p,
                                     pka_operand_t *q,
                                     pka_operand_t *msg,
                                     pka_operand_t *d_p,
                                     pka_operand_t *d_q,
                                     pka_operand_t *qinv)
{
    if (SUCCESS !=
            pka_modular_exp_crt(handle, NULL, msg, p, q, d_p, d_q, qinv))
    {
        PKA_ERROR(PKA_TESTS,  "sync_exp_with_crt failed\n");
        return NULL;
    }

    return results_to_operand(handle);
}

pka_operand_t *sync_mont_ecdh_multiply(pka_handle_t      handle,
                                       ecc_mont_curve_t *curve,
                                       pka_operand_t    *pointA_x,
                                       pka_operand_t    *multiplier)
{
    if (SUCCESS != pka_mont_ecdh_mult(handle, NULL, curve, pointA_x,
                                      multiplier))
    {
        PKA_ERROR(PKA_TESTS, "sync_ecc_mont_multiply failed\n");
        return NULL;
    }

    return results_to_operand(handle);
}

ecc_point_t *sync_ecc_add(pka_handle_t  handle,
                          ecc_curve_t  *curve,
                          ecc_point_t  *pointA,
                          ecc_point_t  *pointB)
{
    ecc_point_t *result_pt;
    uint32_t     buf_len;
    uint8_t      big_endian;

    if (SUCCESS != pka_ecc_pt_add(handle, NULL, curve, pointA, pointB))
    {
        PKA_ERROR(PKA_TESTS,  "sync_ecc_add failed\n");
        return NULL;
    }

    buf_len    = curve->p.actual_len;
    big_endian = pka_get_rings_byte_order(handle);
    result_pt  = malloc_ecc_point(buf_len, buf_len, big_endian);
    if (SUCCESS != get_results(handle, &result_pt->x, &result_pt->y))
        return NULL;

    return result_pt;
}

ecc_point_t *sync_ecc_multiply(pka_handle_t   handle,
                               ecc_curve_t   *curve,
                               ecc_point_t   *pointA,
                               pka_operand_t *multiplier)
{
    ecc_point_t *result_pt;
    uint32_t     buf_len;
    uint8_t      big_endian;

    if (SUCCESS != pka_ecc_pt_mult(handle, NULL, curve, pointA, multiplier))
    {
        PKA_ERROR(PKA_TESTS,  "sync_ecc_multiply failed\n");
        return NULL;
    }

    buf_len    = curve->p.actual_len;
    big_endian = pka_get_rings_byte_order(handle);
    result_pt  = malloc_ecc_point(curve->p.actual_len,
                                  curve->p.actual_len,
                                  big_endian);
    if (SUCCESS != get_results(handle, &result_pt->x, &result_pt->y))
        return NULL;

    return result_pt;
}

dsa_signature_t *sync_ecdsa_gen(pka_handle_t   handle,
                                ecc_curve_t   *curve,
                                ecc_point_t   *base_pt,
                                pka_operand_t *base_pt_order,
                                pka_operand_t *private_key,
                                pka_operand_t *hash,
                                pka_operand_t *k)
{
    dsa_signature_t   *signature;
    uint32_t           buf_len;
    uint8_t            big_endian;

    if (SUCCESS != pka_ecdsa_signature_generate(handle, NULL,
                    curve, base_pt, base_pt_order, private_key, hash, k))
    {
        PKA_ERROR(PKA_TESTS,  "sync_ecdsa_gen failed\n");
        return NULL;
    }

    buf_len    = curve->p.buf_len;
    big_endian = pka_get_rings_byte_order(handle);
    signature  = malloc_dsa_signature(buf_len, buf_len, big_endian);
    if (SUCCESS != get_results(handle, &signature->r, &signature->s))
        return NULL;

    return signature;
}

pka_status_t sync_ecdsa_verify(pka_handle_t       handle,
                               ecc_curve_t       *curve,
                               ecc_point_t       *base_pt,
                               pka_operand_t     *base_pt_order,
                               ecc_point_t       *public_key,
                               pka_operand_t     *hash,
                               dsa_signature_t   *signature)
{
    pka_cmp_code_t comparison;

    if (SUCCESS != pka_ecdsa_signature_verify(handle, NULL, curve, base_pt,
                            base_pt_order, public_key, hash, signature, 0))
    {
        PKA_ERROR(PKA_TESTS,  "sync_ecdsa_verify failed\n");
        return FAILURE;
    }

    comparison = get_cmp_result(handle);
    if (comparison == RC_COMPARE_EQUAL)
        return SUCCESS;

    if (comparison == 0)
        PKA_ERROR(PKA_TESTS,  "sync_ecdsa_verify failed in get_cmp_result\n");

    return FAILURE;
}

dsa_signature_t *sync_dsa_gen(pka_handle_t       handle,
                              pka_operand_t     *p,
                              pka_operand_t     *q,
                              pka_operand_t     *g,
                              pka_operand_t     *private_key,
                              pka_operand_t     *hash,
                              pka_operand_t     *k)
{
    dsa_signature_t   *signature;
    uint32_t           buf_len;
    uint8_t            big_endian;

    if (SUCCESS != pka_dsa_signature_generate(handle, NULL,
                                        p, q, g, private_key, hash, k))
    {
        PKA_ERROR(PKA_TESTS,  "sync_dsa_gen failed\n");
        return NULL;
    }

    buf_len    = p->buf_len;
    big_endian = pka_get_rings_byte_order(handle);
    signature  = malloc_dsa_signature(buf_len, buf_len, big_endian);
    if (SUCCESS != get_results(handle, &signature->r, &signature->s))
        return NULL;

    return signature;
}

pka_status_t sync_dsa_verify(pka_handle_t       handle,
                             pka_operand_t     *p,
                             pka_operand_t     *q,
                             pka_operand_t     *g,
                             pka_operand_t     *public_key,
                             pka_operand_t     *hash,
                             dsa_signature_t   *signature)
{
    pka_cmp_code_t    comparison;

    if (SUCCESS != pka_dsa_signature_verify(handle, NULL, p, q, g,
                                        public_key, hash, signature, 0))
    {
        PKA_ERROR(PKA_TESTS,  "sync_dsa_verify failed\n");
        return FAILURE;
    }

    comparison = get_cmp_result(handle);
    if (comparison == RC_COMPARE_EQUAL)
        return SUCCESS;

    if (comparison == 0)
        PKA_ERROR(PKA_TESTS,  "sync_dsa_verify failed in get_cmp_result\n");

    return FAILURE;
}

//
// Test helper functions
//

static pka_operand_t *get_basic_answer(pka_handle_t     handle,
                                       pka_test_name_t  test_name,
                                       test_basic_t    *basic)
{
    switch (test_name)
    {
    case TEST_ADD:
        return sw_add(handle, basic->first, basic->second);

    case TEST_SUBTRACT:
        return sw_subtract(handle, basic->first, basic->second);

    case TEST_MULTIPLY:
        return sw_multiply(handle, basic->first, basic->second);

    case TEST_DIVIDE:
        return sw_divide(handle, basic->first, basic->second);

    case TEST_MODULO:
    case TEST_DIV_MOD:
        return sw_modulo(handle, basic->first, basic->second);

    case TEST_MOD_INVERT:
        return sw_mod_inverse(handle, basic->first, basic->second);

    case TEST_SHIFT_LEFT:
        return sw_shift_left(handle, basic->first, basic->shift_cnt);

    case TEST_SHIFT_RIGHT:
        return sw_shift_right(handle, basic->first, basic->shift_cnt);

    default:
        PKA_ASSERT(false);
        return NULL;
    }
}

static pka_status_t create_basic_test_descs(pka_handle_t     handle,
                                            pka_test_kind_t *test_kind,
                                            test_desc_t     *test_descs[],
                                            bool             make_answers,
                                            uint32_t         verbosity)
{
    pka_test_name_t test_name;
    test_basic_t   *basic;
    test_desc_t    *test_desc;
    uint32_t        num_key_systems, tests_per_key_system, test_desc_idx;
    uint32_t        key_cnt, test_cnt, bit_len, second_bit_len;

    test_name            = test_kind->test_name;
    num_key_systems      = test_kind->num_key_systems;
    tests_per_key_system = test_kind->tests_per_key_system;
    bit_len              = test_kind->bit_len;
    second_bit_len       = test_kind->second_bit_len;
    LOG(1, "Create %u random basic test systems:\n", num_key_systems);

    // First loop over the num_key_systems and then loop to create the
    // required number of basic tests per key_system.
    test_desc_idx = 0;
    for (key_cnt = 1;  key_cnt <= num_key_systems;  key_cnt++)
    {
        LOG(1, "Create %u basic tests (random operands and possible answer).\n",
            tests_per_key_system);

        for (test_cnt = 1;  test_cnt <= tests_per_key_system;  test_cnt++)
        {
            test_desc = calloc(1, sizeof(test_desc_t));
            basic     = calloc(1, sizeof(test_basic_t));
            if (test_name == TEST_MOD_INVERT)
            {
                basic->second = rand_prime_operand(handle, bit_len);
                basic->first  = rand_non_zero_integer(handle, basic->second);
            }
            else if ((test_name == TEST_DIVIDE)  ||
                     (test_name == TEST_DIV_MOD) ||
                     (test_name == TEST_MODULO))
            {
                basic->first  = rand_operand(handle, bit_len,        false);
                basic->second = rand_operand(handle, second_bit_len, true);
            }
            else if (test_name == TEST_SUBTRACT)
            {
                basic->first  = rand_operand(handle, bit_len, false);
                basic->second = rand_non_zero_integer(handle, basic->first);
            }
            else
            {
                basic->first  = rand_operand(handle, bit_len, false);
                basic->second = rand_operand(handle, bit_len, false);
            }

            basic->shift_cnt = rand() & 0x1F;
            if (make_answers)
            {
                LOG(2, "  calculate the answer using sofware algorithms.\n");
                basic->answer = get_basic_answer(handle, test_name, basic);
                if (test_name == TEST_DIV_MOD)
                    basic->answer2 = sw_divide(handle,
                                               basic->first,
                                               basic->second);
            }

            test_desc->test_kind        = test_kind;
            test_desc->key_system       = NULL;
            test_desc->test_operands    = basic;
            test_descs[test_desc_idx++] = test_desc;
        }
    }

    LOG(1, "Done creating the %u random basic test systems.\n",
        num_key_systems);
    return SUCCESS;
}

static mod_exp_key_system_t *create_mod_exp_keys(pka_handle_t  handle,
                                                 uint32_t      bit_len,
                                                 uint32_t      verbosity)
{
    mod_exp_key_system_t *mod_exp_keys;

    LOG(2, "  find one large random prime to be the modulus.\n");
    mod_exp_keys          = calloc(1, sizeof(mod_exp_key_system_t));
    mod_exp_keys->modulus = rand_prime_operand(handle, bit_len);
    if (mod_exp_keys->modulus == NULL)
        return NULL;

    return mod_exp_keys;
}

static test_mod_exp_t *create_mod_exp_test(pka_handle_t          handle,
                                           mod_exp_key_system_t *mod_exp_keys,
                                           bool                  make_answers,
                                           uint32_t              verbosity)
{
    test_mod_exp_t *mod_exp_test;
    pka_operand_t  *modulus;

    LOG(2, "  Find two large random integers to be the base and exponent.\n");
    modulus                = mod_exp_keys->modulus;
    mod_exp_test           = calloc(1, sizeof(test_mod_exp_t));
    mod_exp_test->base     = rand_non_zero_integer(handle, modulus);
    mod_exp_test->exponent = rand_non_zero_integer(handle, modulus);

    if (make_answers)
    {
        LOG(2, "  calculate the mod exp answer using sofware algorithms.\n");
        LOG(2, "    (note that this can take a while).\n");
        mod_exp_test->answer = sw_mod_exp(handle,
                                          mod_exp_test->exponent,
                                          modulus,
                                          mod_exp_test->base);
        LOG(2, "  done calculating the mod exp answer.\n");
    }

    return mod_exp_test;
}

static pka_status_t create_mod_exp_test_descs(pka_handle_t     handle,
                                              pka_test_kind_t *test_kind,
                                              test_desc_t     *test_descs[],
                                              bool             make_answers,
                                              uint32_t         verbosity)
{
    mod_exp_key_system_t *mod_exp_keys;
    pka_test_name_t       test_name;
    test_mod_exp_t       *test_mod_exp;
    test_desc_t          *test_desc;
    uint32_t              num_key_systems, tests_per_key_system, test_desc_idx;
    uint32_t              key_cnt, test_cnt, bit_len;

    test_name            = test_kind->test_name;
    num_key_systems      = test_kind->num_key_systems;
    tests_per_key_system = test_kind->tests_per_key_system;
    bit_len              = test_kind->bit_len;
    LOG(1, "Create %u modular exponentiation key systems:\n", num_key_systems);
    PKA_ASSERT(test_name == TEST_MOD_EXP);

    // First loop over the creation of the mod_exp_keys objects.  Then for each
    // mod_exp_key object create the required number of different mod-_xp tests.
    test_desc_idx = 0;
    for (key_cnt = 1;  key_cnt <= num_key_systems;  key_cnt++)
    {
        mod_exp_keys = create_mod_exp_keys(handle, bit_len, verbosity);
        if (mod_exp_keys == NULL)
            return FAILURE;

        LOG(1, "Create %u mod exp tests (random msg and possible answer).\n",
            tests_per_key_system);

        for (test_cnt = 1;  test_cnt <= tests_per_key_system;  test_cnt++)
        {
            test_desc    = calloc(1, sizeof(test_desc_t));
            test_mod_exp = create_mod_exp_test(handle, mod_exp_keys,
                                               make_answers, verbosity);

            test_desc->test_kind        = test_kind;
            test_desc->key_system       = mod_exp_keys;
            test_desc->test_operands    = test_mod_exp;
            test_descs[test_desc_idx++] = test_desc;
        }

        LOG(1, "Done creating the %u mod exp tests.\n", tests_per_key_system);
    }

    LOG(1, "Done creating the %u modular exponentiation key systems.\n",
        num_key_systems);
    return SUCCESS;
}

static pka_operand_t *power_of_two(pka_handle_t  handle,
                                   uint32_t      bit_len,
                                   bool          make_odd)
{
    pka_operand_t *result;
    uint32_t       byte_len, msb_idx, lsb_idx, num_msb_bits;

    byte_len           = (bit_len + 7) / 8;
    result             = malloc_operand(byte_len);
    result->actual_len = byte_len;
    result->big_endian = pka_get_rings_byte_order(handle);

    // Get the index of the most significant and least significant bytes.
    if (result->big_endian)
    {
        result->big_endian = 1;
        msb_idx            = 0;
        lsb_idx            = byte_len - 1;
    }
    else
    {
        result->big_endian = 0;
        msb_idx            = byte_len - 1;
        lsb_idx            = 0;
    }

    // Make sure the msb byte is non-zero and in fact is of the correct
    // bit len.
    num_msb_bits = bit_len - (8 * (byte_len - 1));
    PKA_ASSERT((1 <= num_msb_bits) && (num_msb_bits <= 8));

    result->buf_ptr[msb_idx] = 1 << (num_msb_bits - 1);
    if (make_odd)
        result->buf_ptr[lsb_idx] = 0x01;

    PKA_ASSERT(operand_bit_len(result) == bit_len);
    return result;
}

static rsa_key_system_t *create_rsa_keys(pka_handle_t       handle,
                                         pka_test_kind_t   *test_kind,
                                         uint32_t           verbosity)
{
    pka_cmp_code_t    a_b_order;
    rsa_key_system_t *keys;
    pka_operand_t    *a, *b, *p, *q, *d, *e, *q_qinv, *q_qinv_mod_p, *p_minus_1;
    pka_operand_t    *q_minus_1, *product, *prod_inv, *diff, *temp, *plus_one;
    uint32_t          bit_len;

    LOG(2, "  find two large random primes to be p and q.\n");
    bit_len   = test_kind->bit_len;
    a         = rand_prime_operand(handle, bit_len / 2);
    b         = rand_prime_operand(handle, bit_len / 2);
    a_b_order = pki_compare(a, b);
    if (a_b_order == RC_LEFT_IS_SMALLER)
    {
        p = b;
        q = a;
    }
    else if (a_b_order == RC_RIGHT_IS_SMALLER)
    {
        p = a;
        q = b;
    }
    else
        PKA_ASSERT(false);

    // Make sure e is coprime to (p - 1) * (q - 1).  This is done by making
    // e a big prime number (i.e. a prime just a little bigger than (p - 1)
    // and (q - 1)).
    LOG(2, "  pick a random prime to be the public key.\n");
    if (test_kind->test_name == TEST_RSA_VERIFY)
    {
        if (test_kind->second_bit_len == 0)
        {
            PKA_ERROR(PKA_TESTS,
                "TEST_RSA_VERIFY requires secondary bit length to be set\n");
            return NULL;
        }

        if (test_kind->second_bit_len == 17)
            e = make_operand(RSA_VERIFY_EXPON, sizeof(RSA_VERIFY_EXPON), true);
        else
        {
            e = power_of_two(handle, test_kind->second_bit_len, true);
            while (! is_prime(handle, e, 25, false))
            {
                // Increment e by 2 and try again
                temp = e;
                e    = sync_add(handle, temp, &TWO);
                free_operand(temp);
            }
        }
    }
    else
        e = rand_prime_operand(handle, (bit_len / 2) + 3);

    LOG(2, "  calculate (p - 1) * (q - 1).\n");
    p_minus_1 = sync_subtract(handle, p, &ONE);
    q_minus_1 = sync_subtract(handle, q, &ONE);
    product   = sync_multiply(handle, p_minus_1, q_minus_1);

    // Note that we can't use sync_mod_inverse directly to get e's inverse,
    // since the modulus (product) is even.  So instead we use the following
    // formula to handle cases where the modulus is even but the value to
    // invert is odd:
    //   d = (1 + (product * (e - mod_inverse(product, e)))) / e;
    LOG(2, "  calculate the private key using modular inverse.\n");
    prod_inv  = sync_mod_inverse(handle, product, e);
    diff      = sync_subtract(handle, e, prod_inv);
    temp      = sync_multiply(handle, product, diff);
    plus_one  = sync_add(handle, temp, &ONE);
    d         = sync_divide(handle, plus_one, e);

    // Derived values
    LOG(2, "  calculate q inverse and modulus (p * q).\n");
    keys              = calloc(1, sizeof(rsa_key_system_t));
    keys->p           = p;
    keys->q           = q;
    keys->d_p         = sync_modulo(handle, d, p_minus_1);
    keys->d_q         = sync_modulo(handle, d, q_minus_1);
    keys->qinv        = sync_mod_inverse(handle, q, p);
    keys->n           = sync_multiply(handle, p, q);
    keys->private_key = d;
    keys->public_key  = e;

    // Test qinv.  qinv * q mod p should be 1.
    LOG(2, "  test that qinv * q mod p == 1.\n");
    q_qinv       = sync_multiply(handle, keys->qinv, q);
    q_qinv_mod_p = sync_modulo(handle, q_qinv, p);

    if (! is_one(q_qinv_mod_p))
    {
        PKA_ERROR(PKA_TESTS,  "qinv * q mod p should be 1, but is instead\n");
        print_operand("", q_qinv_mod_p, "\n\n");
    }

    free_operand(q_qinv_mod_p);
    free_operand(p_minus_1);
    free_operand(q_minus_1);
    free_operand(product);
    free_operand(prod_inv);
    free_operand(diff);
    free_operand(temp);
    free_operand(plus_one);
    return keys;
}

static test_rsa_t *create_rsa_test(pka_handle_t       handle,
                                   pka_test_kind_t   *test_kind,
                                   rsa_key_system_t  *rsa_keys,
                                   bool               make_answers,
                                   uint32_t           verbosity)
{
    pka_operand_t *modulus, *exponent;
    test_rsa_t    *rsa_test;

    // Use the special (simpler) public key for RSA_VERIFY.
    modulus = rsa_keys->n;
    if (test_kind->test_name == TEST_RSA_VERIFY)
        exponent = rsa_keys->public_key;
    else
        exponent = rsa_keys->private_key;

    rsa_test = calloc(1, sizeof(test_rsa_t));

    LOG(2, "  create a random test msg to be encrypted by RSA.\n");
    rsa_test->msg = rand_non_zero_integer(handle, modulus);

    if (make_answers)
    {
        LOG(2, "  calculate the RSA answer using sofware algorithms.\n");
        LOG(2, "    (note that this can take a while).\n");
        rsa_test->answer = sw_mod_exp(handle, exponent, modulus,
                                            rsa_test->msg);
        LOG(2, "  done calculating the RSA answer.\n");
    }

    return rsa_test;
}

static pka_status_t create_rsa_test_descs(pka_handle_t       handle,
                                          pka_test_kind_t   *test_kind,
                                          test_desc_t       *test_descs[],
                                          bool               make_answers,
                                          uint32_t           verbosity)
{
    rsa_key_system_t *rsa_keys;
    pka_test_name_t   test_name;
    test_desc_t      *test_desc;
    test_rsa_t       *test_rsa;
    uint32_t          num_key_systems, tests_per_key_system, test_desc_idx;
    uint32_t          key_cnt, test_cnt;

    test_name            = test_kind->test_name;
    num_key_systems      = test_kind->num_key_systems;
    tests_per_key_system = test_kind->tests_per_key_system;
    LOG(1, "Create %u RSA key systems:\n", num_key_systems);

    PKA_ASSERT((test_name == TEST_RSA_MOD_EXP)          ||
               (test_name == TEST_RSA_VERIFY)           ||
               (test_name == TEST_RSA_MOD_EXP_WITH_CRT));

    // First loop over the creation of the rsa_keys objects.  Then for each
    // rsa_key object create the required number of different rsa tests.
    test_desc_idx = 0;
    for (key_cnt = 1; key_cnt <= num_key_systems; key_cnt++)
    {
        rsa_keys = create_rsa_keys(handle, test_kind, verbosity);

        LOG(1, "Create %u RSA tests (random msg and possible answer).\n",
            tests_per_key_system);

        for (test_cnt = 1; test_cnt <= tests_per_key_system; test_cnt++)
        {
            test_desc = calloc(1, sizeof(test_desc_t));
            test_rsa  = create_rsa_test(handle, test_kind, rsa_keys,
                                        make_answers, verbosity);

            test_desc->test_kind        = test_kind;
            test_desc->key_system       = rsa_keys;
            test_desc->test_operands    = test_rsa;
            test_descs[test_desc_idx++] = test_desc;
        }

        LOG(1, "Done creating the %u RSA tests.\n", tests_per_key_system);
    }

    LOG(1, "Done creating the %u RSA key systems.\n", num_key_systems);
    return SUCCESS;
}

uint8_t is_point_on_mont_curve(ecc_mont_curve_t *curve, ecc_point_t *point)
{
    pka_operand_t     y_squared, x_squared, x_cubed, x_sqrd_times_A, temp, rhs;
    pka_result_code_t rc;
    pka_cmp_code_t    comparison;
    uint8_t           bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t           bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t           big_endian;

    big_endian = curve->p.big_endian;
    PKA_ASSERT(big_endian == curve->A.big_endian);
    PKA_ASSERT(big_endian == point->x.big_endian);
    PKA_ASSERT(big_endian == point->y.big_endian);

    init_operand(&y_squared,      bufA, MAX_ECC_BUF, big_endian);
    init_operand(&x_squared,      bufB, MAX_ECC_BUF, big_endian);
    init_operand(&x_cubed,        bufC, MAX_ECC_BUF, big_endian);
    init_operand(&x_sqrd_times_A, bufD, MAX_ECC_BUF, big_endian);
    init_operand(&temp,           bufE, MAX_ECC_BUF, big_endian);
    init_operand(&rhs,            bufF, MAX_ECC_BUF, big_endian);

    // Need to compare "y^2 mod p" with "x^3 + A*x^2 + x mod p"
    rc = pki_mod_multiply(&point->y,  &point->y,       &curve->p, &y_squared);
    rc = pki_mod_multiply(&point->x,  &point->x,       &curve->p, &x_squared);
    rc = pki_mod_multiply(&x_squared, &point->x,       &curve->p, &x_cubed);
    rc = pki_mod_multiply(&x_squared, &curve->A,       &curve->p, &x_sqrd_times_A);
    rc = pki_mod_add(&x_cubed,        &x_sqrd_times_A, &curve->p, &temp);
    rc = pki_mod_add(&temp,           &point->x,       &curve->p, &rhs);

    comparison = pki_compare(&y_squared, &rhs);
    if (comparison != RC_COMPARE_EQUAL)
    {
        PKA_ERROR(PKA_TESTS,  " is_point_on_mont_curve comparison=%u\n",
                  comparison);
        print_operand("x                 =", &point->x,       "\n");
        print_operand("y                 =", &point->y,       "\n");
        print_operand("y^2 mod p         =", &y_squared,      "\n");
        print_operand("x^2 mod p         =", &x_squared,      "\n");
        print_operand("x^3 mod p         =", &x_cubed,        "\n");
        print_operand("A*x^2 mod p       =", &x_sqrd_times_A, "\n");
        print_operand("x^3 + A*x^2 mod p =", &temp,           "\n");
        print_operand("rhs               =", &rhs,            "\n\n");
        return 0;
    }

    return 1;
}

uint8_t is_point_on_curve(ecc_curve_t *curve, ecc_point_t *point)
{
    pka_operand_t     y_squared, x_squared, x_cubed, x_times_a, temp, rhs;
    pka_result_code_t rc;
    pka_cmp_code_t    comparison;
    uint8_t           bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t           bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t           big_endian;

    PKA_ASSERT(curve->p.big_endian == curve->a.big_endian);
    PKA_ASSERT(curve->p.big_endian == curve->b.big_endian);
    PKA_ASSERT(curve->p.big_endian == point->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == point->y.big_endian);
    big_endian = curve->p.big_endian;

    init_operand(&y_squared, bufA, MAX_ECC_BUF, big_endian);
    init_operand(&x_squared, bufB, MAX_ECC_BUF, big_endian);
    init_operand(&x_cubed,   bufC, MAX_ECC_BUF, big_endian);
    init_operand(&x_times_a, bufD, MAX_ECC_BUF, big_endian);
    init_operand(&temp,      bufE, MAX_ECC_BUF, big_endian);
    init_operand(&rhs,       bufF, MAX_ECC_BUF, big_endian);

    // Need to compare "y^2 mod p" with "x^3 + a*x + b mod p"
    rc = pki_mod_multiply(&point->y,  &point->y,  &curve->p, &y_squared);
    rc = pki_mod_multiply(&point->x,  &point->x,  &curve->p, &x_squared);
    rc = pki_mod_multiply(&x_squared, &point->x,  &curve->p, &x_cubed);
    rc = pki_mod_multiply(&point->x,  &curve->a,  &curve->p, &x_times_a);
    rc = pki_mod_add(&x_cubed,        &x_times_a, &curve->p, &temp);
    rc = pki_mod_add(&temp,           &curve->b,  &curve->p, &rhs);

    comparison = pki_compare(&y_squared, &rhs);

    if (comparison != RC_COMPARE_EQUAL)
    {
        PKA_ERROR(PKA_TESTS,  " is_point_on_curve comparison=%u\n", comparison);
        print_operand("x              =", &point->x,  "\n");
        print_operand("y              =", &point->y,  "\n");
        print_operand("y^2 mod p      =", &y_squared, "\n");
        print_operand("x^2 mod p      =", &x_squared, "\n");
        print_operand("x^3 mod p      =", &x_cubed,   "\n");
        print_operand("a*x mod p      =", &x_times_a, "\n");
        print_operand("x^3 + a*x mod p=", &temp,      "\n");
        print_operand("b              =", &curve->b,  "\n");
        print_operand("rhs            =", &rhs,       "\n\n");
        return 0;
    }

    return 1;
}

static mont_ecdh_keys_t *create_mont_ecdh_keys(pka_handle_t handle,
                                               uint32_t     bit_len,
                                               uint32_t     verbosity)
{
    mont_ecdh_keys_t *ecdh_keys;

    ecdh_keys = calloc(1, sizeof(mont_ecdh_keys_t));
    if (bit_len == 255)
    {
        ecdh_keys->curve         = &curve25519;
        ecdh_keys->base_pt_x     = &C255_base_pt->x;
        ecdh_keys->base_pt_order = C255_base_pt_order;
    }
    else if (bit_len == 448)
    {
        ecdh_keys->curve         = &curve448;
        ecdh_keys->base_pt_x     = &C448_base_pt->x;
        ecdh_keys->base_pt_order = C448_base_pt_order;
    }
    else
    {
        PKA_ERROR(PKA_TESTS,
                  "create_mont_ecdh_keys failed to select an ecc curve\n");
        return NULL;
    }

    return ecdh_keys;
}

static test_mont_ecdh_t *create_mont_ecdh_test(pka_handle_t      handle,
                                               pka_test_name_t   test_name,
                                               mont_ecdh_keys_t *ecdh_keys,
                                               uint32_t          bit_len,
                                               bool              make_answers,
                                               uint32_t          verbosity)
{
    ecc_mont_curve_t *curve;
    test_mont_ecdh_t *ecdh_test;
    pka_operand_t    *random_mult1, *random_mult2;
    pka_operand_t    *base_pt_x, *base_pt_order;
    pka_operand_t    *remote_private_key, *remote_public_key;
    uint32_t          rand_len;

    curve         = ecdh_keys->curve;
    base_pt_x     = ecdh_keys->base_pt_x;
    base_pt_order = ecdh_keys->base_pt_order;
    ecdh_test     = calloc(1, sizeof(test_mont_ecdh_t));
    rand_len      = bit_len - 4;

    LOG(2, "  find some large random integers to use as ECC test operands.\n");
    random_mult1       = rand_operand(handle, rand_len, false);
    random_mult2       = rand_operand(handle, rand_len, false);
    remote_private_key = rand_non_zero_integer(handle, base_pt_order);
    remote_public_key  = sw_mont_ecdh_multiply(handle, curve, base_pt_x,
                                               remote_private_key);

    ecdh_test->point_x = sw_mont_ecdh_multiply(handle, curve, base_pt_x,
                                               random_mult1);

    ecdh_test->multiplier         = random_mult2;
    ecdh_test->remote_private_key = remote_private_key;
    ecdh_test->remote_public_key  = remote_public_key;
    ecdh_test->answer             = NULL;

    if (make_answers == false)
        return ecdh_test;

    LOG(2, "  calculate the ECC answer using sofware algorithms.\n");
    LOG(2, "    (note that this can take awhile).\n");
    if (test_name == TEST_MONT_ECDH_MULTIPLY)
        ecdh_test->answer = sw_mont_ecdh_multiply(handle, curve,
                                                  ecdh_test->point_x,
                                                  ecdh_test->multiplier);
    else if (test_name == TEST_MONT_ECDH)
        ecdh_test->answer = sw_mont_ecdh_multiply(handle, curve,
                                                  remote_public_key,
                                                  remote_private_key);
    else
        PKA_ASSERT(false);

    return ecdh_test;
}

static pka_status_t create_mont_ecdh_test_descs(pka_handle_t     handle,
                                                pka_test_kind_t *test_kind,
                                                test_desc_t     *test_descs[],
                                                bool             make_answers,
                                                uint32_t         verbosity)
{
    mont_ecdh_keys_t *ecdh_keys;
    test_mont_ecdh_t *ecdh_test;
    pka_test_name_t   test_name;
    test_desc_t      *test_desc;
    uint32_t          num_key_systems, tests_per_key_system;
    uint32_t          test_desc_idx, key_cnt, test_cnt, bit_len;

    test_name            = test_kind->test_name;
    num_key_systems      = test_kind->num_key_systems;
    tests_per_key_system = test_kind->tests_per_key_system;
    bit_len              = test_kind->bit_len;
    LOG(1, "Create %u Montgomery ECDH key systems:\n", num_key_systems);

    PKA_ASSERT((test_name == TEST_MONT_ECDH_MULTIPLY) ||
               (test_name == TEST_MONT_ECDH) || (test_name == TEST_MONT_ECDHE));
    if (test_name == TEST_MONT_ECDHE)
       make_answers = false;

    init_mont_curves();

    // First loop over the creation of the ecdh_keys objects.  Then for each
    // ecdh_key object create the required number of different ecdh tests.
    test_desc_idx = 0;
    for (key_cnt = 1;  key_cnt <= num_key_systems;  key_cnt++)
    {
        ecdh_keys = create_mont_ecdh_keys(handle, bit_len, verbosity);

        LOG(1, "Create %u Montgomery ECDH tests (random msg and possible answer).\n",
            tests_per_key_system);

        for (test_cnt = 1;  test_cnt <= tests_per_key_system;  test_cnt++)
        {
            ecdh_test = create_mont_ecdh_test(handle, test_name, ecdh_keys,
                                              bit_len, make_answers, verbosity);
            test_desc = calloc(1, sizeof(test_desc_t));

            test_desc->test_kind        = test_kind;
            test_desc->key_system       = ecdh_keys;
            test_desc->test_operands    = ecdh_test;
            test_descs[test_desc_idx++] = test_desc;
        }

        LOG(1, "Done creating the %u Montgomery ECDH tests.\n",
            tests_per_key_system);
    }

    LOG(1, "Done creating the %u Montgomery ECDH key systems.\n",
        num_key_systems);
    return SUCCESS;
}

static ecc_key_system_t *create_ecc_keys(pka_handle_t  handle,
                                         uint32_t      bit_len,
                                         uint32_t      verbosity)
{
    ecc_key_system_t *ecc_keys;
    pka_operand_t    *p, *a, *b, *x, *y, *y_squared, *x_squared, *x_cubed;
    pka_operand_t    *x_times_a, *temp;

    LOG(2, "  find a large random prime to be the ECC curve modulus.\n");
    LOG(2, "  find three random integers to be the ECC curve a, x and y.\n");
    p = rand_prime_operand(handle, bit_len);
    a = rand_non_zero_integer(handle, p);
    x = rand_non_zero_integer(handle, p);
    y = rand_non_zero_integer(handle, p);

    // Now determine curve->b as = y^2 - (x^3 + a*x) mod p.
    LOG(2, "  calculate the ECC curve param b based on chosen p,a,x and y.\n");
    y_squared = sync_mod_multiply(handle, y, y, p);
    x_squared = sync_mod_multiply(handle, x, x, p);
    x_cubed   = sync_mod_multiply(handle, x_squared, x, p);
    x_times_a = sync_mod_multiply(handle, x, a, p);
    temp      = sync_mod_add(handle, x_cubed, x_times_a, p);
    b         = sync_mod_subtract(handle, y_squared, temp, p);

    ecc_keys             = calloc(1, sizeof(ecc_key_system_t));
    ecc_keys->curve      = create_ecc_curve(p, a, b);
    ecc_keys->base_pt    = calloc(1, sizeof(ecc_point_t));
    set_ecc_point(ecc_keys->base_pt, x, y);

    PKA_ASSERT(is_point_on_curve(ecc_keys->curve, ecc_keys->base_pt));
    free_operand(y_squared);
    free_operand(x_squared);
    free_operand(x_cubed);
    free_operand(x_times_a);
    free_operand(temp);
    free_operand(p);
    free_operand(a);
    free_operand(b);
    free_operand(x);
    free_operand(y);
    return ecc_keys;
}

static test_ecc_t *create_ecc_test(pka_handle_t      handle,
                                   pka_test_name_t   test_name,
                                   ecc_key_system_t *ecc_key,
                                   uint32_t          bit_len,
                                   bool              make_answers,
                                   uint32_t          verbosity)
{
    pka_operand_t *random_mult1, *random_mult2;
    ecc_curve_t   *curve;
    ecc_point_t   *base_pt;
    test_ecc_t    *ecc_test;
    uint32_t       rand_len;

    curve    = ecc_key->curve;
    base_pt  = ecc_key->base_pt;
    ecc_test = calloc(1, sizeof(test_ecc_t));
    rand_len = bit_len - 4;

    LOG(2, "  find some large random integers to use as ECC test operands.\n");
    random_mult1     = rand_operand(handle, rand_len, false);
    random_mult2     = rand_operand(handle, rand_len, false);
    ecc_test->pointA = sw_ecc_multiply(handle, curve, base_pt, random_mult1);
    ecc_test->pointB = sw_ecc_multiply(handle, curve, base_pt, random_mult2);
    ecc_test->multiplier = random_mult2;

    if ((! is_point_on_curve(curve, ecc_test->pointA)) ||
        (! is_point_on_curve(curve, ecc_test->pointB)))
    {
        PKA_ERROR(PKA_TESTS,
                "create_ecc_add_params point A and/or B not on curve\n");
        return NULL;
    }

    if (make_answers == false)
        return ecc_test;

    LOG(2, "  calculate the ECC answer using sofware algorithms.\n");
    LOG(2, "    (note that this can take awhile).\n");
    if (test_name == TEST_ECC_ADD)
        ecc_test->answer = sw_ecc_add(handle, curve, ecc_test->pointA,
                                      ecc_test->pointB);
    else if (test_name == TEST_ECC_DOUBLE)
        ecc_test->answer = sw_ecc_add(handle, curve, ecc_test->pointA,
                                      ecc_test->pointA);
    else if (test_name == TEST_ECC_MULTIPLY)
        ecc_test->answer = sw_ecc_multiply(handle, curve, ecc_test->pointA,
                                           ecc_test->multiplier);
    else
        PKA_ASSERT(false);

    LOG(2, "  done calculating the ECC answer.\n");
    if (! is_point_on_curve(curve, ecc_test->answer))
    {
        PKA_ERROR(PKA_TESTS,
                "create_ecc_add_params result point not on curve\n");
        return NULL;
    }

    return ecc_test;
}

static pka_status_t create_ecc_test_descs(pka_handle_t       handle,
                                          pka_test_kind_t   *test_kind,
                                          test_desc_t       *test_descs[],
                                          bool               make_answers,
                                          uint32_t           verbosity)
{
    ecc_key_system_t *ecc_key;
    pka_test_name_t   test_name;
    test_desc_t      *test_desc;
    test_ecc_t       *ecc_test;
    uint32_t          num_key_systems, tests_per_key_system, test_desc_idx;
    uint32_t          key_cnt, test_cnt, bit_len;

    test_name            = test_kind->test_name;
    num_key_systems      = test_kind->num_key_systems;
    tests_per_key_system = test_kind->tests_per_key_system;
    bit_len              = test_kind->bit_len;
    LOG(1, "Create %u ECC key systems:\n", num_key_systems);

    PKA_ASSERT((test_name == TEST_ECC_ADD) ||
               (test_name == TEST_ECC_DOUBLE) ||
               (test_name == TEST_ECC_MULTIPLY));

    // First loop over the creation of the ecc_keys objects.  Then for each
    // ecc_key object create the required number of different ecc tests.
    test_desc_idx = 0;
    for (key_cnt = 1;  key_cnt <= num_key_systems;  key_cnt++)
    {
        ecc_key = create_ecc_keys(handle, bit_len, verbosity);

        LOG(1, "Create %u ECC tests (random msg and possible answer).\n",
            tests_per_key_system);

        for (test_cnt = 1;  test_cnt <= tests_per_key_system;  test_cnt++)
        {
            ecc_test  = create_ecc_test(handle, test_name, ecc_key, bit_len,
                                        make_answers, verbosity);
            test_desc = calloc(1, sizeof(test_desc_t));

            test_desc->test_kind        = test_kind;
            test_desc->key_system       = ecc_key;
            test_desc->test_operands    = ecc_test;
            test_descs[test_desc_idx++] = test_desc;
        }

        LOG(1, "Done creating the %u ECC tests.\n", tests_per_key_system);
    }

    LOG(1, "Done creating the %u ECC key systems.\n", num_key_systems);
    return SUCCESS;
}

static ecc_curve_t *select_ecc_curve(pka_handle_t  handle,
                                     uint32_t      bit_len)
{
    if (bit_len == 256)
        return P256_ecdsa.curve;
    else if (bit_len == 384)
        return P384_ecdsa.curve;
    else if (bit_len == 521)
        return P521_ecdsa.curve;
    else
        return NULL;
}

static ecc_point_t *select_base_pt(pka_handle_t    handle,
                                   ecc_curve_t    *curve,
                                   uint32_t        bit_len,
                                   pka_operand_t **base_pt_order)
{
    if (bit_len == 256)
    {
        *base_pt_order = P256_ecdsa.base_pt_order;
        return P256_ecdsa.base_pt;
    }
    else if (bit_len == 384)
    {
        *base_pt_order = P384_ecdsa.base_pt_order;
        return P384_ecdsa.base_pt;
    }
    else if (bit_len == 521)
    {
        *base_pt_order = P521_ecdsa.base_pt_order;
        return P521_ecdsa.base_pt;
    }
    else
        return NULL;
}

static ec_key_system_t *create_ec_key_system(pka_handle_t  handle,
                                             uint32_t      p_bit_len,
                                             char         *key_system,
                                             uint32_t      verbosity)
{
    ec_key_system_t *ec_keys;
    pka_operand_t   *base_pt_order, *d;
    ecc_curve_t     *curve;
    ecc_point_t     *base_pt, *public_pt;

    // Select curve.
    LOG(2, "  select a standard ECC curve for this %s key system\n",
            key_system);
    curve = select_ecc_curve(handle, p_bit_len);
    if (curve == NULL)
    {
        PKA_ERROR(PKA_TESTS,
                "create_ec_key_system failed to select an ecc curve\n");
        return NULL;
    }

    // Pick base_pt with appropriate base_pt_order.
    LOG(2, "  select a base_pt with the appropriate base_pt_order\n");
    base_pt = select_base_pt(handle, curve, p_bit_len, &base_pt_order);
    if (base_pt == NULL)
    {
        PKA_ERROR(PKA_TESTS,
            "create_ec_key_system failed to find a suitable base_pt\n");
        return NULL;
    }

    // Finally create a private/public key pair.
    LOG(2, "  create a %s private/public key pair.\n", key_system);
    d          = rand_non_zero_integer(handle, base_pt_order);
    public_pt  = sync_ecc_multiply(handle, curve, base_pt, d);

    ec_keys                = calloc(1, sizeof(ec_key_system_t));
    ec_keys->curve         = curve;
    ec_keys->base_pt       = base_pt;
    ec_keys->base_pt_order = base_pt_order;
    ec_keys->private_key   = d;
    ec_keys->public_key    = public_pt;
    return ec_keys;
}

static ecdh_key_system_t *create_ecdh_key_system(pka_handle_t  handle,
                                                 uint32_t      p_bit_len,
                                                 uint32_t      verbosity)
{
    return create_ec_key_system(handle, p_bit_len, "ECDH", verbosity);
}

static ecdsa_key_system_t *create_ecdsa_key_system(pka_handle_t  handle,
                                                   uint32_t      p_bit_len,
                                                   uint32_t      verbosity)
{
    return create_ec_key_system(handle, p_bit_len, "ECDSA", verbosity);
}

static test_ecdh_t *create_ecdh_test(pka_handle_t       handle,
                                     ecdh_key_system_t *ecdh_keys,
                                     bool               make_answers,
                                     uint32_t           verbosity)
{
    pka_operand_t *remote_private_key;
    ecc_point_t   *remote_public_key, *answer;
    test_ecdh_t   *ecdh_test;

    LOG(2, "  create random ECDH operands.\n");

    remote_private_key = rand_non_zero_integer(handle,
                                               ecdh_keys->base_pt_order);
    remote_public_key  = sync_ecc_multiply(handle, ecdh_keys->curve,
                                           ecdh_keys->base_pt,
                                           remote_private_key);

    answer = NULL;
    if (make_answers)
    {
        LOG(2, "  calculate the ECDH secret using sofware algorithms.\n");
        answer = sync_ecc_multiply(handle, ecdh_keys->curve,
                                   remote_public_key,
                                   ecdh_keys->private_key);
        // *TBD*
        LOG(2, "  done calculating the ECDH shared secret.\n");
    }


    ecdh_test                     = calloc(1, sizeof(test_ecdh_t));
    ecdh_test->remote_private_key = remote_private_key;
    ecdh_test->remote_public_key  = remote_public_key;
    ecdh_test->answer             = answer;
    return ecdh_test;
}

static pka_status_t create_ecdh_test_descs(pka_handle_t       handle,
                                           pka_test_kind_t   *test_kind,
                                           test_desc_t       *test_descs[],
                                           bool               make_answers,
                                           uint32_t           verbosity)
{
    ecdh_key_system_t *ecdh_keys;
    pka_test_name_t    test_name;
    test_desc_t       *test_desc;
    test_ecdh_t       *ecdh_test;
    uint32_t           num_key_systems, tests_per_key_system, test_desc_idx;
    uint32_t           key_cnt, test_cnt, p_bit_len;

    test_name            = test_kind->test_name;
    p_bit_len            = test_kind->bit_len;
    num_key_systems      = test_kind->num_key_systems;
    tests_per_key_system = test_kind->tests_per_key_system;
    LOG(1, "Create %u ECDH key systems:\n", num_key_systems);

    PKA_ASSERT((test_name == TEST_ECDH) || (test_name == TEST_ECDHE));
    if (test_name == TEST_ECDHE)
       make_answers = false;

    // First loop over the creation of the ecdh_keys objects.  Then for each
    // ecdh_key object create the required number of different ecdh tests.
    test_desc_idx = 0;
    for (key_cnt = 1;  key_cnt <= num_key_systems;  key_cnt++)
    {
        ecdh_keys = create_ecdh_key_system(handle, p_bit_len, verbosity);

        LOG(1, "Create %u ECDH tests (random msg and possible answer).\n",
            tests_per_key_system);

        for (test_cnt = 1;  test_cnt <= tests_per_key_system;  test_cnt++)
        {
            ecdh_test = create_ecdh_test(handle, ecdh_keys, make_answers,
                                         verbosity);
            test_desc  = calloc(1, sizeof(test_desc_t));

            test_desc->test_kind        = test_kind;
            test_desc->key_system       = ecdh_keys;
            test_desc->test_operands    = ecdh_test;
            test_descs[test_desc_idx++] = test_desc;
        }

        LOG(1, "Done creating the %u ECDH tests.\n", tests_per_key_system);
    }

    LOG(1, "Done creating the %u ECDH key systems.\n", num_key_systems);
    return SUCCESS;
}

static test_ecdsa_t *create_ecdsa_test(pka_handle_t        handle,
                                       pka_test_kind_t    *test_kind,
                                       ecdsa_key_system_t *ecdsa_keys,
                                       bool                make_answers,
                                       uint32_t            verbosity)
{
    dsa_signature_t *answer, *signature;
    pka_operand_t   *base_pt_order, *c, *n_minus_1, *temp, *k, *hash;
    test_ecdsa_t    *ecdsa_test;
    uint32_t         n, hash_len;
    uint8_t          big_endian;

    LOG(2, "  create the random ECDSA operands like the hash and secret k.\n");
    base_pt_order = ecdsa_keys->base_pt_order;
    n             = operand_bit_len(base_pt_order);
    c             = rand_operand(handle, n + 64, false);
    n_minus_1     = sync_subtract(handle, base_pt_order, &ONE);
    temp          = sync_modulo(handle, c, n_minus_1);
    k             = sync_add(handle, temp, &ONE);

    hash_len   = n - 16;  // *TBD*
    hash       = rand_operand(handle, hash_len, false);
    big_endian = pka_get_rings_byte_order(handle);
    signature  = malloc_dsa_signature(MAX_ECC_BUF, MAX_ECC_BUF, big_endian);
    answer     = NULL;

    if ((make_answers) || (test_kind->test_name == TEST_ECDSA_VERIFY))
    {
        LOG(2, "  calculate the ECDSA signature using sofware algorithms.\n");
        answer = sw_ecdsa_gen(handle,
                              ecdsa_keys->curve,
                              ecdsa_keys->base_pt,
                              ecdsa_keys->base_pt_order,
                              ecdsa_keys->private_key,
                              hash,
                              k);
        LOG(2, "  done calculating the ECDSA signature.\n");
    }

    free_operand(c);
    free_operand(n_minus_1);
    free_operand(temp);

    ecdsa_test            = calloc(1, sizeof(test_ecdsa_t));
    ecdsa_test->k         = k;
    ecdsa_test->hash      = hash;
    ecdsa_test->signature = signature;
    ecdsa_test->answer    = answer;
    return ecdsa_test;
}

static pka_status_t create_ecdsa_test_descs(pka_handle_t       handle,
                                            pka_test_kind_t   *test_kind,
                                            test_desc_t       *test_descs[],
                                            bool               make_answers,
                                            uint32_t           verbosity)
{
    ecdsa_key_system_t *ecdsa_keys;
    pka_test_name_t     test_name;
    test_desc_t        *test_desc;
    test_ecdsa_t       *ecdsa_test;
    uint32_t            num_key_systems, tests_per_key_system, test_desc_idx;
    uint32_t            key_cnt, test_cnt, p_bit_len;

    test_name            = test_kind->test_name;
    p_bit_len            = test_kind->bit_len;
    num_key_systems      = test_kind->num_key_systems;
    tests_per_key_system = test_kind->tests_per_key_system;
    LOG(1, "Create %u ECDSA key systems:\n", num_key_systems);

    PKA_ASSERT((test_name == TEST_ECDSA_GEN)    ||
               (test_name == TEST_ECDSA_VERIFY) ||
               (test_name == TEST_ECDSA_GEN_VERIFY));

    // First loop over the creation of the ecdsa_keys objects.  Then for each
    // ecdsa_key object create the required number of different ecdsa tests.
    test_desc_idx = 0;
    for (key_cnt = 1;  key_cnt <= num_key_systems;  key_cnt++)
    {

        ecdsa_keys = create_ecdsa_key_system(handle, p_bit_len, verbosity);

        LOG(1, "Create %u ECDSA tests (random msg and possible answer).\n",
            tests_per_key_system);

        for (test_cnt = 1;  test_cnt <= tests_per_key_system;  test_cnt++)
        {
            ecdsa_test = create_ecdsa_test(handle, test_kind, ecdsa_keys, make_answers,
                                           verbosity);
            test_desc  = calloc(1, sizeof(test_desc_t));

            test_desc->test_kind        = test_kind;
            test_desc->key_system       = ecdsa_keys;
            test_desc->test_operands    = ecdsa_test;
            test_descs[test_desc_idx++] = test_desc;
        }

        LOG(1, "Done creating the %u ECDSA tests.\n", tests_per_key_system);
    }

    LOG(1, "Done creating the %u ECDSA key systems.\n", num_key_systems);
    return SUCCESS;
}

static pka_status_t create_dsa_p_and_q(pka_handle_t    handle,
                                       pka_operand_t **p_ptr,
                                       pka_operand_t **q_ptr,
                                       uint32_t        p_bit_len,
                                       uint32_t        q_bit_len)
{
    pka_operand_t *p, *q, *X, *c, *c_minus_1, *q_times_2;
    uint32_t       counter;

    // Generate prime numbers p and q.
    p = NULL;
    while (true)
    {
        q = rand_prime_operand(handle, q_bit_len);
        if (q == NULL)
            return FAILURE;

        q_times_2 = sync_add(handle, q, q);
        for (counter = 0;  counter < (4 * p_bit_len) - 1;  counter++)
        {
            X         = rand_operand(handle, p_bit_len, true);
            c         = sync_modulo(handle, X, q_times_2);
            c_minus_1 = sync_subtract(handle, c, &ONE);
            p         = sync_subtract(handle, X, c_minus_1);

            free_operand(X);
            free_operand(c);
            free_operand(c_minus_1);
            if ((operand_bit_len(p) == p_bit_len) &&
                is_prime(handle, p, 25, false))
            {
                // *TBD* Check that sync_modulus(handle, p, q_times_2) == 1.
                *p_ptr = p;
                *q_ptr = q;
                // free_operand(&q_times_2);
                return SUCCESS;
            }
        }

        free_operand(p);
        free_operand(q);
        free_operand(q_times_2);
    }

    return FAILURE;
}

static pka_operand_t *create_dsa_g(pka_handle_t   handle,
                                   pka_operand_t *p,
                                   pka_operand_t *q,
                                   uint32_t       p_bit_len)
{
    pka_operand_t *p_minus_1, *exponent, *temp, *h, *g, *next_h, *mod_exp;
    uint32_t       counter;

    // Generate generator g.
    p_minus_1  = sync_subtract(handle, p, &ONE);
    exponent   = sync_divide(handle, p_minus_1, q);
    temp       = rand_operand(handle, p_bit_len - 2, true);
    h          = sync_add(handle, temp, &ONE);
    // The above construction of h should ensure that 1 < h < p_minus_1!

    for (counter = 1;  counter < 100;  counter++)
    {
        g = sync_mod_exp(handle, exponent, p, h);
        if (pki_compare(g, &ONE) == RC_RIGHT_IS_SMALLER)
        {
            // Note that 2 <= g <= p-1 && g^q mod p == 1.
            PKA_ASSERT(pki_compare(g, p) == RC_LEFT_IS_SMALLER);
            mod_exp = sync_mod_exp(handle, q, p, g);
            PKA_ASSERT(pki_compare(mod_exp, &ONE) == RC_COMPARE_EQUAL);
            free_operand(h);
            free_operand(mod_exp);
            return g;
        }

        next_h = sync_add(handle, h, &ONE);
        free_operand(h);
        h = next_h;
    }

    return NULL;
}

static dsa_key_system_t *create_dsa_key_system(pka_handle_t  handle,
                                               uint32_t      p_bit_len,
                                               uint32_t      q_bit_len,
                                               uint32_t      verbosity)
{
    dsa_key_system_t *dsa_keys;
    pka_operand_t    *c, *q_minus_1, *temp, *x, *y;
    pka_status_t      status;

    // Generate prime numbers p and q.
    LOG(2, "  find two large random primes to be p and q for DSA.\n");
    dsa_keys = calloc(1, sizeof(dsa_key_system_t));
    status   = create_dsa_p_and_q(handle, &dsa_keys->p, &dsa_keys->q,
                                  p_bit_len, q_bit_len);
    if (status != SUCCESS)
    {
        PKA_ERROR(PKA_TESTS,
                  "create_dsa_key_system failed to create p and q\n");
        return NULL;
    }

    // Generate generator g.
    LOG(2, "  generate the DSA generator g.\n");
    dsa_keys->g = create_dsa_g(handle, dsa_keys->p, dsa_keys->q, p_bit_len);
    if (dsa_keys->g == NULL)
    {
        PKA_ERROR(PKA_TESTS,
                "create_dsa_key_system failed to generate a generator\n");
        return NULL;
    }

    // Finally create a private/public key pair.
    LOG(2, "  create a DSA private/public key pair.\n");
    c          = rand_operand(handle, q_bit_len + 64, false);
    q_minus_1  = sync_subtract(handle, dsa_keys->q, &ONE);
    temp       = sync_modulo(handle, c, q_minus_1);
    x          = sync_add(handle, temp, &ONE);
    y          = sync_mod_exp(handle, x, dsa_keys->p, dsa_keys->g);

    free_operand(c);
    free_operand(q_minus_1);
    free_operand(temp);

    // Note that private_key is in the range 1 .. q-1 and the public_key is
    // in the range 1..prime-1.
    dsa_keys->private_key = x;
    dsa_keys->public_key  = y;
    return dsa_keys;
}

static test_dsa_t *create_dsa_test(pka_handle_t      handle,
                                   pka_test_kind_t  *test_kind,
                                   dsa_key_system_t *dsa_keys,
                                   uint32_t          q_bit_len,
                                   bool              make_answers,
                                   uint32_t          verbosity)
{
    dsa_signature_t *signature, *answer;
    pka_operand_t   *c, *q_minus_1, *temp, *k, *hash;
    test_dsa_t      *dsa_test;
    uint32_t         hash_len;
    uint8_t          big_endian;

    LOG(2, "  create a random DSA operands like the hash and secret k.\n");
    c          = rand_operand(handle, q_bit_len + 64, false);
    q_minus_1  = sync_subtract(handle, dsa_keys->q, &ONE);
    temp       = sync_modulo(handle, c, q_minus_1);
    k          = sync_add(handle, temp, &ONE);

    hash_len   = q_bit_len;  // *TBD*
    hash       = rand_operand(handle, hash_len, false);
    big_endian = pka_get_rings_byte_order(handle);
    signature  = malloc_dsa_signature(MAX_BUF, MAX_BUF, big_endian);
    answer     = NULL;

    if ((make_answers) || (test_kind->test_name == TEST_DSA_VERIFY))
    {
        LOG(2, "  calculate the DSA signature using sofware algorithms.\n");
        answer = sw_dsa_gen(handle,
                            dsa_keys->p,
                            dsa_keys->q,
                            dsa_keys->g,
                            dsa_keys->private_key,
                            hash,
                            k);
        LOG(2, "  done calculating the DSA signature.\n");
    }

    free_operand(c);
    free_operand(q_minus_1);
    free_operand(temp);

    dsa_test            = calloc(1, sizeof(test_dsa_t));
    dsa_test->k         = k;
    dsa_test->hash      = hash;
    dsa_test->signature = signature;
    dsa_test->answer    = answer;
    return dsa_test;
}

static pka_status_t create_dsa_test_descs(pka_handle_t     handle,
                                          pka_test_kind_t *test_kind,
                                          test_desc_t     *test_descs[],
                                          bool             make_answers,
                                          uint32_t         verbosity)
{
    dsa_key_system_t *dsa_keys;
    pka_test_name_t   test_name;
    test_desc_t      *test_desc;
    test_dsa_t       *dsa_test;
    uint32_t          num_key_systems, tests_per_key_system, test_desc_idx;
    uint32_t          key_cnt, test_cnt, p_bit_len, q_bit_len;

    test_name            = test_kind->test_name;
    p_bit_len            = test_kind->bit_len;
    q_bit_len            = test_kind->second_bit_len;
    num_key_systems      = test_kind->num_key_systems;
    tests_per_key_system = test_kind->tests_per_key_system;
    LOG(1, "Create %u DSA key systems:\n", num_key_systems);

    PKA_ASSERT((test_name == TEST_DSA_GEN)    ||
               (test_name == TEST_DSA_VERIFY) ||
               (test_name == TEST_DSA_GEN_VERIFY));

    if (q_bit_len == 0)
    {
        PKA_ERROR(PKA_TESTS,  "create_dsa_test_descs error. Need to set the "
               "secondary bit_len\n");
        return FAILURE;
    }

    // First loop over the creation of the dsa_keys objects.  Then for each
    // dsa_key object create the required number of different dsa tests.
    test_desc_idx = 0;
    for (key_cnt = 1;  key_cnt <= num_key_systems;  key_cnt++)
    {
        dsa_keys = create_dsa_key_system(handle, p_bit_len, q_bit_len,
                                         verbosity);

        LOG(1, "Create %u DSA tests (random msg and possible answer).\n",
            tests_per_key_system);

        for (test_cnt = 1;  test_cnt <= tests_per_key_system;  test_cnt++)
        {
            dsa_test  = create_dsa_test(handle, test_kind, dsa_keys, q_bit_len,
                                        make_answers, verbosity);
            test_desc = calloc(1, sizeof(test_desc_t));

            test_desc->test_kind        = test_kind;
            test_desc->key_system       = dsa_keys;
            test_desc->test_operands    = dsa_test;
            test_descs[test_desc_idx++] = test_desc;
        }

        LOG(1, "Done creating the %u DSA tests.\n", tests_per_key_system);
    }

    LOG(1, "Done creating the %u DSA key systems.\n", num_key_systems);
    return SUCCESS;
}

pka_status_t create_pka_test_descs(pka_handle_t     handle,
                                   pka_test_kind_t *test_kind,
                                   test_desc_t     *test_descs[],
                                   bool             make_answers,
                                   uint32_t         verbosity)
{
    // PKA_ASSERT(test_desc->test_category == PKA_TEST);

    switch (test_kind->test_name)
    {
    case TEST_ADD:
    case TEST_SUBTRACT:
    case TEST_MULTIPLY:
    case TEST_DIVIDE:
    case TEST_DIV_MOD:
    case TEST_MODULO:
    case TEST_SHIFT_LEFT:
    case TEST_SHIFT_RIGHT:
    case TEST_MOD_INVERT:
        return create_basic_test_descs(handle, test_kind, test_descs,
                                       make_answers, verbosity);

    case TEST_MOD_EXP:
        return create_mod_exp_test_descs(handle, test_kind, test_descs,
                                         make_answers, verbosity);

    case TEST_RSA_MOD_EXP:
    case TEST_RSA_VERIFY:
    case TEST_RSA_MOD_EXP_WITH_CRT:
        return create_rsa_test_descs(handle, test_kind, test_descs,
                                     make_answers, verbosity);

    case TEST_MONT_ECDH_MULTIPLY:
    case TEST_MONT_ECDH:
    case TEST_MONT_ECDHE:
        return create_mont_ecdh_test_descs(handle, test_kind, test_descs,
                                           make_answers, verbosity);

    case TEST_ECC_ADD:
    case TEST_ECC_DOUBLE:
    case TEST_ECC_MULTIPLY:
        return create_ecc_test_descs(handle, test_kind, test_descs,
                                     make_answers, verbosity);

    case TEST_ECDH:
    case TEST_ECDHE:
        return create_ecdh_test_descs(handle, test_kind, test_descs,
                                      make_answers, verbosity);
    case TEST_ECDSA_GEN:
    case TEST_ECDSA_VERIFY:
    case TEST_ECDSA_GEN_VERIFY:
        return create_ecdsa_test_descs(handle, test_kind, test_descs,
                                       make_answers, verbosity);

    case TEST_DSA_GEN:
    case TEST_DSA_VERIFY:
    case TEST_DSA_GEN_VERIFY:
        return create_dsa_test_descs(handle, test_kind, test_descs,
                                     make_answers, verbosity);

    default:
        PKA_ASSERT(false);
    }
}

void free_pka_test_descs(test_desc_t *test_descs[])
{
}

pka_status_t chk_bit_lens(pka_test_kind_t *test_kind)
{
    switch (test_kind->test_name)
    {
    case TEST_ADD:
    case TEST_SUBTRACT:
    case TEST_MULTIPLY:
    case TEST_SHIFT_LEFT:
    case TEST_SHIFT_RIGHT:
    case TEST_MOD_INVERT:
        // test_kind->bit_len must be in range 33 .. 4096
        if ((33 <= test_kind->bit_len) && (test_kind->bit_len <= 4096))
            return SUCCESS;

        PKA_ERROR(PKA_TESTS,
            "Basic tests require bit_len to be in the range 33..4096\n");
        return FAILURE;

    case TEST_DIVIDE:
    case TEST_DIV_MOD:
    case TEST_MODULO:
        // test_kind->bit_len must be in range 33 .. 4096
        // test_kind->second_bit_len must be in the range 33..4095 AND
        // test_kind->second_bit_len must be <= test_kind->bit_len
        if ((33 <= test_kind->bit_len) && (test_kind->bit_len <= 4096) &&
            (33 <= test_kind->second_bit_len) &&
            (test_kind->second_bit_len <= test_kind->bit_len))
            return SUCCESS;

        PKA_ERROR(PKA_TESTS,
            "Divide/modulo tests require bit_len to be in the range "
            "33..4096 and 33 <= second_bit <= bit_len\n");
        return FAILURE;

    case TEST_MOD_EXP:
        // test_kind->bit_len must be in range 33 .. 4096
        if ((33 <= test_kind->bit_len) && (test_kind->bit_len <= 4096))
            return SUCCESS;

        PKA_ERROR(PKA_TESTS,
            "ModExp tests require bit_len to be in the range 33..4096\n");
        return FAILURE;

    case TEST_RSA_VERIFY:
        // test_kind->bit_len must be in range 66 .. 4096 and
        // test_kind->second_bit_len must be in the range 9..4095 AND
        // test_kind->second_bit_len must be < test_kind->bit_len
        if ((66 <= test_kind->bit_len) && (test_kind->bit_len <= 4096) &&
            (9 <= test_kind->second_bit_len) &&
            (test_kind->second_bit_len < test_kind->bit_len))
            return SUCCESS;

        PKA_ERROR(PKA_TESTS,
            "RSA Verify tests require bit_len to be in the range 66..4096 "
            "and 9 <= second_bit < bit_len\n");
        return FAILURE;

    case TEST_RSA_MOD_EXP:
    case TEST_RSA_MOD_EXP_WITH_CRT:
        // test_kind->bit_len must be in range 66 .. 4096
        if ((66 <= test_kind->bit_len) && (test_kind->bit_len <= 4096))
            return SUCCESS;

        PKA_ERROR(PKA_TESTS,
            "RsaModExp tests (with or without CRT) require bit_len "
            "to be in the range 66..4096\n");
        return FAILURE;

    case TEST_MONT_ECDH_MULTIPLY:
    case TEST_MONT_ECDH:
    case TEST_MONT_ECDHE:
        // test_kind->bit_len must either 255 or 448
        if ((test_kind->bit_len == 255) || (test_kind->bit_len == 448))
            return SUCCESS;

        PKA_ERROR(PKA_TESTS,
            "Montgomery ECDH multiply tests are only supported for curve25519 "
            "or curve448\n");
        return FAILURE;

    case TEST_ECC_ADD:
    case TEST_ECC_DOUBLE:
    case TEST_ECC_MULTIPLY:
        // test_kind->bit_len must be in range 33 .. 4096
        if ((33 <= test_kind->bit_len) && (test_kind->bit_len <= 521))
            return SUCCESS;

        if ((522 <= test_kind->bit_len) && (test_kind->bit_len <= 4096))
        {
            PKA_ERROR(PKA_TESTS,
                   "WARNING bit lengths > 521 for ECC tests are valid, but\n"
                   "are not recommended since they can take a very long\n"
                   "time and also do not reflect real ECC systems\n");
            return SUCCESS;
        }

        PKA_ERROR(PKA_TESTS,
            "ECC tests require bit_len to be in the range 33..4096\n");
        return FAILURE;

    case TEST_ECDH:
    case TEST_ECDHE:
        // test_kind->bit_len MUST equal 256, 384 or 521
        if ((test_kind->bit_len == 256) || (test_kind->bit_len == 384) ||
	    (test_kind->bit_len == 521))
            return SUCCESS;

        PKA_ERROR(PKA_TESTS,
                  "ECDH tests require bit_len to be either 256, 384 "
                  "or 521\n");
        return FAILURE;

    case TEST_ECDSA_GEN:
    case TEST_ECDSA_VERIFY:
    case TEST_ECDSA_GEN_VERIFY:
        // test_kind->bit_len MUST equal 256, 384 or 521
        if ((test_kind->bit_len == 256) || (test_kind->bit_len == 384) ||
	    (test_kind->bit_len == 521))
            return SUCCESS;

        PKA_ERROR(PKA_TESTS,
                  "ECDSA tests require bit_len to be either 256, 384 "
                  "or 521\n");
        return FAILURE;

    case TEST_DSA_GEN:
    case TEST_DSA_VERIFY:
    case TEST_DSA_GEN_VERIFY:
        // test_kind->bit_len must be in range 33 .. 4096 and
        // test_kind->second_bit_len must be in the range 9..4095 AND
        // test_kind->second_bit_len must be < test_kind->bit_len
        // The standard DSA domain parameters are:
        //     bit_len = 1024 second_bit_len = 160
        //     bit_len = 2048 second_bit_len = 224
        //     bit_len = 2048 second_bit_len = 256
        //     bit_len = 3072 second_bit_len = 256
        if ((33 <= test_kind->bit_len) && (test_kind->bit_len <= 4096) &&
            (9 <= test_kind->second_bit_len) &&
            (test_kind->second_bit_len < test_kind->bit_len))
            return SUCCESS;

        PKA_ERROR(PKA_TESTS,
            "DSA tests require bit_len to be in the range 33..4096 "
            "and 9 <= second_bit < bit_len\n");
        return FAILURE;

    default:
        PKA_ASSERT(false);
        return FAILURE;
    }
}

void check_ecc_dsa(pka_handle_t        handle,
                   ecdsa_key_system_t *ecdsa_keys,
                   test_ecdsa_t       *ecdsa_test,
                   pka_operand_t      *kinv)
{
    pka_operand_t *k_times_kinv;

    if (! is_valid_curve(handle, ecdsa_keys->curve))
        PKA_ERROR(PKA_TESTS,  "check_ecc_dsa bad curve\n");

    if (! is_point_on_curve(ecdsa_keys->curve, ecdsa_keys->base_pt))
        PKA_ERROR(PKA_TESTS,  "check_ecc_dsa base_pt NOT on curve\n");

    if (! is_point_on_curve(ecdsa_keys->curve, ecdsa_keys->public_key))
        PKA_ERROR(PKA_TESTS,  "check_ecc_dsa public key NOT on curve\n");

    k_times_kinv = sync_mod_multiply(handle, ecdsa_test->k, kinv,
                                     ecdsa_keys->base_pt_order);

    if (! is_one(k_times_kinv))
    {
        PKA_ERROR(PKA_TESTS,
            "init_ecc_values (k * k_inv) mod n doesn't equal 1\n");
        print_operand("k           =", ecdsa_test->k, "\n");
        print_operand("kinv        =", kinv,          "\n");
        print_operand("k_times_kinv=", k_times_kinv,  "\n");
    }
}

static void init_ecc_values(uint8_t big_endian)
{
    ecc_curve_t *P256, *P384, *P521;
    ecc_point_t *P256_base_pt, *P384_base_pt, *P521_base_pt;

    P256 = make_ecc_curve(P256_p_buf, sizeof(P256_p_buf),
                          P256_a_buf, sizeof(P256_a_buf),
                          P256_b_buf, sizeof(P256_b_buf),
                          big_endian);
    P384 = make_ecc_curve(P384_p_buf, sizeof(P384_p_buf),
                          P384_a_buf, sizeof(P384_a_buf),
                          P384_b_buf, sizeof(P384_b_buf),
                          big_endian);
    P521 = make_ecc_curve(P521_p_buf, sizeof(P521_p_buf),
                          P521_a_buf, sizeof(P521_a_buf),
                          P521_b_buf, sizeof(P521_b_buf),
                          big_endian);

    C255_base_pt = make_mont_ecc_point(&curve25519,
                                       Curve255_bp_u_buf,
                                       sizeof(Curve255_bp_u_buf),
                                       Curve255_bp_v_buf,
                                       sizeof(Curve255_bp_u_buf),
                                       big_endian);

    P256_base_pt = make_ecc_point(P256,
                                  P256_xg_buf, sizeof(P256_xg_buf),
                                  P256_yg_buf, sizeof(P256_yg_buf),
                                  big_endian);
    P384_base_pt = make_ecc_point(P384,
                                  P384_xg_buf, sizeof(P384_xg_buf),
                                  P384_yg_buf, sizeof(P384_yg_buf),
                                  big_endian);
    C448_base_pt = make_mont_ecc_point(&curve448,
                                       Curve448_bp_u_buf, sizeof(Curve448_bp_u_buf),
                                       Curve448_bp_v_buf, sizeof(Curve448_bp_u_buf),
                                       big_endian);
    P521_base_pt = make_ecc_point(P521,
                                  P521_xg_buf, sizeof(P521_xg_buf),
                                  P521_yg_buf, sizeof(P521_yg_buf),
                                  big_endian);

    C255_base_pt_order = make_operand(Curve255_bp_order_buf,
                                      sizeof(Curve255_bp_order_buf),
                                      big_endian);

    C448_base_pt_order = make_operand(Curve448_bp_order_buf,
                                      sizeof(Curve448_bp_order_buf),
                                      big_endian);

    // Set up P256_ecdsa* params
    P256_ecdsa.curve         = P256;
    P256_ecdsa.base_pt       = P256_base_pt;
    P256_ecdsa.base_pt_order = make_operand(P256_n_buf,
                                            sizeof(P256_n_buf),
                                            big_endian);
    P256_ecdsa.private_key   = make_operand(P256_d_buf,
                                            sizeof(P256_d_buf),
                                            big_endian);
    P256_ecdsa.public_key    = make_ecc_point(NULL,
                                              P256_xq_buf, sizeof(P256_xq_buf),
                                              P256_yq_buf, sizeof(P256_yq_buf),
                                              big_endian);

    P256_kinv                = make_operand(P256_kinv_buf,
                                            sizeof(P256_kinv_buf),
                                            big_endian);
    P256_ecdsa_test.hash     = make_operand(P256_hash_buf,
                                            sizeof(P256_hash_buf),
                                            big_endian);
    P256_ecdsa_test.k        = make_operand(P256_k_buf,
                                            sizeof(P256_k_buf),
                                            big_endian);

    P256_ecdsa_test.signature = calloc(1, sizeof(dsa_signature_t));
    P256_ecdsa_test.signature->s.big_endian = big_endian;
    make_operand_buf(&P256_ecdsa_test.signature->s,
                     P256_s_buf,
                     sizeof(P256_s_buf));

    // Set up P384_ecdsa* params
    P384_ecdsa.curve         = P384;
    P384_ecdsa.base_pt       = P384_base_pt;
    P384_ecdsa.base_pt_order = make_operand(P384_n_buf,
                                            sizeof(P384_n_buf),
                                            big_endian);
    P384_ecdsa.private_key   = make_operand(P384_d_buf,
                                            sizeof(P384_d_buf),
                                            big_endian);
    P384_ecdsa.public_key    = make_ecc_point(NULL,
                                              P384_xq_buf, sizeof(P384_xq_buf),
                                              P384_yq_buf, sizeof(P384_yq_buf),
                                              big_endian);

    P384_kinv               = make_operand(P384_kinv_buf,
                                           sizeof(P384_kinv_buf),
                                           big_endian);
    P384_ecdsa_test.hash    = make_operand(P384_hash_buf,
                                           sizeof(P384_hash_buf),
                                           big_endian);
    P384_ecdsa_test.k       = make_operand(P384_k_buf,
                                           sizeof(P384_k_buf),
                                           big_endian);

    P384_ecdsa_test.signature = calloc(1, sizeof(dsa_signature_t));
    P384_ecdsa_test.signature->s.big_endian = big_endian;
    make_operand_buf(&P384_ecdsa_test.signature->s,
                     P384_s_buf, sizeof(P384_s_buf));

    // Set up P521_ecdsa* params
    P521_ecdsa.curve         = P521;
    P521_ecdsa.base_pt       = P521_base_pt;
    P521_ecdsa.base_pt_order = make_operand(P521_n_buf,
                                            sizeof(P521_n_buf),
                                            big_endian);

    // *TBD*
    //if (! is_valid_curve(handle, P521_ecdsa.curve))
    //    PKA_ERROR(PKA_TESTS,  "init_ecc_values P521 bad curve\n");

    //if (! is_point_on_curve(P521_ecdsa.curve, P521_ecdsa.base_pt))
    //    PKA_ERROR(PKA_TESTS,  "init_ecc_values P521 base_pt NOT on curve\n");

    return;
}

void init_test_utils(pka_handle_t handle)
{
    uint8_t big_endian;

    big_endian      = pka_get_rings_byte_order(handle);
    ZERO.big_endian = big_endian;
    ONE.big_endian  = big_endian;
    TWO.big_endian  = big_endian;
    init_ecc_values(0);
}

pka_status_t get_rand_bytes(pka_handle_t  handle,
                            uint8_t      *buf,
                            uint32_t      buf_len)
{
    int fd;

    if ((fd = open("/dev/hwrng", O_RDONLY | O_NONBLOCK)) != -1)
    {
        if (read(fd, buf, buf_len) < 0)
            return FAILURE;
        close(fd);
        return SUCCESS;
    }
    else
    {
        if (errno == EACCES)
        {
            PKA_ERROR(PKA_TESTS,
                "unpriviliged user, access denied for /dev/hwrng\n");
        }
        else
        {
            PKA_ERROR(PKA_TESTS,  "failed to open /dev/hwrng\n");
        }
        exit(1);
    }

    return FAILURE;
}
