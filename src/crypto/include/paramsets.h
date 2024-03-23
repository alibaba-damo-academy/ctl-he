#pragma once
#include "sealutil.h"
namespace seal
{


enum ParamSet { RLWE,
                RGSW,
                LWE,
                RLWELittle };

struct RLWEParams {
    static constexpr bool use_special_prime = true;
    static constexpr seal::scheme_type scheme_type = seal::scheme_type::bfv;
    // static constexpr bool use_special_prime = true;
    // for 786433/65536/32768
    // static constexpr size_t poly_logn = 15;
    // for test
    // for Keyswtich test
    static constexpr size_t poly_logn = 15;
    static constexpr size_t poly_modulus_degree = (1ULL << poly_logn);
    // static constexpr size_t poly_modulus_degree = 8192;
    // for 786433
    // static constexpr const int coeff_modulus_size = 17;
    // for 65537
    static constexpr const int coeff_modulus_size = 12;
    // for 32768
    // static constexpr const int coeff_modulus_size = 14;
    // static constexpr const int coeff_modulus_size = 12;
    // for test
    // static constexpr const int coeff_modulus_size = 2;
    // static constexpr const int bits[coeff_modulus_size] = {50, 30,...,30 for 19 times , 59}
    // for 786433 degree
    // static constexpr int bits[coeff_modulus_size] = { 50, 60,60,50,50,50,50,50,50,50,50,50,50,50,50,50, 59 };
    // for 65537 degree
    // static constexpr int bits[coeff_modulus_size] = { 50, 50,50,50,50,50,50,50,50,50,50,50,50, 59 };
    // static constexpr int bits[coeff_modulus_size] = { 45, 60,60,60,60,60,60,60,60,60,60, 60 }; // best
    static constexpr int bits[coeff_modulus_size] = { 60, 60,60,60,60,60,60,60,60,60,60, 60 }; // e2e
    // static constexpr int bits[coeff_modulus_size] = { 60, 60,60,60,60,60,60, 60 }; // 383 best
    // static constexpr int bits[coeff_modulus_size] = { 60, 60,60,60,60,60,60, 60}; // 383 e2e
    // static constexpr int bits[coeff_modulus_size] = { 60, 60,60,60,60,60,60,60,60,60,60,50, 60 };
    // for 32768
    // static constexpr int bits[coeff_modulus_size] = { 50, 50,50,50,50,50,50,50,50,50,50,50,50, 59 };
    // for test
    // Key switch test
    // static constexpr int bits[coeff_modulus_size] = { 26,26,26,26,26,26 }; // successful
    // static constexpr int bits[coeff_modulus_size] = { 21, 21, 21, 60 }; // successful
    // static constexpr int bits[coeff_modulus_size] = { 50, 50,50,50,50, 50 };
    static constexpr size_t lognmod = 2;
    // static constexpr uint64_t plain_modulus = (1ULL << 40);
    // Batch auto create palin_modulus
    // static constexpr uint64_t plain_modulus = 21;
    // specific plai_modulus
    // static constexpr uint64_t plain_modulus = 786433;
    static constexpr uint64_t plain_modulus = 65537;

    // for LWE test
    // static constexpr uint64_t plain_modulus = (1ULL << 40);
    // change to bits
    // digit extraction(CKKS clean)
};

struct RGSWParams {
    static constexpr seal::scheme_type scheme_type = RLWEParams::scheme_type;
    static constexpr size_t poly_logn = RLWEParams::poly_logn;
    static constexpr size_t poly_modulus_degree = RLWEParams::poly_modulus_degree;
    static constexpr size_t coeff_modulus_size = RLWEParams::coeff_modulus_size - (RLWEParams::use_special_prime ? 1 : 0);
    static constexpr uint64_t plain_modulus = RLWEParams::plain_modulus;
    static constexpr size_t lognmod = RLWEParams::lognmod;
    static constexpr size_t decompose_level = 8;
    static constexpr size_t decompose_log_base = 16;
    static constexpr size_t decompose_base = (1ULL << decompose_log_base);
};

struct LWEParams {
    static constexpr seal::scheme_type scheme_type = RLWEParams::scheme_type;
    static constexpr size_t poly_logn = 12; // shoud be a even number, because n is a square number!
    static constexpr size_t poly_modulus_degree = (1ULL << poly_logn);
    static constexpr size_t coeff_modulus_size = 1;
    static constexpr size_t npoly = RLWEParams::poly_modulus_degree / poly_modulus_degree;
    static constexpr uint64_t plain_modulus = RLWEParams::plain_modulus;
    static constexpr size_t lognmod = 0;
    // static constexpr size_t decompose_level = 2;
    // static constexpr size_t decompose_log_base = 13;
    // static constexpr size_t decompose_level = 15;
    static constexpr size_t decompose_level = 15;
    static constexpr size_t decompose_log_base = RLWEParams::bits[0] / decompose_level; // should equals to last modulo coefficient
    static constexpr size_t decompose_base = (1ULL << decompose_log_base);
};

struct RLWEParamsLittle{
    static constexpr bool use_special_prime = true;
    static constexpr seal::scheme_type scheme_type = seal::scheme_type::bfv;
    static constexpr size_t poly_logn = LWEParams::poly_logn;
    static constexpr size_t poly_modulus_degree = (1ULL << poly_logn);
    static constexpr const int coeff_modulus_size = 1;
    static constexpr size_t lognmod = 2;
    static constexpr uint64_t plain_modulus = 65537;
    static constexpr size_t npoly = RLWEParams::poly_modulus_degree / poly_modulus_degree;
    static constexpr size_t decompose_level = LWEParams::decompose_level;
    static constexpr size_t decompose_log_base = LWEParams::decompose_log_base; // should equals to last modulo coefficient
};

} // namespace seal


/*
        +----------------------------------------------------+
        | poly_modulus_degree | max coeff_modulus bit-length |
        +---------------------+------------------------------+
        | 1024                | 27                           |
        | 2048                | 54                           |
        | 4096                | 109                          |
        | 8192                | 218                          |
        | 16384               | 438                          |
        | 32768               | 881                          |ls
        +---------------------+------------------------------+
*/