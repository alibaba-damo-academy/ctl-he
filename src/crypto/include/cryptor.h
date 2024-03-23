#pragma once
#include "paramsets.h"
#include "sealutil.h"
#include <map>
#include <functional>

namespace seal
{
using RLWECipher = Ciphertext; // Define a type alias for Ciphertext as RLWECipher
using VecData = std::vector<uint64_t>; // Define a type alias for std::vector<uint64_t> as VecData
using MatrixData = std::vector<VecData>; // Define a type alias for std::vector<VecData> as MatrixData
using LWECipher = VecData;
using RLevCipher = std::vector<RLWECipher>;
using RGSWCipher = std::vector<RLevCipher>;
using KSRGSWCipher = KSwitchKeys;
using KSRLevCipher = std::vector<PublicKey>;
using KSBootKey = std::vector<KSRGSWCipher>;

namespace util
{
  class TFHERNSTool;
  class DRaMOp;
}

// AES S-box
const uint8_t sbox[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};
const uint8_t inverse_sbox[16][16] = {
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0xBE, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};

// Define the Cryptor class
class Cryptor
{
  public:
    // Default constructor for the Cryptor class
    Cryptor(void);

    // DEBUG: Mannualy little key switch
    void kswitch_little(const RLWECipher &ilwe, RLWECipher &olwe) const;
    void generate_rlwe_little_kswitchkey(void ) const;
    

    // DEBUG: Mannualy rotate
    void gen_rt_key_little(void) const;
    void rotation_little(const RLWECipher &ilwe, const size_t &step, RLWECipher &olwe) const;

    // generate kskey form database
    void gen_kskey_database(void) const;
    void kswitch_database(const RLWECipher &ilwe, std::vector<RLWECipher> &vec_olwe) const;

    // lwe vector ciphertext addition
    void lwe_add(const std::vector<LWECipher> &ilwe_1, const std::vector<LWECipher> &ilwe_2, const uint64_t &Q, std::vector<LWECipher> &olwe) const;

    // LWE copy function
    void lwe_copy(const std::vector<LWECipher> &lwe1, std::vector<LWECipher> &lwe2) const;

    // Pack LWE to RLWE
    void packlwes(const std::vector<LWECipher> &lwevec, RLWECipher &rlwe, const bool withtrace) const;

    // Scale down lwe by factor alpha / q
    void lwe_scale_down(const uint64_t &q, const uint64_t &alpha, std::vector<LWECipher> &lwe_vec) const;

    // LWE negative in Q
    void lwe_neg(const uint64_t &Q, std::vector<LWECipher> &lwe_vec) const;

    // LWE - LWE mod Q
    void lwe_sub(const std::vector<LWECipher> &ilwe_1, const std::vector<LWECipher> &ilwe_2, const uint64_t &Q, std::vector<LWECipher> &olwe) const;

    // LWE add beta(b' = b + beta)
    void lwe_add_beta(const std::vector<LWECipher> &ilwe, const uint64_t &Q, const uint64_t &beta, std::vector<LWECipher> &olwe, const bool &if_print=true) const;

    // construct LWE for HomoFloor and HomoSign
    void construct_lwe_sign(const uint64_t &bit, const uint64_t &Q, std::vector<LWECipher> &vec_lwe) const;
    // LWE vector all encrypt bit
    void construct_lwe_XOR(const uint64_t &bit, const uint64_t &Q, std::vector<LWECipher> &vec_lwe) const;
    // LWE vector encrypt 1~16
    void construct_lwe_AES(const uint64_t &Q, std::vector<LWECipher> &vec_lwe) const;

    // mod LWE from Q to q
    void lwe_mod_q(const std::vector<LWECipher> &lwe_Q, std::vector<LWECipher> &lwe_q) const;

    // add bias to lwe b
    void lwe_add_b (LWECipher &ilwe, const uint64_t &bias, const uint64_t &Q) const;

    // Detect beta range
    void beta_detection() const;

    // LWE pre inverse
    void LWEpreinverse(LWECipher &lwe, const uint64_t scale) const;

    // field trace
    void field_trace(RLWECipher &rlwe, const size_t nslot, const size_t cur_nslot = RGSWParams::poly_modulus_degree) const;

    // Print noise budget
    void print_noise(const RLWECipher &rlwe, const ParamSet paramset) const;

    // Construct LWE for BatchPBS
    void construct_lwe(const uint64_t &message, std::vector<LWECipher> &vec_lwe) const;

    // KeyAddition of AES
    void KeyAddition(const uint64_t &Q, std::vector<LWECipher> &state_vec_lwe, const std::vector<LWECipher> &key_vec_lwe) const;
    void SubBytes(const uint64_t &Q, std::vector<LWECipher> &state_vec_lwe) const;
    void ShiftRows(const uint64_t &Q, std::vector<LWECipher> &state_vec_lwe) const;
    void MixColum(const uint64_t &Q, std::vector<LWECipher> &state_vec_lwe) const;

    // HomoSign
    void HomoSign(const uint64_t &Q, const uint64_t &alpha, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe, uint64_t &final_sign) const;

    // HomoFloor
    void HomoFloor(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe) const;
    void HomoFloor(const uint64_t &Q, std::vector<LWECipher> &input_vec_lwe) const;

    // BatchPBS
    void BatchPBS(const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe) const;

    // BatchPBS customize version
    void Batch_Customize(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe, const util::DRaMOp& dramOp) const;

    // Batch High 4bit extraction
    void Batch_ExtractHigh4bit(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe) const;

    // Batch Low 4bit extraction
    void Batch_ExtractLow4bit(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe) const;

    // Batch XOR High 4bit (9 bit version)
    void Batch_HighXOR9bit(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe) const;

    // Batch XOR High 4bit
    void Batch_HighXOR(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe) const;

    // Batch XOR Low 4bit
    void Batch_LowXOR(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe) const;

    // Batch for sign extract
    void Batch_sign(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe) const;

    // Batch for f0
    void Batch_f0(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe) const;

    // Batch for f1
    void Batch_f1(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe) const;

    // Initialize matrix A from many "a" of LWE
    void initial_A(const std::vector<LWECipher> &vec_lwe, MatrixData &matrix_A) const;
    // Initialize plaintext b from many "b" of LWE
    void initial_b(const std::vector<LWECipher> &vec_lwe, Plaintext &ptxt_b) const;
    // Initialize secret key to plaintext
    void initial_s(Ciphertext &ctxt_seckey) const;

    // Function to encrypt plain data
    void encrypt(const VecData &plain, RLWECipher &cipher, const ParamSet paramset = ParamSet::RLWE) const;
    void encrypt(const Plaintext &ptxt, RLWECipher &rlwe, const ParamSet paramset = ParamSet::RLWE) const;
    void encrypt(const util::RNSIter &new_key, KSRLevCipher &rlev) const;
    void encrypt(const uint64_t key, KSRGSWCipher &rgsw) const;
    void encrypt(const util::RNSIter &new_key, RLevCipher &rlev, const ParamSet paramset) const;

    // Function to encode
    void encode(const VecData &message, Plaintext &ptxt, ParamSet paramset = ParamSet::RLWE) const;
    void encode_manual(const VecData &message, Plaintext &ptxt) const;
    void decode(const Plaintext &ptxt, VecData &message, ParamSet paramset = ParamSet::RLWE) const;
    void decode_manual(const Plaintext &ptxt, VecData &message) const;

    // NTT Check function using either seal extracted or generated matrix
    void NTT_manual(const Plaintext &ptxt) const;
    void iNTT_manual(const Plaintext &ptxt) const;
    void doubleNTT_manual(const Plaintext &ptxt) const;

    // NTT Transform function using either seal extracted or generated matrix
    void NTT_manual_trans(const VecData &poly, VecData &result) const;
    void iNTT_manual_trans(const VecData &poly, VecData &result) const;
    void NTT_manual_seal(const VecData &poly, VecData &result) const;
    void iNTT_manual_seal(const VecData &poly, VecData &result) const;

    // Function to decrypt cipher data
    void decrypt(const RLWECipher &rlwe, Plaintext &ptxt, ParamSet paramset = ParamSet::RLWE) const;
    void decrypt(const RLWECipher &cipher, VecData &plain, ParamSet paramset = ParamSet::RLWE) const;
    uint64_t decrypt(const LWECipher &lwe, const ParamSet paramset) const;
    // mannual test decrypt procedure
    void decrypt_manual_test(void) const;
    // manual lwe decryption
    void lwe_manual_decrypt(const LWECipher &lwe, uint64_t &result, const bool &have_modswitched=false, uint64_t new_mod=0, uint64_t new_plain=0) const;

    // Function to get the evaluator
    const Evaluator &get_evaluator(void) const;

    // RLWE mod switch to last
    void mod_to_last(RLWECipher &rlwe);

    // Function to perform a linear transformation on the cipher
    void LinearTransform(RLWECipher &cipher, MatrixData A) const;

    // Test Double LT 
    void TestDoubleLT(RLWECipher &bfvct, MatrixData A) const;

    // Function to compute all powers of ciphertext according to degree
    void Compute_all_powers(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers) const;

    // Same as above but modswitch when meet bound
    void Compute_all_powers_bound(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers, int switch_bound, std::vector<int> mul_count) const;

    // Square Optimization
    void Compute_all_powers_square_opt(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers, int switch_bound, std::vector<int> mul_count) const;
    
    // Compute all powers in multi-threads
    void Compute_all_powers_in_parallel(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers, int switch_bound, std::vector<int> mul_count) const;

    // Compute all powers in pyramid
    void Compute_all_powers_in_pyramid(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers, int switch_bound, std::vector<int> mul_count) const;
    
    // Relin Improve
    void Compute_all_powers_relin_improve(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers, int switch_bound, std::vector<int> mul_count) const;

    // Function to evaluate an interpolation polynomial on the cipher using tree method
    void PolyEvalTree(const VecData &coeffs, RLWECipher &cipher) const;
    
    // Function to evaluate an interpolation polynomial using tree method on a given cipher and output another cipher
    void PolyEvalTree(const VecData &coefficients, const RLWECipher &icipher, RLWECipher &ocipher) const;

    // Function to evaluate an interpolation polynomial using BSGS method on a given cipher and output another cipher
    void PolyEvalBSGS(const VecData &coefficients, const RLWECipher &icipher, RLWECipher &ocipher) const;

    // Function to evaluate an interpolation polynomial using Horner method on a given cipher and output another cipher
    void PolyEvalHorner(const VecData &coefficients, const RLWECipher &icipher, RLWECipher &ocipher) const;

    // Function to perform BatchPBS on the cipher
    void BatchPBS(RLWECipher &cipher) const;

    void dot_product(std::vector<Plaintext> &pts, int skip, const std::vector<RLWECipher> &ctx, RLWECipher &destination) const;

    void dot_product_vec(const VecData &vec_coeff, int skip, const std::vector<RLWECipher> &ctx, RLWECipher &destination) const;

    void Test_Square_Opt(const RLWECipher &icipher1, const RLWECipher &icipher2) const;

    void pack_mul_test(RLWECipher &ictxt, const uint64_t &message) const;
    
    // ptxt + (- ctxt) (used for -b + as in TFHE Bootstrapping)
    void negate_add_plain(const RLWECipher &rlwe, const Plaintext &ptxt, RLWECipher &orlwe) const;
    // ptxt + ctxt
    void ctxt_add_plain(const RLWECipher &irlwe, const Plaintext &ptxt, RLWECipher &orlwe) const;

    // transform ciphertext from slot to coefficients
    void CtxtSlot2Coeff(const RLWECipher &ictxt, RLWECipher &octxt) const;
    void CtxtCoeff2Slot(const RLWECipher &ictxt, RLWECipher &octxt) const;

    // S2C DFT -> Extract -> Add LWE
    void S2C_no_Add(const RLWECipher &ictxt, std::vector<LWECipher> &veclwe) const;
    void GenS2CPtxt(const size_t idx, Plaintext &ptxt_s2c) const;
    
    // S2C after Keyswitch, better parallelism
    void S2C_no_Add_after_KS(const std::vector<seal::RLWECipher> rlwe_l_vec, std::vector<LWECipher> &veclwe) const;

    // Generate transform matrix in S2C
    void GenEncodeMatrix(MatrixData& matrix_encode) const;
    void GenDecodeMatrix(MatrixData& matrix_decode) const;

    // Generate NTT matrix
    void GenNttMatrix(MatrixData& matrix_NTT) const;
    void GenNttRevMatrix(MatrixData& matrix_NTT) const;
    void GenNTTMatrixManual(MatrixData& matrix_NTT_manual) const;
    void GeniNttMatrix(MatrixData& matrix_iNTT) const;
    void GeniNttRevMatrix(MatrixData& matrix_iNTT) const;
    void GeniNTTMatrixManual(MatrixData& matrix_NTT_manual) const;

    // get first modulus
    Modulus get_first_modulus() const;

    // Manual ModSwitch for LWE
    // void ModSwitchLWE(const LWECipher &ilwe, uint64_t dest_mod, LWECipher &olwe) const;
    void ModSwitchLWE(const LWECipher &ilwe, const uint64_t &dest_plain, const uint64_t &dest_mod, LWECipher &olwe) const;

    // Analyze where the noise comes from
    void NoiseAnal() const;

    // TFHE part
    // Generate lwe secret key
    void generate_lweseckey(void) const;

    // extract LWE encrypting plaintext coefficient p[idx] from RLWE encrypting polynomial p
    void SampleExtract(const RLWECipher &rlwe, LWECipher &lwe, const size_t idx, const bool mod_switch, const ParamSet paramset) const;
    void vecSampleExtract(const RLWECipher &rlwe, std::vector<LWECipher> &vec_lwe, const ParamSet paramset) const;

    // Trivial way transform LWE to RLWE with valid location at polynomial constant coefficient(other location of plaintext are invalid)
    void LWEtoRLWE(const LWECipher &lwe, RLWECipher &rlwe) const;

    // LWE * Scalar (not correct)
    void LWEMultScalar(const LWECipher &ilwe, uint64_t scalar, LWECipher &olwe) const;

    // LWE Keyswitch
    void lwekeyswitch(const LWECipher &ilwe, LWECipher &olwe) const;
    void veclwekeyswtich(const std::vector<LWECipher> &ilwe_vec, const size_t &number, std::vector<LWECipher> &olwe_vec) const;

    // RLWE Keyswitch
    void rlwekeyswitch(const RLWECipher &ilwe, std::vector<RLWECipher> &vec_olwe) const;

    // RLWE Keyswitch for arbitary mod size
    void switch_key_inplace(
    Ciphertext &encrypted, util::ConstRNSIter target_iter, const KSwitchKeys &kswitch_keys, size_t kswitch_keys_index,
    MemoryPoolHandle pool) const;
    void rlwekeyswitch_arbitary(const RLWECipher &ilwe, std::vector<RLWECipher> &vec_olwe) const;
    void rlwekeyswitch_seal(const RLWECipher &ilwe, std::vector<RLWECipher> &vec_olwe) const;
    void rlwekeyswitch_arbitary_trash(const RLWECipher &ilwe, std::vector<RLWECipher> &vec_olwe) const;

    // RLWE context and mod check
    void rlwe_context_mod_check();

    // Generate LWE keyswtich key
    void generate_lweswitchkeys(void) const;

    void keyswitch(const util::ConstRNSIter &poly, const RLevCipher &rlev, RLWECipher &rlwe, const ParamSet paramset) const;
    
    // get LWE secret key
    const Plaintext &get_lwe_seckey(void) const;

    // construct LWE element
    void construct_lwe_element(MatrixData &matrix_lwe_A, VecData &vec_lwe_b);

    // Sub poly element wise mannual
    const void Sub_Manual(const VecData &operand1, const VecData &operand2, const size_t size,  const Modulus modulus, VecData &result);

    // Add poly element wise mannual
    const void Add_Manual(const VecData &operand1, const VecData &operand2, const size_t &poly_size, const size_t &mod_size, const Modulus modulus, std::vector<Modulus> vec_mod,  VecData &result);

    // Manual shift poly
    const void Shift_Manual(const VecData &operand1, const size_t size, const size_t shift_idx, VecData &result);

    // RLWE KeySwitch function
    void generate_rlwe_switchkeys(void) const;

    // RLWE KeySwitch for arbitary mod size
    void generate_one_kswitch_key(seal::util::ConstRNSIter new_key, std::vector<seal::PublicKey> &destination, bool save_seed) const;
    void generate_rlwe_switchkeys_arbitary(void) const;
    void generate_rlwe_switchkeys_seal(void) const;
    void generate_rlwe_switchkeys_arbitary_trash(void) const;

    // Test if we add each rns a 1*scale, if decryption add 1?
    void rns_add_test(void) const;

    // Compare NWC and auto NTT
    void NWC_NTT_Compare();

    // Learning NTT part
    void show_encode_step() const;

    // Compare result of intt by extract and matrix multiplication
    void intt_extract_matrix_compare() const;

    // Using seal intt function to do NWC INTT
    void intt_extract(std::vector<uint64_t> values_matrix, uint64_t slot, seal::Modulus mod_plain, std::vector<uint64_t> &ptxt_encode_scale) const;

    // Using seal ntt function to do NWC NTT
    void ntt_extract(std::vector<uint64_t> values_matrix, uint64_t slot, seal::Modulus mod_plain, std::vector<uint64_t> &ptxt_encode_scale) const;

    // Mirror pattern of INTT and NTT
    void ntt_intt_mirror(std::vector<uint64_t> values_matrix, uint64_t slot, seal::Modulus mod_plain) const;

  // For the Cryptor constructor - We'll need to initialize some encryption parameters and 
  // create contexts, keys, encryptors, decryptors, and evaluators.
  private:
    std::shared_ptr<EncryptionParameters> rlwe_parms_ = nullptr;
    std::shared_ptr<SEALContext> rlwe_context_ = nullptr;
    std::shared_ptr<KeyGenerator> keygen_ = nullptr;
    std::shared_ptr<SecretKey> rlwe_seckey_ = nullptr;
    std::shared_ptr<PublicKey> rlwe_pubkey_ = nullptr;
    std::shared_ptr<RelinKeys> rlwe_relinkeys_ = nullptr;
    std::shared_ptr<RelinKeys> rlwe_relinkeys3_ = nullptr;
    // std::shared_ptr<RelinKeys> rlwe_relinkeys3_ = nullptr;
    std::shared_ptr<GaloisKeys> rlwe_galoiskeys_ = nullptr;
    std::shared_ptr<Encryptor> rlwe_encryptor_ = nullptr;
    std::shared_ptr<Decryptor> rlwe_decryptor_ = nullptr;
    std::shared_ptr<Evaluator> rlwe_evaluator_ = nullptr;
    std::shared_ptr<BatchEncoder> rlwe_batch_encoder_ = nullptr;
    std::shared_ptr<MemoryPoolHandle> pool_ = nullptr;

    // TFHE Part
    std::shared_ptr<EncryptionParameters> lwe_parms_ = nullptr;
    std::shared_ptr<Encryptor> lwe_encryptor_ = nullptr;
    std::shared_ptr<Decryptor> lwe_decryptor_ = nullptr;
    std::shared_ptr<SEALContext> lwe_context_ = nullptr;
    std::shared_ptr<SecretKey> lwe_seckey_ = nullptr;
    std::shared_ptr<SecretKey> lwe_seckey_intt_ = nullptr;
    std::shared_ptr<RGSWCipher> lweswitchkey_ = nullptr;
    std::shared_ptr<KSRGSWCipher> kssquarekey_ = nullptr;
    std::shared_ptr<EncryptionParameters> rgsw_parms_ = nullptr;
    std::shared_ptr<SEALContext> rgsw_context_ = nullptr;
    std::shared_ptr<util::TFHERNSTool> lwe_rnstool_ = nullptr;
    std::shared_ptr<util::TFHERNSTool> rgsw_rnstool_ = nullptr;

    // RLWE KeySwitch Part
    std::shared_ptr<EncryptionParameters> rlwe_parms_little_ = nullptr;
    std::shared_ptr<SEALContext> rlwe_context_little_ = nullptr;
    std::shared_ptr<KeyGenerator> keygen_little_ = nullptr;
    std::shared_ptr<SecretKey> rlwe_seckey_little_ = nullptr;
    std::shared_ptr<PublicKey> rlwe_pubkey_little_ = nullptr;
    std::shared_ptr<RelinKeys> rlwe_relinkeys_little_ = nullptr;   // not supported by little RLWE
    std::shared_ptr<GaloisKeys> rlwe_galoiskeys_little_ = nullptr; // not supported by little RLWE
    std::shared_ptr<Encryptor> rlwe_encryptor_little_ = nullptr;
    std::shared_ptr<Decryptor> rlwe_decryptor_little_ = nullptr;
    std::shared_ptr<Evaluator> rlwe_evaluator_little_ = nullptr;
    std::shared_ptr<BatchEncoder> rlwe_batch_encoder_little_ = nullptr;
    std::shared_ptr<RGSWCipher> rlweswitchkey_ = nullptr;
    std::shared_ptr<GaloisKeys> KSkey_ = nullptr;
    // std::shared_ptr<std::vector<std::vector<Plaintext>>> ptxt_decode_matrix_ = nullptr;
    std::vector<std::vector<Plaintext>> ptxt_decode_matrix_;
    uint64_t mod_inv[RLWEParams::coeff_modulus_size];

    // DEBUG
    std::shared_ptr<GaloisKeys> little_galois_keys_ = nullptr;
    std::shared_ptr<GaloisKeys> little_kswitchkey_ = nullptr;

    // DBBUG FLAG
    int m_verbose;
    int lwe_dec;



};

// Define the util namespace inside seal
namespace util
{

// Customized DRaM function
class DRaMOp {
private:
    std::function<int(int, int)> operation;
    std::string fileSuffix;

public:
    DRaMOp(std::function<int(int, int)> op, const std::string& suffix) 
        : operation(op), fileSuffix(suffix) {}

    int operator()(int x, int t) const {
        return operation(x, t);
    }

    const std::string& getFileSuffix() const {
        return fileSuffix;
    }
};


// Print banner
void print_example_banner(std::string title);

// Function to print uint64_t number in proper form
void printInBinary(uint64_t num);

// bit reversion
const size_t bitrev(const size_t idx, const size_t count);
  
// Function to compute the degree of a polynomial
const size_t Degree(const VecData &coeffs);

const std::vector<uint32_t> ComputeDegreesPS(const uint32_t n);

// Define if i is power of 2
bool isPowerOf2(const int &i);

// Define DRaM with NAND gate
const int DRaM_NAND(int x, int t);

// process two bit
const uint8_t process_low_pair(uint8_t pair);
const uint8_t process_high_pair(uint8_t pair);

// Define DRaM with High xor
const int DRaM_highxor(int x, int t);

// Define DRaM with High xor 9 bit version
const int DRaM_highxor9bit(int x, int t);

// Define DRaM with Low XOR
const int DRaM_lowxor(int x, int t);

// Define DRaM with H4 extract
const int DRaM_H4(int x, int t);

// Define DRaM with L4 extract
const int DRaM_L4(int x, int t);

// Define sign function
const int DRaM_sign(int x, int t, uint64_t Q);

// Define f0 function
const int DRaM_f0(int x, int t, uint64_t Q);

// Define f1 function
const int DRaM_f1(int x, int t, uint64_t Q);

// Get coefficient of DRaMPoly
const std::vector<int> get_NAND_Coefficients(int t);

// Get coefficient of H4
const std::vector<int> get_H4_Coefficients(int t);

// Get coefficient of L4
const std::vector<int> get_L4_Coefficients(int t);

// Get coefficient of xor high 9 bit version
const std::vector<int> get_highxor9bit_Coefficients(int t);

// Get coefficient of xor high
const std::vector<int> get_highxor_Coefficients(int t);

// Get coefficient of xor low
const std::vector<int> get_lowxor_Coefficients(int t);

// Get coefficient of sign
const std::vector<int> get_sign_Coefficients(int t, uint64_t Q);

// Get coefficient
const std::vector<int> get_customize_Coefficients(int t, const util::DRaMOp& dramOp);

// Get coefficient of f0
const std::vector<int> get_f0_Coefficients(int t, uint64_t Q);

// Get coefficient of f1
const std::vector<int> get_f1_Coefficients(int t, uint64_t Q);

// Evaluate DRaMPoly on plaintext
const int evaluateDraMpoly(int x, std::vector<int> coefficients);

// Test DRaMPoly with NAND gate
const void test_NAND_poly(int t);

// Test customize version
const void test_customize_poly(int t, const util::DRaMOp& dramOp);

// Test Low xor
const void test_lowxor_poly(int t);

// Test High xor
const void test_highxor_poly(int t);

// Test High xor 9 bit version
const void test_highxor9bit_poly(int t);

// Test H4 extract with NAND gate
const void test_H4_poly(int t);

// Test L4 extract with NAND gate
const void test_L4_poly(int t);

// Test DRaMPoly with sign extract function
const void test_sign_poly(int t, uint64_t Q);

// Test DRaMPoly with f0 function
const void test_f0_poly(int t, uint64_t Q);

// Test DRaMPoly with f1 function
const void test_f1_poly(int t, uint64_t Q);

// Manual implement NWC
const void NWC_Manual(const VecData &operand1, const VecData &operand2, const size_t poly_size, const size_t mod_size, const Modulus modulus, const std::vector<Modulus> &vec_mod, VecData &result);

// Manual negate vector
const void Negate_Manual(const VecData &operand1, const size_t &poly_size, const size_t &mod_size,  const Modulus modulus, const std::vector<Modulus> &vec_mod,  VecData &result);

// Manual implement Encrypt
const void Encrypt_Manual(const VecData &ptxt, const VecData &seckey, const size_t &poly_size, const size_t &mod_size, const Modulus modulus, const std::vector<Modulus> &vec_mod, MatrixData &ctxt);

// Manual implement Decrypt
const void Decrypt_Manual( MatrixData &ctxt, const VecData &seckey,  const size_t &poly_size, const size_t &mod_size, const Modulus modulus, VecData &ptxt);

// Manual generate rlwe key switching key
const void Generate_RLWE_KSkey_Manual(const VecData &longkey, const VecData &shortkey, const size_t &long_n, const size_t &short_n, const size_t &mod_size, const size_t &dec_base, const size_t &dec_level, const Modulus &modulus, const std::vector<Modulus> &vec_mod, std::vector<std::vector<MatrixData>> &rlwe_switch_key);

// Manual do RLWE Key switch
const void RLWE_Key_Switch_Manual(const MatrixData &long_rlwe, const VecData &short_key, const std::vector<std::vector<MatrixData>> &rlwe_switch_key, const size_t &long_n, const size_t &short_n, const size_t &mod_size, const size_t dec_level, const size_t dec_base, const Modulus &modulus, const std::vector<Modulus> &vec_mod, std::vector<MatrixData> &vec_short_rlwe);

// Multiply coefficient-wise by scalar
const void mul_coeff_mod(const seal::VecData &vec, const size_t poly_size, const size_t &mod_size, const uint64_t scale, const seal::Modulus modulus, const std::vector<Modulus> &vec_mod, VecData &result);

// Multiply rlwe with a poly
const void poly_rlwe_mul(const MatrixData &rlwe, const VecData &poly, const size_t &poly_size, const size_t &mod_size, const Modulus modulus, const std::vector<Modulus> &vec_mod, MatrixData &result_rlwe);

// Divide coefficient-wise by base^idx
const void divide_coeff_mod(const seal::VecData &vec, const size_t &poly_size,const size_t &mod_size, const size_t dec_base, const size_t idx, const seal::Modulus modulus, const std::vector<Modulus> &vec_mod, VecData &result);

// Extract short key from long key
const void extract_temp_key(const VecData &long_key, const size_t &long_n, const size_t &short_n, const size_t &mod_size, const size_t &idx, VecData &short_key);

// RLWE sub RLWE
const void rlwe_add_inplace(MatrixData &rlwe1, const MatrixData &rlwe2, const size_t &poly_size, const size_t &mod_size, const Modulus &modulus, const std::vector<Modulus> &vec_mod);

// RLWE add RLWE
const void rlwe_sub_inplace(MatrixData &rlwe1, const MatrixData &rlwe2, const size_t &poly_size, const size_t &mod_size, const Modulus &modulus, const std::vector<Modulus> &vec_mod);

// bias poly
const void bias_poly(const VecData &poly, const size_t &poly_size, const size_t &mod_size, const Modulus &modulus, const std::vector<Modulus> &vec_mod, VecData &biased_poly);

// NTT trans use matrix
const void NTT_Matrix_Trans(const VecData &operand, const size_t size, const Modulus modulus, VecData &result);

// Inverse NTT trans use matrix
const void Inverse_NTT_Matrix_Trans(const VecData &operand, const size_t size, const Modulus modulus, VecData &result);

// component mod mul of vector
const void component_wise_mod_mul(const VecData &operand1, const VecData &operand2, const size_t &size, const Modulus modulus, VecData &result);

// poly mul use ntt matrix method
const void poly_mul_use_matrix_ntt(const VecData &operand1, const VecData &operand2, const size_t &size, const Modulus modulus, VecData &result);

// try to find correct poly in s2c with out add
const void try_to_find_poly(const size_t n, const seal::Modulus mod_plain);

// TFHE Part
void sample_poly_binary(  
    std::shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination);

const uint64_t pow2mod(const size_t exponent, const Modulus modulus);

const void Display(const seal::VecData &vec, const size_t display_length=0);

const void RLWEKeySwitchVerify();

const void Extract_NWC_test();

class TFHERNSTool
{
  public:
    TFHERNSTool(void) = default;
    TFHERNSTool(const SEALContext &context, const ParamSet paramset);
    void CRTDecPoly(const std::uint64_t *poly, std::vector<std::vector<uint64_t>> &crtdec) const;
    inline void vec_sft_red(const uint64_t *vec_in, uint64_t *vec_out) const;

  private:
    std::vector<std::vector<uint64_t>> Qbar;
    std::vector<uint64_t> Qtot;
    std::vector<uint64_t> Qinv;
    std::shared_ptr<SEALContext> context_ = nullptr;
    size_t lognmod;
    size_t Qbits;
    size_t Bgbits;
    size_t coeff_modulus_size;
    size_t poly_modulus_degree;
    size_t Qsize;
    size_t Qword;
};




}
} // End of the seal namespace