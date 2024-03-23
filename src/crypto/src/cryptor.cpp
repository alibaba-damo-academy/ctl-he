#include "cryptor.h"
#include "paramsets.h"
#include <chrono>
#include <omp.h>
#include <thread>

// include necessary libraries and headers
#include <bitset>
#include <filesystem>
#include <fstream>
#include <streambuf>

#define num_th std::thread::hardware_concurrency()

using seal::util::get;

namespace seal
{
Cryptor::Cryptor(void): m_verbose(0), lwe_dec(1)
{   
    std::cout << "Number of supported threads: " << num_th << std::endl;    
    // Set up the encryption parameters using the RLWEParams scheme
    rlwe_parms_ = std::make_shared<EncryptionParameters>(RLWEParams::scheme_type);
    // Configure the parameters according to RLWEParams
    rlwe_parms_->set_poly_modulus_degree(RLWEParams::poly_modulus_degree);
    // convert the array to a std::vector<int> before passing it to CoeffModulus::Create
    std::vector<int> bit_sizes(RLWEParams::bits, RLWEParams::bits + RLWEParams::coeff_modulus_size);
    rlwe_parms_->set_coeff_modulus(CoeffModulus::Create(RLWEParams::poly_modulus_degree, bit_sizes));

    // std::vector<Modulus> vec_mod;
    // vec_mod.resize(2);
    // vec_mod[0] = 786433;
    // vec_mod[1] = 1099510054913;
    

    // vec_mod = CoeffModulus::Create(RLWEParams::poly_modulus_degree, bit_sizes);
    // for(int i=0; i<bit_sizes.size(); i++){
    //     std::cout << i << "-th prime: " << *vec_mod[i].data() << std::endl;
    // }
    // vec_mod[0] = 1433731073;
    // for(int i=0; i<bit_sizes.size(); i++){
    //     std::cout << i << "-th prime: " << *vec_mod[i].data() << std::endl;
    // }
    // rlwe_parms_->set_coeff_modulus(vec_mod);
    

    // rlwe_parms_->set_coeff_modulus(CoeffModulus::BFVDefault(RLWEParams::poly_modulus_degree));
    // rlwe_parms_->set_plain_modulus(RLWEParams::plain_modulus);
    // batch auto generate plain_modulus
    // rlwe_parms_->set_plain_modulus(PlainModulus::Batching(RLWEParams::poly_modulus_degree, RLWEParams::plain_modulus));
    // specific plain_modulus
    rlwe_parms_->set_plain_modulus(RLWEParams::plain_modulus);
    // Set up the SEALContext
    rlwe_context_ = std::make_shared<SEALContext>(*rlwe_parms_, true, sec_level_type::none);

    auto qualifiers = rlwe_context_->first_context_data()->qualifiers();
    std::cout << "Parameter setting: " << qualifiers.parameter_error_name() << std::endl; // print error name

    // Check if batch is enabled
    if (m_verbose)
    {
        auto qualifiers = rlwe_context_->first_context_data()->qualifiers();
        if (qualifiers.using_batching)
            std::cout << "Batching enabled: True" << std::endl;
        else 
            std::cout << "Batching enabled: False" << std::endl;
    }

    // Set up the key generator and generate the keys
    keygen_ = std::make_shared<KeyGenerator>(*rlwe_context_);
    rlwe_seckey_ = std::make_shared<SecretKey>(keygen_->secret_key());

    // Generate public key using create_public_key method
    rlwe_pubkey_ = std::make_shared<PublicKey>();
    keygen_->create_public_key(*rlwe_pubkey_);  // New: Generate public key using correct method

    // Generte the relinearization keys
    rlwe_relinkeys_ = std::make_shared<RelinKeys>();
    keygen_->create_relin_keys(*rlwe_relinkeys_);
    // rlwe_relinkeys3_ = std::make_shared<RelinKeys>();
    // *rlwe_relinkeys3_ = keygen_->create_relin_keys(3, true);
    // rlwe_relinkeys3_ = std::make_shared<RelinKeys>();
    // *rlwe_relinkeys3_ = keygen_->create_relin_keys(3, true);

    // Generate the Galois keys
    rlwe_galoiskeys_ = std::make_shared<GaloisKeys>();
    keygen_->create_galois_keys(*rlwe_galoiskeys_);

    // Set up the encryptor and decryptor
    rlwe_encryptor_ = std::make_shared<Encryptor>(*rlwe_context_, *rlwe_pubkey_);
    rlwe_decryptor_ = std::make_shared<Decryptor>(*rlwe_context_, *rlwe_seckey_);

    // Set up the evaluator
    rlwe_evaluator_ = std::make_shared<Evaluator>(*rlwe_context_);

    // Set up BatchEncoder
    rlwe_batch_encoder_ = std::make_shared<BatchEncoder>(*rlwe_context_);

    pool_ = std::make_shared<MemoryPoolHandle>(MemoryManager::GetPool());

    std::transform(rlwe_parms_->coeff_modulus().cbegin(), rlwe_parms_->coeff_modulus().cend(), mod_inv, [&](Modulus modulus) {
        uint64_t inv;
        util::try_invert_uint_mod(RLWEParams::poly_modulus_degree, modulus.value(), inv);
        return inv;
    });

    /*
    // TFHE Part
    std::cout << "TFHE Part" << std::endl;
    rgsw_parms_ = std::make_shared<EncryptionParameters>(*rlwe_parms_);
    rgsw_context_ = std::make_shared<SEALContext>(*rgsw_parms_);
    rgsw_rnstool_ = std::make_shared<util::TFHERNSTool>(*rgsw_context_, ParamSet::RGSW);

    lwe_parms_ = std::make_shared<EncryptionParameters>(LWEParams::scheme_type);
    lwe_parms_->set_poly_modulus_degree(LWEParams::poly_modulus_degree);
    auto coeff_modulus = rlwe_parms_->coeff_modulus();
    for (size_t i = LWEParams::coeff_modulus_size; i < RLWEParams::coeff_modulus_size; i++)
        coeff_modulus.pop_back();
    lwe_parms_->set_coeff_modulus(coeff_modulus);
    if (RLWEParams::scheme_type != scheme_type::ckks) {
        lwe_parms_->set_plain_modulus(LWEParams::plain_modulus);
    }
    lwe_context_ = std::make_shared<SEALContext>(*lwe_parms_, false, sec_level_type::none);
    lwe_rnstool_ = std::make_shared<util::TFHERNSTool>(*lwe_context_, ParamSet::LWE);

    lwe_seckey_ = std::make_shared<SecretKey>();
    lwe_seckey_intt_ = std::make_shared<SecretKey>();
    generate_lweseckey();
    
    SecretKey new_key(*rlwe_seckey_);
    util::RNSIter new_key_iter(new_key.data().data(), RLWEParams::poly_modulus_degree);
    util::dyadic_product_coeffmod(new_key_iter, new_key_iter, RLWEParams::coeff_modulus_size, rlwe_parms_->coeff_modulus(), new_key_iter);
    kssquarekey_ = std::make_shared<KSRGSWCipher>();
    kssquarekey_->data().resize(1);
    encrypt(new_key_iter, kssquarekey_->data()[0]);

    lwe_encryptor_ = std::make_shared<Encryptor>(*lwe_context_, *lwe_seckey_);
    lwe_decryptor_ = std::make_shared<Decryptor>(*lwe_context_, *lwe_seckey_);
    
    lweswitchkey_ = std::make_shared<RGSWCipher>();
    if (1){ // TODO: add keyfile management
        SecretKey new_key(*rlwe_seckey_);
        util::RNSIter new_key_iter(new_key.data().data(), RLWEParams::poly_modulus_degree);
        util::dyadic_product_coeffmod(new_key_iter, new_key_iter, RLWEParams::coeff_modulus_size, rlwe_parms_->coeff_modulus(), new_key_iter);
        kssquarekey_->data().resize(1);
        encrypt(new_key_iter, kssquarekey_->data()[0]);
        std::cout << "lweswitchkey gerate: OFF" << std::endl;
        // generate_lweswitchkeys();

        // TODO: keyfile management
        // rlwe_parms_->save(ofs);
        // lwe_parms_->save(ofs);
        // rgsw_parms_->save(ofs);
        // rlwe_seckey_->save(ofs);
        // lwe_seckey_->save(ofs);
        // lwe_seckey_intt_->save(ofs);
        // rlwe_galoiskeys_->save(ofs);
        // for (size_t i = 0; i < LWEParams::poly_modulus_degree; i++) {
        //     ksbootkey_->at(i).save(ofs);
        // }
        // kssquarekey_->save(ofs);
        // for (size_t i = 0; i < LWEParams::npoly; i++)
        //     for (size_t j = 0; j < LWEParams::decompose_level; j++)
        //         lweswitchkey_->at(i)[j].save(ofs);
        
    }
    */

    // RLWE KeySwitch Part
    // Set up the encryption parameters using the RLWEParamsLittle scheme
    // std::cout << "RLWE key switch Part" << std::endl;
    std::cout << "KS Part" << std::endl;
    rlwe_parms_little_= std::make_shared<EncryptionParameters>(RLWEParamsLittle::scheme_type);
    // Configure the parameters according to RLWEParams
    rlwe_parms_little_->set_poly_modulus_degree(RLWEParamsLittle::poly_modulus_degree);
    // convert the array to a std::vector<int> before passing it to CoeffModulus::Create
    // std::vector<int> bit_sizes_little(RLWEParamsLittle::bits, RLWEParamsLittle::bits + RLWEParamsLittle::coeff_modulus_size);
    // rlwe_parms_little_->set_coeff_modulus(CoeffModulus::Create(RLWEParamsLittle::poly_modulus_degree, bit_sizes_little));
    std::vector<Modulus> rlwe_vec_mod = rlwe_parms_->coeff_modulus();
    std::vector<Modulus> rlwe_vec_mod_little;
    rlwe_vec_mod_little.resize(RLWEParamsLittle::coeff_modulus_size);
    for (int i=0; i<RLWEParamsLittle::coeff_modulus_size; i++){
        rlwe_vec_mod_little[i] = rlwe_vec_mod[i];
    }
    rlwe_parms_little_->set_coeff_modulus(rlwe_vec_mod_little); // Manual set as same as RLWE


    // rlwe_parms_little_->set_coeff_modulus(CoeffModulus::BFVDefault(RLWEParamsLittle::poly_modulus_degree));
    // rlwe_parms_little_->set_plain_modulus(RLWEParamsLittle::plain_modulus);
    // batch auto generate plain_modulus
    // rlwe_parms_little_->set_plain_modulus(PlainModulus::Batching(RLWEParamsLittle::poly_modulus_degree, RLWEParamsLittle::plain_modulus));
    // specific plain_modulus
    rlwe_parms_little_->set_plain_modulus(RLWEParamsLittle::plain_modulus);
    // Set up the SEALContext
    // rlwe_context_little_ = std::make_shared<SEALContext>(*rlwe_parms_little_);
    // None security
    rlwe_context_little_ = std::make_shared<SEALContext>(*rlwe_parms_little_, true, sec_level_type::none);

    // Check if batch is enabled
    if (1)
    {
        auto qualifiers_little  = rlwe_context_little_ ->first_context_data()->qualifiers();
        if (qualifiers_little.using_batching)
            std::cout << "Batching enabled: True" << std::endl;
        else 
            std::cout << "Batching enabled: False" << std::endl;
    }

    // Set up the key generator and generate the keys
    keygen_little_ = std::make_shared<KeyGenerator>(*rlwe_context_little_);
    rlwe_seckey_little_ = std::make_shared<SecretKey>(keygen_little_->secret_key());
    // We fix rlwe_seckey_little_
    // for(int i=0; i<RLWEParamsLittle::coeff_modulus_size*RLWEParamsLittle::poly_modulus_degree; i++){
    //     rlwe_seckey_little_->data()[i] = 0;
    // }
    // rlwe_seckey_little_ = lwe_seckey_;

    // Generate public key using create_public_key method
    rlwe_pubkey_little_ = std::make_shared<PublicKey>();
    keygen_little_->create_public_key(*rlwe_pubkey_little_);  // New: Generate public key using correct method

    // Generte the relinearization keys(Unnecessary)
    rlwe_relinkeys_little_ = std::make_shared<RelinKeys>();
    // keygen_little_->create_relin_keys(*rlwe_relinkeys_little_);

    // Generate the Galois keys
    // not supported by little RLWE
    rlwe_galoiskeys_little_  = std::make_shared<GaloisKeys>();
    // keygen_little_ ->create_galois_keys(*rlwe_galoiskeys_little_ );

    // Set up the encryptor and decryptor
    rlwe_encryptor_little_  = std::make_shared<Encryptor>(*rlwe_context_little_ , *rlwe_pubkey_little_ );
    rlwe_decryptor_little_ = std::make_shared<Decryptor>(*rlwe_context_little_ , *rlwe_seckey_little_ );

    // Set up the evaluator
    rlwe_evaluator_little_  = std::make_shared<Evaluator>(*rlwe_context_little_ );

    // Set up BatchEncoder
    rlwe_batch_encoder_little_  = std::make_shared<BatchEncoder>(*rlwe_context_little_ );

    // Generate key switch key
    rlweswitchkey_ = std::make_shared<RGSWCipher>();

    // Genrate key switch key
    KSkey_ = std::make_shared<GaloisKeys>();

    // Generate Decode plaintext matrix
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    auto poly_degree = RLWEParams::poly_modulus_degree;
    Modulus mod_plain(RLWEParams::plain_modulus);
    seal::MatrixData matrix_decode;
    matrix_decode.resize(poly_degree, VecData(poly_degree));
    time_start = std::chrono::high_resolution_clock::now();
    GenDecodeMatrix(matrix_decode);
    // std::vector<std::vector<Plaintext>> ptxt_decode_matrix;
    ptxt_decode_matrix_.resize(poly_degree);
    size_t npoly = RLWEParams::poly_modulus_degree/RLWEParamsLittle::poly_modulus_degree;
    #pragma omp parallel for num_threads(num_th)
    for (int i=0; i<poly_degree; i++){
        (ptxt_decode_matrix_)[i].resize(npoly);
    }
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<poly_degree; i++){
        for(int j=0; j<npoly; j++){
            // std::cout << "j: " << j << std::endl;
            Plaintext ptxt_temp(RLWEParamsLittle::poly_modulus_degree);
            for(int t=0; t<RLWEParamsLittle::poly_modulus_degree; t++){
                if (t==0){
                    ptxt_temp.data()[0] = matrix_decode[i][j];
                    // std::cout << " ptxt_temp.data()[0] = matrix_decode["<< i << "]["<<j<< "]" << std::endl;
                }
                else{
                    ptxt_temp.data()[RLWEParamsLittle::poly_modulus_degree-t] = matrix_decode[i][t*npoly+j];
                    ptxt_temp.data()[RLWEParamsLittle::poly_modulus_degree-t] = seal::util::negate_uint_mod(ptxt_temp.data()[RLWEParamsLittle::poly_modulus_degree-t], mod_plain);
                    // std::cout << "ptxt_temp.data()["<<RLWEParamsLittle::poly_modulus_degree-t<<"] = matrix_decode["<<i<<"]["<<t*npoly+j<<"]" << std::endl;
                }
            }
            (ptxt_decode_matrix_)[i][j] = ptxt_temp;
        }
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Initialize decode matrix: [" << time_diff.count() << " microseconds]" << std::endl;

    // DEBUG: Manually generate little context galois key
    little_galois_keys_ = std::make_shared<GaloisKeys>();
    little_kswitchkey_ = std::make_shared<GaloisKeys>();

}

void Cryptor::lwe_add(const std::vector<LWECipher> &ilwe_1, const std::vector<LWECipher> &ilwe_2, const uint64_t &Q, std::vector<LWECipher> &olwe) const
{
    util::print_example_banner("LWE Add");
    // Modulus mod_q(RLWEParams::plain_modulus);
    Modulus mod_Q(Q);
    olwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        olwe[i].resize(seal::RLWEParamsLittle::poly_modulus_degree + 1);
        for(int j=0; j<seal::RLWEParamsLittle::poly_modulus_degree + 1; j++){
            olwe[i][j] = util::add_uint_mod(ilwe_1[i][j], ilwe_2[i][j], mod_Q);
            if(j==0&&i==0){
                std::cout << "ilwe_1: " << ilwe_1[i][j] << " in binary: ";
                util::printInBinary(ilwe_1[i][j]);
                std::cout << "ilwe_2: " << ilwe_2[i][j] << " in binary: ";
                util::printInBinary(ilwe_2[i][j]);
                std::cout << "olwe: " << olwe[i][j] << " in binary: ";
                util::printInBinary(olwe[i][j]);                
            }
        }
    }
    return;
}

void Cryptor::kswitch_little(const RLWECipher &ilwe, RLWECipher &olwe) const
{
    // This is a DEBUG funtion

    // (1) Extract Encryption Parameters
    auto context_data_ptr = rlwe_context_little_->get_context_data(ilwe.parms_id());
    size_t coeff_count = context_data_ptr->parms().poly_modulus_degree();
    auto galois_tool = context_data_ptr->galois_tool();

    auto &context_data = *rlwe_context_little_->get_context_data(ilwe.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    // size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t encrypted_size = ilwe.size();
    
    // SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count, coeff_modulus_size, *pool_);
    // First transform encrypted.data(0)
    olwe = ilwe;
    util::RNSIter temp(olwe.data(1), coeff_count);
    // Wipe encrypted.data(1)
    util::set_zero_poly(coeff_count, coeff_modulus_size, olwe.data(1));

    switch_key_inplace(olwe, temp, static_cast<const KSwitchKeys &>(*little_kswitchkey_), 0, *pool_);

    return;
}

void Cryptor::generate_rlwe_little_kswitchkey(void ) const
{

    // Extract encryption parameters.
    auto &context_data = *rlwe_context_little_->key_context_data();
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t small_coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t npoly = RLWEParamsLittle::npoly;
    size_t large_coeff_count = RLWEParams::poly_modulus_degree;

    little_kswitchkey_->data().resize(1);
    util::RNSIter secret_key(rlwe_seckey_little_->data().data(), small_coeff_count);

    generate_one_kswitch_key(secret_key, little_kswitchkey_->data()[0], false);
    // little_kswitchkey_->set_parms_id(context_data.parms_id());
        
    return;
}

void Cryptor::generate_rlwe_switchkeys_seal(void) const
{

    // Extract encryption parameters.
    auto &context_data = *rlwe_context_little_->key_context_data();
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    auto galois_tool = context_data.galois_tool();
    size_t small_coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t npoly = RLWEParamsLittle::npoly;
    size_t large_coeff_count = RLWEParams::poly_modulus_degree;

    // std::vector<Modulus> small_vec_mod = rlwe_parms_little_->coeff_modulus();
    // std::vector<Modulus> large_vec_mod = rlwe_parms_->coeff_modulus();
    // size_t large_coeff_count = RLWEParams::poly_modulus_degree;
    // size_t small_coeff_count = RLWEParamsLittle::poly_modulus_degree;
    // size_t coeff_modulus_size = small_vec_mod.size()<3? 1:small_vec_mod.size() - 1;
    // size_t npoly = RLWEParamsLittle::npoly;
    

    // // DEBUG
    // std::cout << "Large Modulus is: " << std::endl;
    // for(int i=0; i<coeff_modulus_size; i++){
    //     std::cout << large_vec_mod[i].value() << std::endl;
    // }
    // std::cout << std::endl;
    // std::cout << "Small Modulus is: " << std::endl;
    // for(int i=0; i<coeff_modulus_size; i++){
    //     std::cout << small_vec_mod[i].value() << std::endl;
    // }
    // std::cout << std::endl;

    // we first construct a Keyswitch key
    // GaloisKeys KSkey;
    KSkey_->data().resize(npoly);
    // KSkey.data().reserve(small_coeff_count);

    
    // DEBUG: we should figure out key is in ntt or intt form when construct kskey
    // Answer: [in NTT form]
    // auto &context_data = *rlwe_context_little_->key_context_data();
    // auto galois_tool = context_data.galois_tool();
    // util::RNSIter secret_key(rlwe_seckey_little_->data().data(), small_coeff_count);
    // std::cout << "Original key: " << std::endl;
    // for(int i=0; i<coeff_modulus_size; i++){
    //     auto poly_iter = secret_key[i];
    //     for(int j=0; j<small_coeff_count; j++){
    //         std::cout << poly_iter[j] << std::endl;
    //     }
    // }
    // SEAL_ALLOCATE_GET_RNS_ITER(rotated_secret_key, small_coeff_count, coeff_modulus_size, *pool_);
    // galois_tool->apply_galois_ntt(secret_key, coeff_modulus_size, 2, rotated_secret_key);
    // std::cout << "rotated key: " << std::endl;
    // for(int i=0; i<coeff_modulus_size; i++){
    //     auto poly_iter = rotated_secret_key[i];
    //     for(int j=0; j<small_coeff_count; j++){
    //         std::cout << poly_iter[j] << std::endl;
    //     }
    // }
    
    

    util::RNSIter secret_key(rlwe_seckey_->data().data(), large_coeff_count);

    // // DEBUG
    // std::cout << "NTT Secret Key is: " << std::endl;
    // for (size_t i = 0; i < coeff_modulus_size; ++i) {
    //     auto poly_iter = secret_key[i];
    //     for (size_t j = 0; j < large_coeff_count; ++j) {
    //         std::cout << poly_iter[j] << " ";
    //     }
    // }
    // std::cout << std::endl;

    // we get inverse ntt of secret key
    // util::RNSIter inv_secret_key(rlwe_seckey_->data().data(), large_coeff_count);
    SEAL_ALLOCATE_GET_RNS_ITER(inv_secret_key, large_coeff_count, coeff_modulus_size, *pool_);
    for (size_t i = 0; i < coeff_modulus_size; ++i) {
        auto poly_iter = secret_key[i];
        // DEBUG
        // std::cout << i << "-th extract NTT key: " << std::endl;
        // for (size_t j = 0; j < large_coeff_count; ++j) {
        //     std::cout << poly_iter[j] << " ";
        // }
        // std::cout << std::endl;

        util::inverse_ntt_negacyclic_harvey(poly_iter, rlwe_context_->key_context_data()->small_ntt_tables()[i]);

        // DEBUG
        // std::cout << i << "-th extract iNTT key: " << std::endl;
        // for (size_t j = 0; j < large_coeff_count; ++j) {
        //     std::cout << poly_iter[j] << " ";
        // }
        // std::cout << std::endl;

        std::copy_n(poly_iter, large_coeff_count, inv_secret_key[i]);
    }

    // // DEBUG
    // std::cout << "Inverse NTT Secret Key is: " << std::endl;
    // for (size_t i = 0; i < coeff_modulus_size; ++i) {
    //     auto poly_iter = inv_secret_key[i];
    //     for (size_t j = 0; j < large_coeff_count; ++j) {
    //         std::cout << poly_iter[j] << " ";
    //     }
    // }
    // std::cout << std::endl;

    // Then we extract inverse ntt form secret key
    // #pragma omp parallel for num_threads(num_th)
    for(int index=0; index<npoly; index++){
        util::RNSIter temp_key(rlwe_seckey_little_->data().data(), small_coeff_count);
        // SEAL_ALLOCATE_GET_RNS_ITER(temp_key, small_coeff_count, coeff_modulus_size, *pool_);
        for(int i=0; i<coeff_modulus_size; i++){
            auto poly_iter = inv_secret_key[i];
            auto temp_poly = temp_key[i];
            for (int j=0; j<small_coeff_count; j++){
                temp_poly[j] = poly_iter[j*npoly+index];
            }

            // // DEBUG
            // std::cout << "extract temp poly: " << std::endl;
            // for (int j=0; j<small_coeff_count; j++){
            //     std::cout << temp_poly[j] << std::endl;
            // }
            // std::cout << std::endl;

            util::ntt_negacyclic_harvey(temp_poly, rlwe_context_little_->key_context_data()->small_ntt_tables()[i]);

            // // DEBUG
            // std::cout << "NTT extract temp poly: " << std::endl;
            // for (int j=0; j<small_coeff_count; j++){
            //     std::cout << temp_poly[j] << std::endl;
            // }
            // std::cout << std::endl;

            // temp_key[i] = temp_poly;
            std::copy_n(temp_poly, large_coeff_count, temp_key[i]);
        }

        // // DEBUG
        // std::cout << "To be keswitch Key is: " << std::endl;
        // for (size_t i = 0; i < coeff_modulus_size; ++i) {
        //     auto poly_iter = temp_key[i];
        //     for (size_t j = 0; j < small_coeff_count; ++j) {
        //         std::cout << poly_iter[j] << " ";
        //     }
        // }
        // std::cout << std::endl;


        // Create key switch keys.
        generate_one_kswitch_key(temp_key, KSkey_->data()[index], false);
        // generate_one_kswitch_key(temp_key, KSkey.data()[index], true);

        // // DEBUG
        // auto kskey = KSkey_->data()[index];
        // std::cout << "if match 1 : " << (kskey[0].parms_id()==rlwe_context_little_->key_parms_id()) << std::endl;
        // std::cout << "if match 2 : " << (KSkey_->parms_id()==rlwe_context_little_->key_parms_id()) << std::endl;
        
    }

    // Set the parms_id (we add a new public setter, we can cancel this later)
    // auto &context_data = *rlwe_context_little_->key_context_data();
    // KSkey_->set_parms_id(context_data.parms_id());

    // DEBUG
    // std::cout << "if match 3 : " << (KSkey_->parms_id()==rlwe_context_little_->key_parms_id()) << std::endl;
    // std::cout << std::endl;
        
    return;
}

void Cryptor::rlwekeyswitch_seal(const RLWECipher &ilwe, std::vector<RLWECipher> &vec_olwe) const
{

    auto &context_data = *rlwe_context_->get_context_data(ilwe.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t small_coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    std::cout << "mannual information: ciphertext modulus size: " << coeff_modulus_size << std::endl;
    size_t encrypted_size = ilwe.size();
    size_t large_coeff_count = RLWEParams::poly_modulus_degree;
    size_t npoly = RLWEParamsLittle::npoly;
    // Use key_context_data where permutation tables exist since previous runs.
    // auto galois_tool = context_.key_context_data()->galois_tool();

    std::vector<Modulus> small_vec_mod = rlwe_parms_little_->coeff_modulus();
    // std::vector<Modulus> large_vec_mod = rlwe_parms_->coeff_modulus();
    // size_t large_coeff_count = RLWEParams::poly_modulus_degree;
    // size_t small_coeff_count = RLWEParamsLittle::poly_modulus_degree;
    // size_t coeff_modulus_size = small_vec_mod.size()<3? 1:small_vec_mod.size() - 1;
    
    vec_olwe.resize(npoly);

    // util::RNSIter ilwe_b(ilwe.data(0), large_coeff_count);
    // util::RNSIter ilwe_a(ilwe.data(0), large_coeff_count);
    SEAL_ALLOCATE_GET_RNS_ITER(ilwe_b, large_coeff_count, coeff_modulus_size, *pool_);
    // Copy result to encrypted.data(0)
    set_poly(ilwe.data(0), large_coeff_count, coeff_modulus_size, ilwe_b);
    SEAL_ALLOCATE_GET_RNS_ITER(ilwe_a, large_coeff_count, coeff_modulus_size, *pool_);
    // Copy result to encrypted.data(0)
    set_poly(ilwe.data(1), large_coeff_count, coeff_modulus_size, ilwe_a);

    // // DEBUG
    std::cout << "ilwe b: " << std::endl;
    for(int i=0; i<coeff_modulus_size; i++){
        auto poly_iter = ilwe_b[i];
        for (int j=0; j<large_coeff_count; j++){
            std::cout << poly_iter[j] << " ";
        }
    }
    std::cout << std::endl;
    std::cout << "ilwe a: " << std::endl;
    for(int i=0; i<coeff_modulus_size; i++){
        auto poly_iter = ilwe_a[i];
        for (int j=0; j<large_coeff_count; j++){
            std::cout << poly_iter[j] << " ";
        }
    }
    std::cout << std::endl;


    for(int index=0; index<npoly; index++){
        // we extract b at first
        RLWECipher rlwe_temp(*rlwe_context_little_);
        rlwe_encryptor_little_->encrypt_zero(rlwe_temp);
        SEAL_ALLOCATE_GET_RNS_ITER(temp_b, small_coeff_count, coeff_modulus_size, *pool_);
        // set_poly(rlwe_temp.data(0), large_coeff_count, coeff_modulus_size, temp_b);

        // Extract temp b from trivial rlwe
        for(int i=0; i<coeff_modulus_size; i++){
            auto poly_iter = ilwe_b[i];
            auto temp_poly = temp_b[i];
            for (int j=0; j<small_coeff_count; j++){
                temp_poly[j] = poly_iter[j*npoly+index];
            }

            // temp_b[i] = temp_poly;
            std::copy_n(temp_poly, large_coeff_count, temp_b[i]);
        }

        // DEBUG
        std::cout << index << "-th temp b: " << std::endl;
        for(int i=0; i<coeff_modulus_size; i++){
            auto poly_iter = temp_b[i];
            for (int j=0; j<small_coeff_count; j++){
                std::cout << poly_iter[j] << " ";
            }
        }
        std::cout << std::endl;

        // construct trivial rlwe
        set_poly(temp_b, small_coeff_count, coeff_modulus_size, rlwe_temp.data(0));
        util::set_zero_poly(small_coeff_count, coeff_modulus_size, rlwe_temp.data(1));

        // DEBUG
        std::cout << "trivial b: " << std::endl;
        for(int i=0; i<coeff_modulus_size; i++){
            for(int j=0; j<small_coeff_count; j++){
                std::cout << rlwe_temp.data(0)[j+i*small_coeff_count] << " ";
            }
        }
        std::cout << std::endl;
        std::cout << "trivial a: " << std::endl;
        for(int i=0; i<coeff_modulus_size; i++){
            for(int j=0; j<small_coeff_count; j++){
                std::cout << rlwe_temp.data(1)[j+i*small_coeff_count] << " ";
            }
        }
        std::cout << std::endl;

        for (int i=0; i<(index+1); i++){

            SEAL_ALLOCATE_GET_RNS_ITER(temp_a, small_coeff_count, coeff_modulus_size, *pool_); // bug here
            // set_poly(rlwe_temp.data(1), large_coeff_count, coeff_modulus_size, temp_a);

            // Extract temp a from trivial rlwe
            for(int j=0; j<coeff_modulus_size; j++){
                auto poly_iter = ilwe_a[j];
                auto temp_poly = temp_a[j];
                for (int t=0; t<small_coeff_count; t++){
                    temp_poly[t] = poly_iter[t*npoly+i];
                }
                // temp_a[j] = temp_poly;
                std::copy_n(temp_poly, small_coeff_count, temp_a[j]);
            }

            // DEBUG
            std::cout << i << "-th temp a: " << std::endl;
            for(int j=0; j<coeff_modulus_size; j++){
                auto poly_iter = temp_a[j];
                for (int t=0; t<small_coeff_count; t++){
                    std::cout << poly_iter[t] << " ";
                }
            }
            std::cout << std::endl;

            // Calculate (temp * galois_key[0], temp * galois_key[1]) + (ct[0], 0)
            switch_key_inplace(rlwe_temp, temp_a, static_cast<const KSwitchKeys &>(*KSkey_), i, *pool_);
            // // DEBUG
            // std::cout << "after add b: " << std::endl;
            // for(int i=0; i<coeff_modulus_size; i++){
            //     for(int j=0; j<small_coeff_count; j++){
            //         std::cout << rlwe_temp.data(0)[j+i*small_coeff_count] << std::endl;
            //     }
            // }
            // std::cout << std::endl;
            // std::cout << "after add a: " << std::endl;
            // for(int i=0; i<coeff_modulus_size; i++){
            //     for(int j=0; j<small_coeff_count; j++){
            //         std::cout << rlwe_temp.data(1)[j+i*small_coeff_count] << std::endl;
            //     }
            // }
            // std::cout << std::endl;

        }

        for (int i=index+1; i<npoly; i++){

            // Extract temp a from trivial rlwe
            SEAL_ALLOCATE_GET_RNS_ITER(temp_a, small_coeff_count, coeff_modulus_size, *pool_);
            for(int j=0; j<coeff_modulus_size; j++){
                auto poly_iter = ilwe_a[j];
                auto temp_poly = temp_a[j];
                for (int t=0; t<small_coeff_count; t++){
                    temp_poly[t] = poly_iter[t*npoly+i];
                }

                // temp_a[j] = temp_poly;
                std::copy_n(temp_poly, small_coeff_count, temp_a[j]);
            }

            // // DEBUG
            // std::cout << i << "-th extract temp a: " << std::endl;
            // for(int j=0; j<coeff_modulus_size; j++){
            //     auto poly_iter = temp_a[j];
            //     for (int t=0; t<small_coeff_count; t++){
            //         std::cout << poly_iter[t] << std::endl;
            //     }
            // }
            // std::cout << std::endl;

            // permute temp a
            SEAL_ALLOCATE_GET_RNS_ITER(temp_a_permute, small_coeff_count, coeff_modulus_size, *pool_);
            for(int j=0; j<coeff_modulus_size; j++){
                auto poly_iter = temp_a[j];
                auto temp_poly = temp_a_permute[j];
                for (int t=0; t<small_coeff_count; t++){
                    if(t==0){
                        temp_poly[0] = poly_iter[small_coeff_count-1]==0?0:(small_vec_mod[j].value()-poly_iter[small_coeff_count-1]);
                    }
                    else{
                        temp_poly[t] = poly_iter[t-1];
                    }
                }
                // temp_a_permute[j] = temp_poly;
                std::copy_n(temp_poly, small_coeff_count, temp_a_permute[j]);
            }

            // // DEBUG
            // std::cout << i << "-th permuted extract temp a: " << std::endl;
            // for(int j=0; j<coeff_modulus_size; j++){
            //     auto poly_iter = temp_a_permute[j];
            //     for (int t=0; t<small_coeff_count; t++){
            //         std::cout << poly_iter[t] << std::endl;
            //     }
            // }
            // std::cout << std::endl;

            // Calculate (temp * galois_key[0], temp * galois_key[1]) + (ct[0], 0)
            switch_key_inplace(rlwe_temp, temp_a, static_cast<const KSwitchKeys &>(*KSkey_), i, *pool_);

            // // DEBUG
            // std::cout << "RLWE b: " << std::endl;
            // for(int i=0; i<coeff_modulus_size; i++){
            //     for(int j=0; j<small_coeff_count; j++){
            //         if(rlwe_temp.data(0)[j+i*small_coeff_count] >= small_vec_mod[i].value())
            //             std::cout << rlwe_temp.data(0)[j+i*small_coeff_count] << std::endl;
            //     }
            // }
            // std::cout << std::endl;
            // std::cout << "RLWE a: " << std::endl;
            // for(int i=0; i<coeff_modulus_size; i++){
            //     for(int j=0; j<small_coeff_count; j++){
            //         if(rlwe_temp.data(1)[j+i*small_coeff_count] >= small_vec_mod[i].value())
            //             std::cout << rlwe_temp.data(1)[j+i*small_coeff_count] << std::endl;
            //     }
            // }
            // std::cout << std::endl;


        }

        vec_olwe[index] = rlwe_temp;
        Plaintext debug_ptxt;
        rlwe_decryptor_little_->decrypt(rlwe_temp, debug_ptxt);
        std::cout << "Decryption Result: " << std::endl;
        for(int i=0; i<small_coeff_count; i++){
            std::cout << debug_ptxt.data()[i] << " ";
        }
        std::cout << std::endl;
        
    }

    return;
}

/*
void Cryptor::generate_one_kswitch_key(seal::util::ConstRNSIter new_key, std::vector<seal::PublicKey> &destination, bool save_seed) const
{
    // Copy from SEAL private function generate_one_kswitch_key()
    if (!rlwe_context_little_->using_keyswitching())
    {
        throw std::logic_error("keyswitching is not supported by the context");
    }

    size_t coeff_count = rlwe_context_little_->key_context_data()->parms().poly_modulus_degree();
    // size_t decomp_mod_count = rlwe_context_little_->first_context_data()->parms().coeff_modulus().size();
    size_t decomp_mod_count = RLWEParamsLittle::coeff_modulus_size<3? 1:RLWEParamsLittle::coeff_modulus_size - 1;
    auto &key_context_data = *rlwe_context_little_->key_context_data();
    auto &key_parms = key_context_data.parms();
    auto &key_modulus = key_parms.coeff_modulus();

    // Size check
    if (!util::product_fits_in(coeff_count, decomp_mod_count))
    {
        throw std::logic_error("invalid parameters");
    }

    // KSwitchKeys data allocated from pool given by MemoryManager::GetPool.
    destination.resize(decomp_mod_count);

    SEAL_ITERATE(iter(new_key, key_modulus, destination, size_t(0)), decomp_mod_count, [&](auto I) {
        SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, *pool_);
        util::encrypt_zero_symmetric(
            *rlwe_seckey_little_, *rlwe_context_little_, key_context_data.parms_id(), true, save_seed, get<2>(I).data());
        uint64_t factor = util::barrett_reduce_64(key_modulus.back().value(), get<1>(I));
        multiply_poly_scalar_coeffmod(get<0>(I), coeff_count, factor, get<1>(I), temp);

        // We use the SeqIter at get<3>(I) to find the i-th RNS factor of the first destination polynomial.
        util::CoeffIter destination_iter = (*util::iter(get<2>(I).data()))[get<3>(I)];
        add_poly_coeffmod(destination_iter, temp, coeff_count, get<1>(I), destination_iter);
    });

    // DEBUG
    // for(int i=0; i<decomp_mod_count; i++)
    //     std::cout << i << "-th match here: " << (destination[i].parms_id()==rlwe_context_little_->key_parms_id()) << std::endl;
}
*/

void Cryptor::generate_one_kswitch_key(seal::util::ConstRNSIter new_key, std::vector<PublicKey> &destination, bool save_seed) const
{
    if (!rlwe_context_little_->using_keyswitching())
    {
        throw std::logic_error("keyswitching is not supported by the context");
    }
    
    size_t coeff_count = rlwe_context_little_->key_context_data()->parms().poly_modulus_degree();
    size_t decomp_mod_count = rlwe_context_little_->first_context_data()->parms().coeff_modulus().size();
    auto &key_context_data = *rlwe_context_little_->key_context_data();
    auto &key_parms = key_context_data.parms();
    auto &key_modulus = key_parms.coeff_modulus();

    // Size check
    if (!seal::util::product_fits_in(coeff_count, decomp_mod_count))
    {
        throw std::logic_error("invalid parameters");
    }

    // KSwitchKeys data allocated from pool given by MemoryManager::GetPool.
    destination.resize(decomp_mod_count);

    SEAL_ITERATE(util::iter(new_key, key_modulus, destination, size_t(0)), decomp_mod_count, [&](auto I) {
        SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, *pool_);
        seal::util::encrypt_zero_symmetric(
            *rlwe_seckey_little_, *rlwe_context_little_, key_context_data.parms_id(), true, save_seed, get<2>(I).data());
        uint64_t factor = seal::util::barrett_reduce_64(key_modulus.back().value(), get<1>(I));
        multiply_poly_scalar_coeffmod(get<0>(I), coeff_count, factor, get<1>(I), temp);

        // We use the SeqIter at get<3>(I) to find the i-th RNS factor of the first destination polynomial.
        seal::util::CoeffIter destination_iter = (*util::iter(get<2>(I).data()))[get<3>(I)];
        add_poly_coeffmod(destination_iter, temp, coeff_count, get<1>(I), destination_iter);
    });
}

/*
void Cryptor::switch_key_inplace(
    Ciphertext &encrypted, util::ConstRNSIter target_iter, const KSwitchKeys &kswitch_keys, size_t kswitch_keys_index,
    MemoryPoolHandle pool) const
{
    auto parms_id = encrypted.parms_id();
    auto &context_data = *rlwe_context_little_->get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto &key_context_data = *rlwe_context_little_->key_context_data();
    auto &key_parms = key_context_data.parms();
    auto scheme = parms.scheme();

    // Verify parameters.
    if (!is_metadata_valid_for(encrypted, *rlwe_context_little_) || !is_buffer_valid(encrypted))
    {
        throw std::invalid_argument("encrypted is not valid for encryption parameters");
    }
    if (!target_iter)
    {
        throw std::invalid_argument("target_iter");
    }
    if (!rlwe_context_little_->using_keyswitching())
    {
        throw std::logic_error("keyswitching is not supported by the context");
    }

    // Don't validate all of kswitch_keys but just check the parms_id.
    if (kswitch_keys.parms_id() != rlwe_context_little_->key_parms_id())
    {
        throw std::invalid_argument("parameter mismatch");
    }

    if (kswitch_keys_index >= kswitch_keys.data().size())
    {
        throw std::out_of_range("kswitch_keys_index");
    }
    if (!pool)
    {
        throw std::invalid_argument("pool is uninitialized");
    }
    if (scheme == scheme_type::bfv && encrypted.is_ntt_form())
    {
        throw std::invalid_argument("BFV encrypted cannot be in NTT form");
    }
    if (scheme == scheme_type::ckks && !encrypted.is_ntt_form())
    {
        throw std::invalid_argument("CKKS encrypted must be in NTT form");
    }
    if (scheme == scheme_type::bgv && encrypted.is_ntt_form())
    {
        throw std::invalid_argument("BGV encrypted cannot be in NTT form");
    }

    // Extract encryption parameters.
    size_t coeff_count = parms.poly_modulus_degree();
    size_t decomp_modulus_size = parms.coeff_modulus().size();
    auto &key_modulus = key_parms.coeff_modulus();
    size_t key_modulus_size = key_modulus.size();
    size_t rns_modulus_size = decomp_modulus_size + 1;
    auto key_ntt_tables = iter(key_context_data.small_ntt_tables());
    auto modswitch_factors = key_context_data.rns_tool()->inv_q_last_mod_q();

    // Size check
    if (!util::product_fits_in(coeff_count, rns_modulus_size, size_t(2)))
    {
        throw std::logic_error("invalid parameters");
    }

    // Prepare input
    auto &key_vector = kswitch_keys.data()[kswitch_keys_index];
    size_t key_component_count = key_vector[0].data().size();

    // Check only the used component in KSwitchKeys.
    for (auto &each_key : key_vector)
    {
        if (!is_metadata_valid_for(each_key, *rlwe_context_little_) || !is_buffer_valid(each_key))
        {
            throw std::invalid_argument("kswitch_keys is not valid for encryption parameters");
        }
    }

    // Create a copy of target_iter
    SEAL_ALLOCATE_GET_RNS_ITER(t_target, coeff_count, decomp_modulus_size, pool);
    set_uint(target_iter, decomp_modulus_size * coeff_count, t_target);

    // In CKKS t_target is in NTT form; switch back to normal form
    if (scheme == scheme_type::ckks)
    {
        inverse_ntt_negacyclic_harvey(t_target, decomp_modulus_size, key_ntt_tables);
    }

    // Temporary result
    auto t_poly_prod(util::allocate_zero_poly_array(key_component_count, coeff_count, rns_modulus_size, pool));

    SEAL_ITERATE(util::iter(size_t(0)), rns_modulus_size, [&](auto I) {
        size_t key_index = (I == decomp_modulus_size ? key_modulus_size - 1 : I);

        // Product of two numbers is up to 60 + 60 = 120 bits, so we can sum up to 256 of them without reduction.
        size_t lazy_reduction_summand_bound = size_t(SEAL_MULTIPLY_ACCUMULATE_USER_MOD_MAX);
        size_t lazy_reduction_counter = lazy_reduction_summand_bound;

        // Allocate memory for a lazy accumulator (128-bit coefficients)
        auto t_poly_lazy(util::allocate_zero_poly_array(key_component_count, coeff_count, 2, pool));

        // Semantic misuse of PolyIter; this is really pointing to the data for a single RNS factor
        util::PolyIter accumulator_iter(t_poly_lazy.get(), 2, coeff_count);

        // Multiply with keys and perform lazy reduction on product's coefficients
        SEAL_ITERATE(util::iter(size_t(0)), decomp_modulus_size, [&](auto J) {
            SEAL_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);
            util::ConstCoeffIter t_operand;

            // RNS-NTT form exists in input
            if ((scheme == scheme_type::ckks) && (I == J))
            {
                t_operand = target_iter[J];
            }
            // Perform RNS-NTT conversion
            else
            {
                // No need to perform RNS conversion (modular reduction)
                if (key_modulus[J] <= key_modulus[key_index])
                {
                    set_uint(t_target[J], coeff_count, t_ntt);
                }
                // Perform RNS conversion (modular reduction)
                else
                {
                    modulo_poly_coeffs(t_target[J], coeff_count, key_modulus[key_index], t_ntt);
                }
                // NTT conversion lazy outputs in [0, 4q)
                ntt_negacyclic_harvey_lazy(t_ntt, key_ntt_tables[key_index]);
                t_operand = t_ntt;
            }

            // Multiply with keys and modular accumulate products in a lazy fashion
            SEAL_ITERATE(iter(key_vector[J].data(), accumulator_iter), key_component_count, [&](auto K) {
                if (!lazy_reduction_counter)
                {
                    SEAL_ITERATE(util::iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                        unsigned long long qword[2]{ 0, 0 };
                        util::multiply_uint64(get<0>(L), get<1>(L), qword);

                        // Accumulate product of t_operand and t_key_acc to t_poly_lazy and reduce
                        util::add_uint128(qword, get<2>(L).ptr(), qword);
                        get<2>(L)[0] = util::barrett_reduce_128(qword, key_modulus[key_index]);
                        get<2>(L)[1] = 0;
                    });
                }
                else
                {
                    // Same as above but no reduction
                    SEAL_ITERATE(util::iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                        unsigned long long qword[2]{ 0, 0 };
                        util::multiply_uint64(get<0>(L), get<1>(L), qword);
                        util::add_uint128(qword, get<2>(L).ptr(), qword);
                        get<2>(L)[0] = qword[0];
                        get<2>(L)[1] = qword[1];
                    });
                }
            });

            if (!--lazy_reduction_counter)
            {
                lazy_reduction_counter = lazy_reduction_summand_bound;
            }
        });

        // PolyIter pointing to the destination t_poly_prod, shifted to the appropriate modulus
        util::PolyIter t_poly_prod_iter(t_poly_prod.get() + (I * coeff_count), coeff_count, rns_modulus_size);

        // Final modular reduction
        SEAL_ITERATE(util::iter(accumulator_iter, t_poly_prod_iter), key_component_count, [&](auto K) {
            if (lazy_reduction_counter == lazy_reduction_summand_bound)
            {
                SEAL_ITERATE(iter(get<0>(K), *get<1>(K)), coeff_count, [&](auto L) {
                    get<1>(L) = static_cast<uint64_t>(*get<0>(L));
                });
            }
            else
            {
                // Same as above except need to still do reduction
                SEAL_ITERATE(iter(get<0>(K), *get<1>(K)), coeff_count, [&](auto L) {
                    get<1>(L) = util::barrett_reduce_128(get<0>(L).ptr(), key_modulus[key_index]);
                });
            }
        });
    });
    // Accumulated products are now stored in t_poly_prod

    // Perform modulus switching with scaling
    util::PolyIter t_poly_prod_iter(t_poly_prod.get(), coeff_count, rns_modulus_size);
    SEAL_ITERATE(iter(encrypted, t_poly_prod_iter), key_component_count, [&](auto I) {
        if (scheme == scheme_type::bgv)
        {
            const Modulus &plain_modulus = parms.plain_modulus();
            // qk is the special prime
            uint64_t qk = key_modulus[key_modulus_size - 1].value();
            uint64_t qk_inv_qp = rlwe_context_little_->key_context_data()->rns_tool()->inv_q_last_mod_t();

            // Lazy reduction; this needs to be then reduced mod qi
            util::CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
            inverse_ntt_negacyclic_harvey(t_last, key_ntt_tables[key_modulus_size - 1]);

            SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(k, coeff_count, pool);
            modulo_poly_coeffs(t_last, coeff_count, plain_modulus, k);
            negate_poly_coeffmod(k, coeff_count, plain_modulus, k);
            if (qk_inv_qp != 1)
            {
                multiply_poly_scalar_coeffmod(k, coeff_count, qk_inv_qp, plain_modulus, k);
            }

            SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(delta, coeff_count, pool);
            SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(c_mod_qi, coeff_count, pool);
            SEAL_ITERATE(iter(I, key_modulus, modswitch_factors, key_ntt_tables), decomp_modulus_size, [&](auto J) {
                inverse_ntt_negacyclic_harvey(get<0, 1>(J), get<3>(J));
                // delta = k mod q_i
                modulo_poly_coeffs(k, coeff_count, get<1>(J), delta);
                // delta = k * q_k mod q_i
                multiply_poly_scalar_coeffmod(delta, coeff_count, qk, get<1>(J), delta);

                // c mod q_i
                modulo_poly_coeffs(t_last, coeff_count, get<1>(J), c_mod_qi);
                // delta = c + k * q_k mod q_i
                // c_{i} = c_{i} - delta mod q_i
                const uint64_t Lqi = get<1>(J).value() * 2;
                SEAL_ITERATE(iter(delta, c_mod_qi, get<0, 1>(J)), coeff_count, [Lqi](auto K) {
                    get<2>(K) = get<2>(K) + Lqi - (get<0>(K) + get<1>(K));
                });

                multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<2>(J), get<1>(J), get<0, 1>(J));

                add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J), get<0, 0>(J));
            });
        }
        else
        {
            // Lazy reduction; this needs to be then reduced mod qi
            util::CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
            inverse_ntt_negacyclic_harvey_lazy(t_last, key_ntt_tables[key_modulus_size - 1]);

            // Add (p-1)/2 to change from flooring to rounding.
            uint64_t qk = key_modulus[key_modulus_size - 1].value();
            uint64_t qk_half = qk >> 1;
            SEAL_ITERATE(t_last, coeff_count, [&](auto &J) {
                J = util::barrett_reduce_64(J + qk_half, key_modulus[key_modulus_size - 1]);
            });

            SEAL_ITERATE(iter(I, key_modulus, key_ntt_tables, modswitch_factors), decomp_modulus_size, [&](auto J) {
                SEAL_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);

                // (ct mod 4qk) mod qi
                uint64_t qi = get<1>(J).value();
                if (qk > qi)
                {
                    // This cannot be spared. NTT only tolerates input that is less than 4*modulus (i.e. qk <=4*qi).
                    modulo_poly_coeffs(t_last, coeff_count, get<1>(J), t_ntt);
                }
                else
                {
                    set_uint(t_last, coeff_count, t_ntt);
                }

                // Lazy substraction, results in [0, 2*qi), since fix is in [0, qi].
                uint64_t fix = qi - util::barrett_reduce_64(qk_half, get<1>(J));
                SEAL_ITERATE(t_ntt, coeff_count, [fix](auto &K) { K += fix; });

                uint64_t qi_lazy = qi << 1; // some multiples of qi
                if (scheme == scheme_type::ckks)
                {
                    // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
                    ntt_negacyclic_harvey_lazy(t_ntt, get<2>(J));
#if SEAL_USER_MOD_BIT_COUNT_MAX > 60
                    // Reduce from [0, 4qi) to [0, 2qi)
                    SEAL_ITERATE(
                        t_ntt, coeff_count, [&](auto &K) { K -= SEAL_COND_SELECT(K >= qi_lazy, qi_lazy, 0); });
#else
                    // Since SEAL uses at most 60bit moduli, 8*qi < 2^63.
                    qi_lazy = qi << 2;
#endif
                }
                else if (scheme == scheme_type::bfv)
                {
                    inverse_ntt_negacyclic_harvey_lazy(get<0, 1>(J), get<2>(J));
                }

                // ((ct mod qi) - (ct mod qk)) mod qi with output in [0, 2 * qi_lazy)
                SEAL_ITERATE(
                    iter(get<0, 1>(J), t_ntt), coeff_count, [&](auto K) { get<0>(K) += qi_lazy - get<1>(K); });

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<3>(J), get<1>(J), get<0, 1>(J));
                add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J), get<0, 0>(J));
            });
        }
    });
}
*/

void Cryptor::switch_key_inplace(Ciphertext &encrypted, util::ConstRNSIter target_iter, const KSwitchKeys &kswitch_keys, size_t kswitch_keys_index,MemoryPoolHandle pool) const
{
    
    auto parms_id = encrypted.parms_id();
    auto &context_data = *rlwe_context_little_->get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto &key_context_data = *rlwe_context_little_->key_context_data();
    auto &key_parms = key_context_data.parms();
    auto scheme = parms.scheme();

    // Verify parameters.
    if (!is_metadata_valid_for(encrypted, *rlwe_context_little_) || !is_buffer_valid(encrypted))
    {
        throw std::invalid_argument("encrypted is not valid for encryption parameters");
    }
    if (!target_iter)
    {
        throw std::invalid_argument("target_iter");
    }
    if (!rlwe_context_little_->using_keyswitching())
    {
        throw std::logic_error("keyswitching is not supported by the context");
    }

    // Don't validate all of kswitch_keys but just check the parms_id.
    if (kswitch_keys.parms_id() != rlwe_context_little_->key_parms_id())
    {
        throw std::invalid_argument("parameter mismatch");
    }

    if (kswitch_keys_index >= kswitch_keys.data().size())
    {
        throw std::out_of_range("kswitch_keys_index");
    }
    if (!pool)
    {
        throw std::invalid_argument("pool is uninitialized");
    }
    if (scheme == scheme_type::bfv && encrypted.is_ntt_form())
    {
        throw std::invalid_argument("BFV encrypted cannot be in NTT form");
    }
    if (scheme == scheme_type::ckks && !encrypted.is_ntt_form())
    {
        throw std::invalid_argument("CKKS encrypted must be in NTT form");
    }
    if (scheme == scheme_type::bgv && encrypted.is_ntt_form())
    {
        throw std::invalid_argument("BGV encrypted cannot be in NTT form");
    }

    // Extract encryption parameters.
    size_t coeff_count = parms.poly_modulus_degree();
    size_t decomp_modulus_size = parms.coeff_modulus().size();
    auto &key_modulus = key_parms.coeff_modulus();
    size_t key_modulus_size = key_modulus.size();
    size_t rns_modulus_size = decomp_modulus_size + 1;
    auto key_ntt_tables = iter(key_context_data.small_ntt_tables());
    auto modswitch_factors = key_context_data.rns_tool()->inv_q_last_mod_q();

    // Size check
    if (!util::product_fits_in(coeff_count, rns_modulus_size, size_t(2)))
    {
        throw std::logic_error("invalid parameters");
    }

    // Prepare input
    auto &key_vector = kswitch_keys.data()[kswitch_keys_index];
    size_t key_component_count = key_vector[0].data().size();

    // Check only the used component in KSwitchKeys.
    for (auto &each_key : key_vector)
    {
        if (!is_metadata_valid_for(each_key, *rlwe_context_little_) || !is_buffer_valid(each_key))
        {
            throw std::invalid_argument("kswitch_keys is not valid for encryption parameters");
        }
    }

    // Create a copy of target_iter
    SEAL_ALLOCATE_GET_RNS_ITER(t_target, coeff_count, decomp_modulus_size, pool);
    set_uint(target_iter, decomp_modulus_size * coeff_count, t_target);

    // In CKKS t_target is in NTT form; switch back to normal form
    if (scheme == scheme_type::ckks)
    {
        inverse_ntt_negacyclic_harvey(t_target, decomp_modulus_size, key_ntt_tables);
    }

    // Temporary result
    auto t_poly_prod(util::allocate_zero_poly_array(key_component_count, coeff_count, rns_modulus_size, pool));

    SEAL_ITERATE(util::iter(size_t(0)), rns_modulus_size, [&](auto I) {
        size_t key_index = (I == decomp_modulus_size ? key_modulus_size - 1 : I);

        // Product of two numbers is up to 60 + 60 = 120 bits, so we can sum up to 256 of them without reduction.
        size_t lazy_reduction_summand_bound = size_t(SEAL_MULTIPLY_ACCUMULATE_USER_MOD_MAX);
        size_t lazy_reduction_counter = lazy_reduction_summand_bound;

        // Allocate memory for a lazy accumulator (128-bit coefficients)
        auto t_poly_lazy(util::allocate_zero_poly_array(key_component_count, coeff_count, 2, pool));

        // Semantic misuse of PolyIter; this is really pointing to the data for a single RNS factor
        util::PolyIter accumulator_iter(t_poly_lazy.get(), 2, coeff_count);

        // Multiply with keys and perform lazy reduction on product's coefficients
        SEAL_ITERATE(util::iter(size_t(0)), decomp_modulus_size, [&](auto J) {
            SEAL_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);
            util::ConstCoeffIter t_operand;

            // RNS-NTT form exists in input
            if ((scheme == scheme_type::ckks) && (I == J))
            {
                t_operand = target_iter[J];
            }
            // Perform RNS-NTT conversion
            else
            {
                // No need to perform RNS conversion (modular reduction)
                if (key_modulus[J] <= key_modulus[key_index])
                {
                    set_uint(t_target[J], coeff_count, t_ntt);
                }
                // Perform RNS conversion (modular reduction)
                else
                {
                    modulo_poly_coeffs(t_target[J], coeff_count, key_modulus[key_index], t_ntt);
                }
                // NTT conversion lazy outputs in [0, 4q)
                ntt_negacyclic_harvey_lazy(t_ntt, key_ntt_tables[key_index]);
                t_operand = t_ntt;
            }

            // Multiply with keys and modular accumulate products in a lazy fashion
            SEAL_ITERATE(util::iter(key_vector[J].data(), accumulator_iter), key_component_count, [&](auto K) {
                if (!lazy_reduction_counter)
                {
                    SEAL_ITERATE(util::iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                        unsigned long long qword[2]{ 0, 0 };
                        util::multiply_uint64(get<0>(L), get<1>(L), qword);

                        // Accumulate product of t_operand and t_key_acc to t_poly_lazy and reduce
                        util::add_uint128(qword, get<2>(L).ptr(), qword);
                        get<2>(L)[0] = util::barrett_reduce_128(qword, key_modulus[key_index]);
                        get<2>(L)[1] = 0;
                    });
                }
                else
                {
                    // Same as above but no reduction
                    SEAL_ITERATE(util::iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                        unsigned long long qword[2]{ 0, 0 };
                        util::multiply_uint64(get<0>(L), get<1>(L), qword);
                        util::add_uint128(qword, get<2>(L).ptr(), qword);
                        get<2>(L)[0] = qword[0];
                        get<2>(L)[1] = qword[1];
                    });
                }
            });

            if (!--lazy_reduction_counter)
            {
                lazy_reduction_counter = lazy_reduction_summand_bound;
            }
        });

        // PolyIter pointing to the destination t_poly_prod, shifted to the appropriate modulus
        util::PolyIter t_poly_prod_iter(t_poly_prod.get() + (I * coeff_count), coeff_count, rns_modulus_size);

        // Final modular reduction
        SEAL_ITERATE(util::iter(accumulator_iter, t_poly_prod_iter), key_component_count, [&](auto K) {
            if (lazy_reduction_counter == lazy_reduction_summand_bound)
            {
                SEAL_ITERATE(util::iter(get<0>(K), *get<1>(K)), coeff_count, [&](auto L) {
                    get<1>(L) = static_cast<uint64_t>(*get<0>(L));
                });
            }
            else
            {
                // Same as above except need to still do reduction
                SEAL_ITERATE(util::iter(get<0>(K), *get<1>(K)), coeff_count, [&](auto L) {
                    get<1>(L) = util::barrett_reduce_128(get<0>(L).ptr(), key_modulus[key_index]);
                });
            }
        });
    });
    // Accumulated products are now stored in t_poly_prod

    // Perform modulus switching with scaling
    util::PolyIter t_poly_prod_iter(t_poly_prod.get(), coeff_count, rns_modulus_size);
    SEAL_ITERATE(util::iter(encrypted, t_poly_prod_iter), key_component_count, [&](auto I) {
        if (scheme == scheme_type::bgv)
        {
            const Modulus &plain_modulus = parms.plain_modulus();
            // qk is the special prime
            uint64_t qk = key_modulus[key_modulus_size - 1].value();
            uint64_t qk_inv_qp = rlwe_context_little_->key_context_data()->rns_tool()->inv_q_last_mod_t();

            // Lazy reduction; this needs to be then reduced mod qi
            util::CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
            inverse_ntt_negacyclic_harvey(t_last, key_ntt_tables[key_modulus_size - 1]);

            SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(k, coeff_count, pool);
            modulo_poly_coeffs(t_last, coeff_count, plain_modulus, k);
            negate_poly_coeffmod(k, coeff_count, plain_modulus, k);
            if (qk_inv_qp != 1)
            {
                multiply_poly_scalar_coeffmod(k, coeff_count, qk_inv_qp, plain_modulus, k);
            }

            SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(delta, coeff_count, pool);
            SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(c_mod_qi, coeff_count, pool);
            SEAL_ITERATE(util::iter(I, key_modulus, modswitch_factors, key_ntt_tables), decomp_modulus_size, [&](auto J) {
                inverse_ntt_negacyclic_harvey(get<0, 1>(J), get<3>(J));
                // delta = k mod q_i
                modulo_poly_coeffs(k, coeff_count, get<1>(J), delta);
                // delta = k * q_k mod q_i
                multiply_poly_scalar_coeffmod(delta, coeff_count, qk, get<1>(J), delta);

                // c mod q_i
                modulo_poly_coeffs(t_last, coeff_count, get<1>(J), c_mod_qi);
                // delta = c + k * q_k mod q_i
                // c_{i} = c_{i} - delta mod q_i
                const uint64_t Lqi = get<1>(J).value() * 2;
                SEAL_ITERATE(util::iter(delta, c_mod_qi, get<0, 1>(J)), coeff_count, [Lqi](auto K) {
                    get<2>(K) = get<2>(K) + Lqi - (get<0>(K) + get<1>(K));
                });

                multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<2>(J), get<1>(J), get<0, 1>(J));

                add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J), get<0, 0>(J));
            });
        }
        else
        {
            // Lazy reduction; this needs to be then reduced mod qi
            util::CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
            inverse_ntt_negacyclic_harvey_lazy(t_last, key_ntt_tables[key_modulus_size - 1]);

            // Add (p-1)/2 to change from flooring to rounding.
            uint64_t qk = key_modulus[key_modulus_size - 1].value();
            uint64_t qk_half = qk >> 1;
            SEAL_ITERATE(t_last, coeff_count, [&](auto &J) {
                J = util::barrett_reduce_64(J + qk_half, key_modulus[key_modulus_size - 1]);
            });

            SEAL_ITERATE(util::iter(I, key_modulus, key_ntt_tables, modswitch_factors), decomp_modulus_size, [&](auto J) {
                SEAL_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);

                // (ct mod 4qk) mod qi
                uint64_t qi = get<1>(J).value();
                if (qk > qi)
                {
                    // This cannot be spared. NTT only tolerates input that is less than 4*modulus (i.e. qk <=4*qi).
                    modulo_poly_coeffs(t_last, coeff_count, get<1>(J), t_ntt);
                }
                else
                {
                    set_uint(t_last, coeff_count, t_ntt);
                }

                // Lazy substraction, results in [0, 2*qi), since fix is in [0, qi].
                uint64_t fix = qi - util::barrett_reduce_64(qk_half, get<1>(J));
                SEAL_ITERATE(t_ntt, coeff_count, [fix](auto &K) { K += fix; });

                uint64_t qi_lazy = qi << 1; // some multiples of qi
                if (scheme == scheme_type::ckks)
                {
                    // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
                    ntt_negacyclic_harvey_lazy(t_ntt, get<2>(J));
#if SEAL_USER_MOD_BIT_COUNT_MAX > 60
                    // Reduce from [0, 4qi) to [0, 2qi)
                    SEAL_ITERATE(
                        t_ntt, coeff_count, [&](auto &K) { K -= SEAL_COND_SELECT(K >= qi_lazy, qi_lazy, 0); });
#else
                    // Since SEAL uses at most 60bit moduli, 8*qi < 2^63.
                    qi_lazy = qi << 2;
#endif
                }
                else if (scheme == scheme_type::bfv)
                {
                    inverse_ntt_negacyclic_harvey_lazy(get<0, 1>(J), get<2>(J));
                }

                // ((ct mod qi) - (ct mod qk)) mod qi with output in [0, 2 * qi_lazy)
                SEAL_ITERATE(
                    util::iter(get<0, 1>(J), t_ntt), coeff_count, [&](auto K) { get<0>(K) += qi_lazy - get<1>(K); });

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<3>(J), get<1>(J), get<0, 1>(J));
                add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J), get<0, 0>(J));
            });
        }
    });
}

void Cryptor::gen_rt_key_little(void) const
{   
    // this is a debug function
    // we mannually generate rotation key

    // (1) Generate Galois Steps
    util::print_example_banner("Print Galoise Steps");
    std::vector<uint32_t> galois_elts = rlwe_context_little_->key_context_data()->galois_tool()->get_elts_all();
    std::cout << "galois steps vector: ";
    for(int i=0; i<galois_elts.size(); i++){
        std::cout << galois_elts[i] << " ";
    }
    std::cout << std::endl;

    // (2) Generate Galois Keys
    // 2.1 Extract Encryption Parameters
    // Extract encryption parameters.
    auto &context_data = *rlwe_context_little_->key_context_data();
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    auto galois_tool = context_data.galois_tool();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    util::print_example_banner("Print Encryption Parameter");
    std::cout << "coeff_count: " << coeff_count << std::endl;
    std::cout << "coeff_modulus_size: " << coeff_modulus_size << std::endl;
    
    // DEBUG
    std::cout << "coefficient modulus" << std::endl;
    for(int i=0; i<coeff_modulus_size; i++){
        std::cout << coeff_modulus[i].value() << " ";
    }
    std::cout << std::endl;

    // 2.2 resize key size
    // The max number of keys is equal to number of coefficients
    little_galois_keys_->data().resize(coeff_count);

    int i = 0; // steps index
    for (auto galois_elt : galois_elts){
        // Do we already have the key?
        if (little_galois_keys_->has_key(galois_elt))
        {
            continue;
        }

        // 2.3 Rotate secret key for each coeff_modulus
        SEAL_ALLOCATE_GET_RNS_ITER(rotated_secret_key, coeff_count, coeff_modulus_size, *pool_);
        util::RNSIter secret_key(rlwe_seckey_little_->data().data(), coeff_count);
        galois_tool->apply_galois_ntt(secret_key, coeff_modulus_size, galois_elt, rotated_secret_key);

        // DEBUG
        util::print_example_banner("Mannually Original secret Key:");
        for(int i=0; i<coeff_modulus_size; i++){
            auto poly_iter = secret_key[i];
            for(int j=0; j<coeff_count; j++){
                std::cout << poly_iter[j] << " ";
            }
        }
        std::cout << std::endl;
        util::print_example_banner("Mannually Genrate Rotated Key:");
        for(int i=0; i<coeff_modulus_size; i++){
            auto poly_iter = rotated_secret_key[i];
            for(int j=0; j<coeff_count; j++){
                std::cout << poly_iter[j] << " ";
            }
        }
        std::cout << std::endl;

        // 2.4 Initialize Galois key
        // This is the location in the galois_keys vector
        size_t index = GaloisKeys::get_index(galois_elt);
        util::print_example_banner(std::to_string(i) + "-th galoise key index");
        std::cout << "galois_elt: " << galois_elt << " index: " << index << std::endl;

        // 2.5 Create Galois keys.
        generate_one_kswitch_key(rotated_secret_key, little_galois_keys_->data()[index], false);

        // DEBUG
        auto kskey = little_galois_keys_->data()[index];
        auto pubkey = kskey.data()[0];
        auto cipher = pubkey.data();
        auto b = cipher.data(0);
        auto a = cipher.data(1);
        size_t decomp_mod_count = rlwe_context_little_->first_context_data()->parms().coeff_modulus().size();
        std::cout << "galois key size(vector<vector<PublicKey>>): "<< little_galois_keys_->data().size() << " equals to polynomial degree"<< std::endl;
        std::cout << "kskey size(vector<PublicKey>): " << kskey.size() << " equals to decomp_mod_count(modulus size - 1)" << std::endl;
        std::cout << "pubkey size(PublicKey): " << pubkey.data().size() << " equals to rlwe poly amount(2)" << std::endl;
        std::cout << "summary: glois key is poly_degree * decom_mod(modulus_size - 1) * RLWECipher(2 * modulus_size * poly_degree)" << std::endl;

        // std::cout << "public key params id equals to key context? " << (cipher.parms_id()==rlwe_context_little_->key_parms_id()) << std::endl;
        // std::cout << "public key params id equals to first data context? " << (cipher.parms_id()==rlwe_context_little_->first_parms_id()) << std::endl;

        

        i++;
    }

    // 2.6 Set the parms_id
    // little_galois_keys_->set_parms_id(context_data.parms_id());


    return;
}

void Cryptor::rotation_little(const RLWECipher &ilwe, const size_t &step, RLWECipher &olwe) const
{
    // This is a DEBUG funtion

    util::print_example_banner("Start rotation!");

    // (1) Extract Encryption Parameters
    auto context_data_ptr = rlwe_context_little_->get_context_data(ilwe.parms_id());
    size_t coeff_count = context_data_ptr->parms().poly_modulus_degree();
    auto galois_tool = context_data_ptr->galois_tool();
    uint32_t galois_elt = galois_tool->get_elt_from_step(step);

    auto &context_data = *rlwe_context_little_->get_context_data(ilwe.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    // size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t encrypted_size = ilwe.size();

    util::print_example_banner("Print parameters and galois step");
    std::cout << "coeff_count: " << coeff_count << " coeff_modulus_size: " << coeff_modulus_size << std::endl;
    std::cout << "step: " << step << " galois element: " << galois_elt << " index: " << GaloisKeys::get_index(galois_elt) << std::endl;
    
    // Use key_context_data where permutation tables exist since previous runs.
    // auto galois_tool = context_.key_context_data()->galois_tool();

    // (1) Perform rotation
    SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count, coeff_modulus_size, *pool_);
    // First transform encrypted.data(0)
    olwe = ilwe;
    auto encrypted_iter = util::iter(olwe);
    galois_tool->apply_galois(encrypted_iter[0], coeff_modulus_size, galois_elt, coeff_modulus, temp);

    // Copy result to encrypted.data(0)
    set_poly(temp, coeff_count, coeff_modulus_size, olwe.data(0));

    // Next transform encrypted.data(1)
    galois_tool->apply_galois(encrypted_iter[1], coeff_modulus_size, galois_elt, coeff_modulus, temp);

    // Wipe encrypted.data(1)
    util::set_zero_poly(coeff_count, coeff_modulus_size, olwe.data(1));

    // (2) Calculate (temp * galois_key[0], temp * galois_key[1]) + (ct[0], 0)
    // // DEBUG
    // std::cout << "trivial b: " << std::endl;
    // for(int i=0; i<coeff_modulus_size; i++){
    //     for(int j=0; j<coeff_count; j++){
    //         std::cout << olwe.data(0)[j+i*coeff_count] << " ";
    //     }
    // }
    // std::cout << std::endl;
    // std::cout << "trivial a: " << std::endl;
    // for(int i=0; i<coeff_modulus_size; i++){
    //     for(int j=0; j<coeff_count; j++){
    //         std::cout << olwe.data(1)[j+i*coeff_count] << " ";
    //     }
    // }
    // std::cout << std::endl;

    // // DEBUG
    // std::cout << "temp: " << std::endl;
    // for(int j=0; j<coeff_modulus_size; j++){
    //     auto poly_iter = temp[j];
    //     for (int t=0; t<coeff_count; t++){
    //         std::cout << poly_iter[t] << " ";
    //     }
    // }
    // std::cout << std::endl;

    switch_key_inplace(olwe, temp, static_cast<const KSwitchKeys &>(*little_galois_keys_), GaloisKeys::get_index(galois_elt), *pool_);

    // DEBUG: we rotate officially
    RLWECipher off_rlwe = ilwe;
    rlwe_evaluator_little_->rotate_rows(ilwe, step, *rlwe_galoiskeys_little_, off_rlwe);
    VecData debug(coeff_count, 0ULL);
    decrypt(off_rlwe, debug, ParamSet::RLWELittle);
    util::print_example_banner("Official rotation result:");
    for(int i=0; i<coeff_count; i++){
        std::cout << debug[i] << std::endl;
    }
    std::cout << std::endl;

    return;
}

void Cryptor::gen_kskey_database(void) const
{
    std::vector<Modulus> small_vec_mod = rlwe_parms_little_->coeff_modulus();
    std::vector<Modulus> large_vec_mod = rlwe_parms_->coeff_modulus();
    size_t large_coeff_count = RLWEParams::poly_modulus_degree;
    size_t small_coeff_count = RLWEParamsLittle::poly_modulus_degree;
    size_t coeff_modulus_size = small_vec_mod.size()<3? 1:small_vec_mod.size() - 1;
    size_t npoly = RLWEParamsLittle::npoly;
    KSkey_->data().resize(npoly);

    util::RNSIter secret_key(rlwe_seckey_->data().data(), large_coeff_count);

    // DEBUG
    std::cout << "NTT Secret Key is: " << std::endl;
    for (size_t i = 0; i < coeff_modulus_size; ++i) {
        auto poly_iter = secret_key[i];
        for (size_t j = 0; j < large_coeff_count; ++j) {
            std::cout << poly_iter[j] << std::endl;
        }
    }
    std::cout << std::endl;

    // we get inverse ntt of secret key
    util::RNSIter inv_secret_key(rlwe_seckey_->data().data(), large_coeff_count);
    for (size_t i = 0; i < coeff_modulus_size; ++i) {
        auto poly_iter = secret_key[i];
        util::inverse_ntt_negacyclic_harvey(poly_iter, rlwe_context_->first_context_data()->small_ntt_tables()[i]);
        inv_secret_key[i] = poly_iter;
    }

    // DEBUG
    std::cout << "Inverse NTT Secret Key is: " << std::endl;
    for (size_t i = 0; i < coeff_modulus_size; ++i) {
        auto poly_iter = inv_secret_key[i];
        for (size_t j = 0; j < large_coeff_count; ++j) {
            std::cout << poly_iter[j] << std::endl;
        }
    }
    std::cout << std::endl;

    // Then we extract inverse ntt form secret key
    // #pragma omp parallel for num_threads(num_th)
    for(int index=0; index<npoly; index++){
        util::RNSIter temp_key(rlwe_seckey_little_->data().data(), small_coeff_count);
        // SEAL_ALLOCATE_GET_RNS_ITER(temp_key, small_coeff_count, coeff_modulus_size, *pool_);
        for(int i=0; i<coeff_modulus_size; i++){
            auto poly_iter = inv_secret_key[i];
            auto temp_poly = temp_key[i];
            for (int j=0; j<small_coeff_count; j++){
                temp_poly[j] = poly_iter[j*npoly+index];
            }
            util::ntt_negacyclic_harvey(temp_poly, rlwe_context_little_->first_context_data()->small_ntt_tables()[i]);
            temp_key[i] = temp_poly;
        }

        // DEBUG
        std::cout << index << "-th To be keswitch Key is: " << std::endl;
        for (size_t i = 0; i < coeff_modulus_size; ++i) {
            auto poly_iter = temp_key[i];
            for (size_t j = 0; j < small_coeff_count; ++j) {
                std::cout << poly_iter[j] << std::endl;
            }
        }
        std::cout << std::endl;


        // Create key switch keys.
        // generate_one_kswitch_key(temp_key, KSkey_->data()[index], true);
        // generate_one_kswitch_key(temp_key, KSkey.data()[index], true);  
        encrypt(temp_key,KSkey_->data()[index]);      
    }

    // Set the parms_id (we add a new public setter, we can cancel this later)
    auto &context_data = *rlwe_context_little_->key_context_data();
    // KSkey_->set_parms_id(context_data.parms_id());


    return;
}

void Cryptor::kswitch_database(const RLWECipher &ilwe, std::vector<RLWECipher> &vec_olwe) const
{
    std::vector<Modulus> small_vec_mod = rlwe_parms_little_->coeff_modulus();
    std::vector<Modulus> large_vec_mod = rlwe_parms_->coeff_modulus();
    size_t large_coeff_count = RLWEParams::poly_modulus_degree;
    size_t small_coeff_count = RLWEParamsLittle::poly_modulus_degree;
    size_t coeff_modulus_size = small_vec_mod.size()<3? 1:small_vec_mod.size() - 1;
    size_t npoly = RLWEParamsLittle::npoly;
    vec_olwe.resize(npoly);

    // Copy result to encrypted.data(0)
    SEAL_ALLOCATE_GET_RNS_ITER(ilwe_b, large_coeff_count, coeff_modulus_size, *pool_);
    set_poly(ilwe.data(0), large_coeff_count, coeff_modulus_size, ilwe_b);

    // Copy result to encrypted.data(0)
    SEAL_ALLOCATE_GET_RNS_ITER(ilwe_a, large_coeff_count, coeff_modulus_size, *pool_);
    set_poly(ilwe.data(1), large_coeff_count, coeff_modulus_size, ilwe_a);

    // DEBUG
    std::cout << "ilwe b: " << std::endl;
    for(int i=0; i<coeff_modulus_size; i++){
        auto poly_iter = ilwe_b[i];
        for (int j=0; j<large_coeff_count; j++){
            std::cout << poly_iter[j] << std::endl;
        }
    }
    std::cout << std::endl;
    std::cout << "ilwe a: " << std::endl;
    for(int i=0; i<coeff_modulus_size; i++){
        auto poly_iter = ilwe_a[i];
        for (int j=0; j<large_coeff_count; j++){
            std::cout << poly_iter[j] << std::endl;
        }
    }
    std::cout << std::endl;
    
    for(int index=0; index<npoly; index++){
        // we extract b at first
        RLWECipher trivial_rlwe(*rlwe_context_little_);
        rlwe_encryptor_little_->encrypt_zero(trivial_rlwe);
        SEAL_ALLOCATE_GET_RNS_ITER(temp_b, small_coeff_count, coeff_modulus_size, *pool_);
        // set_poly(rlwe_temp.data(0), large_coeff_count, coeff_modulus_size, temp_b);

        // Extract temp b from trivial rlwe
        for(int i=0; i<coeff_modulus_size; i++){
            auto poly_iter = ilwe_b[i];
            auto temp_poly = temp_b[i];
            for (int j=0; j<small_coeff_count; j++){
                temp_poly[j] = poly_iter[j*npoly+index];
            }
            temp_b[i] = temp_poly;
        }

        // DEBUG
        std::cout << index << "-th temp b: " << std::endl;
        for(int i=0; i<coeff_modulus_size; i++){
            auto poly_iter = temp_b[i];
            for (int j=0; j<small_coeff_count; j++){
                std::cout << poly_iter[j] << std::endl;
            }
        }
        std::cout << std::endl;

        // construct trivial rlwe
        set_poly(temp_b, large_coeff_count, coeff_modulus_size, trivial_rlwe.data(0));
        util::set_zero_poly(small_coeff_count, coeff_modulus_size, trivial_rlwe.data(1));

        // DEBUG
        std::cout << "trivial b: " << std::endl;
        for(int i=0; i<coeff_modulus_size; i++){
            for(int j=0; j<small_coeff_count; j++){
                std::cout << trivial_rlwe.data(0)[j+i*small_coeff_count] << std::endl;
            }
        }
        std::cout << std::endl;
        std::cout << "trivial a: " << std::endl;
        for(int i=0; i<coeff_modulus_size; i++){
            for(int j=0; j<small_coeff_count; j++){
                std::cout << trivial_rlwe.data(1)[j+i*small_coeff_count] << std::endl;
            }
        }
        std::cout << std::endl;

        for (int i=0; i<(index+1); i++){
            SEAL_ALLOCATE_GET_RNS_ITER(temp_a, small_coeff_count, coeff_modulus_size, *pool_);
            // Extract temp a from trivial rlwe
            for(int j=0; j<coeff_modulus_size; j++){
                auto poly_iter = ilwe_a[j];
                auto temp_poly = temp_a[j];
                for (int t=0; t<small_coeff_count; t++){
                    temp_poly[t] = poly_iter[t*npoly+i];
                }
                temp_a[j] = temp_poly;
            }

            // DEBUG
            std::cout << i << "-th temp a: " << std::endl;
            for(int j=0; j<coeff_modulus_size; j++){
                auto poly_iter = temp_a[j];
                for (int t=0; t<small_coeff_count; t++){
                    std::cout << poly_iter[t] << std::endl;
                }
            }
            std::cout << std::endl;

            // Calculate temp * kskey[i]
            RLWECipher temp_rlwe(*rlwe_context_little_);
            rlwe_encryptor_little_->encrypt_zero(temp_rlwe);
            auto temp_ksrlev = KSkey_->data()[i];
            std::cout << "temp_ksrlev.size(): " << temp_ksrlev.size() << std::endl;
            RLevCipher temp_rlev;
            temp_rlev.reserve(rlwe_context_->first_context_data()->parms().coeff_modulus().size());
            for (size_t j = 0; j < rlwe_context_->first_context_data()->parms().coeff_modulus().size(); j++) {
                RLWECipher rlwe;
                rlwe = temp_ksrlev[j].data();
                temp_rlev.emplace_back(rlwe);
            }
            keyswitch(temp_a, temp_rlev, temp_rlwe, ParamSet::LWE);
            rlwe_evaluator_little_->add_inplace(trivial_rlwe, temp_rlwe);

        }


    }

    return;
}

void Cryptor::lwe_copy(const std::vector<LWECipher> &lwe1, std::vector<LWECipher> &lwe2) const
{
    size_t N = RLWEParams::poly_modulus_degree;
    size_t n = RLWEParamsLittle::poly_modulus_degree;
    lwe2.resize(N);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<N; i++){
        lwe2[i].resize(n+1);
        for(int j=0; j<n+1; j++){
            lwe2[i][j] = lwe1[i][j];
        }
    }
    return;
}

void Cryptor::packlwes(const std::vector<LWECipher> &lwevec, RLWECipher &rlwe, const bool withtrace) const
{
    std::cout << "We switch to last when pack lwe" << std::endl;
    rlwe_evaluator_little_->mod_switch_to_inplace(rlwe, rlwe_context_little_->last_parms_id());
    std::vector<RLWECipher> packedrlwes;
    size_t nslot = lwevec.size();
    size_t lognslot;
    // SEAL_MSB_INDEX_UINT64(&lognslot, nslot);
    util::get_msb_index_generic(&lognslot, nslot);
    packedrlwes.reserve((1UL << lognslot));
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < (1UL << lognslot); i++) {
        // RLWECipher temp(*rlwe_context_);
        RLWECipher temp = rlwe;
        temp.resize(2);
        size_t idx = util::bitrev(i, (1UL << lognslot));
        if (idx < nslot) {
            LWECipher temp_lwe(lwevec[idx]);
            if (withtrace)
                LWEpreinverse(temp_lwe, 1);
            LWEtoRLWE(temp_lwe, temp);
        }
        packedrlwes.push_back(temp);
    }
    // #pragma omp parallel for num_threads(num_th)
    for (size_t m = 1; m < (1UL << lognslot); m <<= 1) {
        for (size_t i = 0; i < (1UL << lognslot); i += 2 * m) {
            util::negacyclic_multiply_poly_mono_coeffmod(packedrlwes[i + m], 2, 1, RLWEParams::poly_modulus_degree / (2 * m), rlwe_context_->first_context_data()->parms().coeff_modulus(), packedrlwes[i + m], *pool_);
            RLWECipher temp(packedrlwes[i]);
            rlwe_evaluator_->sub_inplace(temp, packedrlwes[i + m]);
            rlwe_evaluator_->add_inplace(packedrlwes[i], packedrlwes[i + m]);
            rlwe_evaluator_->apply_galois_inplace(temp, 2 * m + 1, *rlwe_galoiskeys_);
            rlwe_evaluator_->add_inplace(packedrlwes[i], temp);
        }
    }
    rlwe = packedrlwes[0];
    if (withtrace)
        field_trace(rlwe, 1ULL << lognslot);
}

void Cryptor::field_trace(RLWECipher &rlwe, const size_t nslot, const size_t cur_nslot) const
{
    RLWECipher temp(*rlwe_context_);
    temp.resize(2);
    for (size_t i = cur_nslot; i > nslot; i >>= 1) {
        rlwe_evaluator_->apply_galois(rlwe, i + 1, *rlwe_galoiskeys_, temp);
        rlwe_evaluator_->add_inplace(rlwe, temp);
    }
}

void Cryptor::HomoSign(const uint64_t &Q, const uint64_t &alpha, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe, uint64_t &final_sign) const
{

    util::print_example_banner("Sign Evaluation Starts!");

    std::vector<LWECipher> input_lwe_temp;
    lwe_copy(input_vec_lwe, input_lwe_temp);

    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;
    uint64_t message_debug = 0;
    
    // 1. Initialize LWE ciphertext
    // (1) set up LWE Q
    // uint64_t Q = (1<<17); // we can clean 16(log q) bit each time cause q = 65537
    uint64_t Q_temp = Q; // WARNING: max is 26 bit (16 bit for message) now
    // std::cout << "Q: " << Q << " in binary: ";
    // seal::util::printInBinary(Q);
    // (2) set up PBS Q'
    uint64_t q = seal::RLWEParamsLittle::plain_modulus;
    // std::cout << "q: " << q << " in binary: ";
    // seal::util::printInBinary(q);
    // (3) set up alpha for noise
    // uint64_t alpha = 10; // alpha - 1 bit for noise
    // uint64_t bias = (1<<alpha) - 1;
    // std::cout << "bias: " << bias << " in binary: ";
    // seal::util::printInBinary(bias);
    // (4) set up message (maximum here)
    // uint64_t message = std::round((double)(Q-1-bias) / (double) Q * (double) q); // max message we can encrypt
    // std::cout << "message: " << message << " in binary: ";
    // seal::util::printInBinary(message);
    // uint64_t step = round(Q/q);
    // std::vector<seal::LWECipher> initial_vec_lwe;
    // encrypt message
    // cryptor.construct_lwe_sign(message, Q, initial_vec_lwe); // LWE in Q encrypting (bit / 2) 
    // TODO: why bit/2?(because q is not power of 2), our strategy is modify message

    // Run HomoFloor to clean log(q) significant bits
    size_t times = 0;
    uint64_t alpha_temp = alpha;
    while (Q_temp > q){
        // print title
        std::string title = std::to_string(times) + "-th HomoFloor Start!";
        seal::util::print_example_banner(title);


        // step 1: run HomoFloor
        HomoFloor(Q_temp, input_lwe_temp);
        
        // step2: scale down Q_temp
        // std::cout << "old Q_temp: " << Q_temp << std::endl;
        // std::cout << "q: " << q << std::endl;
        // std::cout << "alpha: " << alpha << std::endl;
        Q_temp = std::round( (double) Q_temp * ( (double) (1<<alpha_temp) / (double) (q-1) ));
        if(Q_temp < q){
            alpha_temp = (1<<alpha_temp) * ((q-1)/Q_temp);
            Q_temp = (q-1);
            // step3: scale down LWE
            lwe_scale_down((q-1), alpha_temp, input_lwe_temp);
        }
        else{
            // step3: scale down LWE
            lwe_scale_down((q-1), (1<<alpha_temp), input_lwe_temp);
        }

        
        
        // WARNING:scale down to alpha_temp/q operation creates larege noise, so we scale to alpha_temp/(q-1)
        std::cout << "renew Q: " << Q_temp << " in binary: ";
        util::printInBinary(Q_temp);

        if(lwe_dec)
            lwe_manual_decrypt(input_lwe_temp[index], message_debug, true, Q_temp, 65537);

        times++;
    }
    // Q < q now

    // d = d + beta
    uint64_t beta = 1700; // 70 is from experiment
    std::vector<seal::LWECipher> lwe_beta;
    lwe_add_beta(input_lwe_temp, Q_temp, beta, lwe_beta);
    if(lwe_dec)
        lwe_manual_decrypt(lwe_beta[index], message_debug, true, Q_temp, 65537);

    // (a,b) = (Q/q) * (c,d)
    if(Q_temp > q){
        lwe_scale_down(Q_temp, (q-1), lwe_beta); // modify to q-1
        if(lwe_dec)
            lwe_manual_decrypt(lwe_beta[index], message_debug, true, q, 65537);
    }
    

    // (c,d) = Boot[f0(a,b)] (mod Q)
    seal::Modulus mod_RLWE = get_first_modulus();
    // std::vector<seal::LWECipher> vec_lwe_final;
    // Batch_sign(mod_RLWE.value(), lwe_beta, output_vec_lwe);
    Batch_sign(Q, lwe_beta, output_vec_lwe);
    if(lwe_dec){
        // lwe_manual_decrypt(output_vec_lwe[index], message_debug, true, mod_RLWE.value(), 65537);
        lwe_manual_decrypt(output_vec_lwe[index], message_debug, true, Q, 65537);
    }
    final_sign = (message_debug%RLWEParamsLittle::plain_modulus);
    std::cout << "Final Sign: " << final_sign << std::endl;
    
    // (c,d) = -(c,d)
    // cryptor.lwe_neg(q, vec_lwe_final);
    // cryptor.lwe_manual_decrypt(vec_lwe_final[index], message_debug, true, q, 65537);

    return;
}

void Cryptor::HomoFloor(const uint64_t &Q, std::vector<LWECipher> &input_vec_lwe) const
{

    // 0. set up parameter
    // uint64_t Q = 1<<(18-1); // total LWE Modulus
    // uint64_t Q = 16777472;
    std::cout << "Q: " << Q << " in binary: ";
    seal::util::printInBinary(Q);
    uint64_t q = seal::RLWEParams::plain_modulus; // PBS Modulus
    std::cout << "q: " << q << " in binary: ";
    seal::util::printInBinary(q);
    uint64_t N = seal::RLWEParamsLittle::poly_modulus_degree; // total LWE degree
    std::cout << "N: " << N << " in binary: ";
    seal::util::printInBinary(N);
    uint64_t message_debug = 0; // for debug
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    // std::cout << "index: " << index <<  std::endl;
    uint64_t PBS_scale = round(double(Q) / (double) q);
    std::cout << "PBS Scale: " << PBS_scale << std::endl;

    // // 1. Initialize LWE ciphertext
    // uint64_t bit = q/(alpha) -  1; // limitation: bit should less than SEAL::RLWEParamsLittle:plain_modulus here
    // std::cout << "bit: " << bit << " in binary: ";
    // seal::util::printInBinary(bit);
    // // uint64_t message = bit * alpha; // message here is scale up from bit to Q
    // uint64_t message = 65025;
    // std::cout << "message: " << message << " in binary: ";
    // seal::util::printInBinary(message);
    // std::vector<seal::LWECipher> initial_vec_lwe;
    // cryptor.construct_lwe_sign(message, Q, initial_vec_lwe); // LWE in Q encrypting (bit / 2) 
    // // TODO: why bit/2?(because q is not power of 2), our strategy is modify message

    // 2. d = d + b
    uint64_t beta = 1000; // 70 is from experiment
    std::vector<seal::LWECipher> lwe_beta;
    lwe_add_beta(input_vec_lwe, Q, beta, lwe_beta);
    if(lwe_dec)
        lwe_manual_decrypt(lwe_beta[index], message_debug, true, Q, 65537);

    // 3. Line3: (a,b) = (c,d) mod q 
    // WARNING: we change to mod 65536 but not mod q
    std::vector<seal::LWECipher> lwe_in_q;
    lwe_mod_q(lwe_beta, lwe_in_q);
    if(lwe_dec)
        lwe_manual_decrypt(lwe_beta[index], message_debug, true, Q, 65537);
    if(lwe_dec)
        lwe_manual_decrypt(lwe_in_q[index], message_debug, true, 65537, 65537);
    
    // 4. Line 4: Boot[f0(x)](a,b) mod q
    std::vector<seal::LWECipher> lwe_f0;
    lwe_f0.resize(seal::RLWEParams::poly_modulus_degree);
    Batch_f0(Q, lwe_in_q, lwe_f0);
    if(lwe_dec)
        lwe_manual_decrypt(lwe_f0[index], message_debug, true, Q, 65537);

    // 5. Line 4: (c,d) = (c,d) - Boot[f0(x)](a,b) mod Q
    std::vector<seal::LWECipher> lwe_step5;
    lwe_step5.resize(seal::RLWEParams::poly_modulus_degree);
    lwe_sub(lwe_beta, lwe_f0, Q, lwe_step5);
    if(lwe_dec)
        lwe_manual_decrypt(lwe_step5[index], message_debug, true, Q, 65537);

    // 6. Line 5: d = d + beta - q/4
    uint64_t beta_q_4 = seal::util::sub_uint_mod(70, q/4, Q); // beta - q/4; TODO: should we use 65536?
    std::cout << "beta_q_4: " << beta_q_4 << std::endl;
    std::vector<seal::LWECipher> lwe_step_six;
    lwe_step_six.resize(seal::RLWEParams::poly_modulus_degree);
    lwe_add_beta(lwe_step5, Q, beta_q_4, lwe_step_six);
    if(lwe_dec)
        lwe_manual_decrypt(lwe_step_six[index], message_debug, true, Q, 65537);

    // 7. Line 6: (a,b) = (c,d) mod q
    // WARNING: we change to mod 65536 but not mod q
    lwe_mod_q(lwe_step_six, lwe_in_q);
    if(lwe_dec)
        lwe_manual_decrypt(lwe_in_q[index], message_debug, true, 65537, 65537);

    // 8. Line 7: Boot[f1(x)](a,b)
    std::vector<seal::LWECipher> lwe_f1;
    lwe_f1.resize(seal::RLWEParams::poly_modulus_degree);
    Batch_f1(Q, lwe_in_q, lwe_f1);
    if(lwe_dec)
        lwe_manual_decrypt(lwe_f1[index], message_debug, true, Q, 65537);

    // 9. Line 7: (c,d) = (c,d) - Boot[f1(x)](a,b) mod Q
    // std::vector<seal::LWECipher> lwe_step9;
    // output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    lwe_sub(lwe_step_six, lwe_f1, Q, input_vec_lwe);
    if(lwe_dec)
        lwe_manual_decrypt(input_vec_lwe[index], message_debug, true, Q, 65537);

    return;
    
}

void Cryptor::HomoFloor(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe) const
{

    // 0. set up parameter
    // uint64_t Q = 1<<(18-1); // total LWE Modulus
    // uint64_t Q = 16777472;
    std::cout << "Q: " << Q << " in binary: ";
    seal::util::printInBinary(Q);
    uint64_t q = seal::RLWEParams::plain_modulus; // PBS Modulus
    std::cout << "q: " << q << " in binary: ";
    seal::util::printInBinary(q);
    uint64_t N = seal::RLWEParamsLittle::poly_modulus_degree; // total LWE degree
    std::cout << "N: " << N << " in binary: ";
    seal::util::printInBinary(N);
    uint64_t message_debug = 0; // for debug
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    // std::cout << "index: " << index <<  std::endl;
    uint64_t PBS_scale = round(double(Q) / (double) q);
    std::cout << "PBS Scale: " << PBS_scale << std::endl;

    // // 1. Initialize LWE ciphertext
    // uint64_t bit = q/(alpha) -  1; // limitation: bit should less than SEAL::RLWEParamsLittle:plain_modulus here
    // std::cout << "bit: " << bit << " in binary: ";
    // seal::util::printInBinary(bit);
    // // uint64_t message = bit * alpha; // message here is scale up from bit to Q
    // uint64_t message = 65025;
    // std::cout << "message: " << message << " in binary: ";
    // seal::util::printInBinary(message);
    // std::vector<seal::LWECipher> initial_vec_lwe;
    // cryptor.construct_lwe_sign(message, Q, initial_vec_lwe); // LWE in Q encrypting (bit / 2) 
    // // TODO: why bit/2?(because q is not power of 2), our strategy is modify message

    // 2. d = d + b
    uint64_t beta = 70; // 70 is from experiment
    std::vector<seal::LWECipher> lwe_beta;
    lwe_add_beta(input_vec_lwe, Q, beta, lwe_beta);
    lwe_manual_decrypt(lwe_beta[index], message_debug, true, Q, 65537);

    // 3. Line3: (a,b) = (c,d) mod q 
    // WARNING: we change to mod 65536 but not mod q
    std::vector<seal::LWECipher> lwe_in_q;
    lwe_mod_q(lwe_beta, lwe_in_q);
    lwe_manual_decrypt(lwe_beta[index], message_debug, true, Q, 65537);
    lwe_manual_decrypt(lwe_in_q[index], message_debug, true, 65537, 65537);
    
    // 4. Line 4: Boot[f0(x)](a,b) mod q
    std::vector<seal::LWECipher> lwe_f0;
    lwe_f0.resize(seal::RLWEParams::poly_modulus_degree);
    Batch_f0(Q, lwe_in_q, lwe_f0);
    lwe_manual_decrypt(lwe_f0[index], message_debug, true, Q, 65537);

    // 5. Line 4: (c,d) = (c,d) - Boot[f0(x)](a,b) mod Q
    std::vector<seal::LWECipher> lwe_step5;
    lwe_step5.resize(seal::RLWEParams::poly_modulus_degree);
    lwe_sub(lwe_beta, lwe_f0, Q, lwe_step5);
    lwe_manual_decrypt(lwe_step5[index], message_debug, true, Q, 65537);

    // 6. Line 5: d = d + beta - q/4
    uint64_t beta_q_4 = seal::util::sub_uint_mod(70, q/4, Q); // beta - q/4; TODO: should we use 65536?
    std::cout << "beta_q_4: " << beta_q_4 << std::endl;
    std::vector<seal::LWECipher> lwe_step_six;
    lwe_step_six.resize(seal::RLWEParams::poly_modulus_degree);
    lwe_add_beta(lwe_step5, Q, beta_q_4, lwe_step_six);
    lwe_manual_decrypt(lwe_step_six[index], message_debug, true, Q, 65537);

    // 7. Line 6: (a,b) = (c,d) mod q
    // WARNING: we change to mod 65536 but not mod q
    lwe_mod_q(lwe_step_six, lwe_in_q);
    lwe_manual_decrypt(lwe_in_q[index], message_debug, true, 65537, 65537);

    // 8. Line 7: Boot[f1(x)](a,b)
    std::vector<seal::LWECipher> lwe_f1;
    lwe_f1.resize(seal::RLWEParams::poly_modulus_degree);
    Batch_f1(Q, lwe_in_q, lwe_f1);
    lwe_manual_decrypt(lwe_f1[index], message_debug, true, Q, 65537);

    // 9. Line 7: (c,d) = (c,d) - Boot[f1(x)](a,b) mod Q
    // std::vector<seal::LWECipher> lwe_step9;
    output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    lwe_sub(lwe_step_six, lwe_f1, Q, output_vec_lwe);
    lwe_manual_decrypt(output_vec_lwe[index], message_debug, true, Q, 65537);

    return;
    
}

void Cryptor::lwe_neg(const uint64_t &Q, std::vector<LWECipher> &lwe_vec) const
{
    util::print_example_banner("LWE Negative");
    Modulus mod_Q(Q);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        for(int j=0; j<seal::RLWEParamsLittle::poly_modulus_degree + 1; j++){
            if(i==0&&j==0){
                std::cout << "ilwe: " << lwe_vec[i][j] << " in binary: ";
                util::printInBinary(lwe_vec[i][j]);            
            }
            lwe_vec[i][j] = util::negate_uint_mod(lwe_vec[i][j], mod_Q);
            if(i==0&&j==0){
                std::cout << "olwe: " << lwe_vec[i][j] << " in binary: ";
                util::printInBinary(lwe_vec[i][j]);                
            }
        }
    }
    return;
}

void Cryptor::lwe_scale_down(const uint64_t &q, const uint64_t &alpha, std::vector<LWECipher> &lwe_vec) const
{
    util::print_example_banner("LWE Scale Down");
    double down_scale = (double) alpha / (double) q;
    // DEBUG
    std::cout << "down_scale: " << down_scale << std::endl;
    // TODO: We change to shift will improve speed
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        for(int j=0; j<seal::RLWEParamsLittle::poly_modulus_degree + 1; j++){
            if(i==0&&j==0){
                std::cout << "ilwe: " << lwe_vec[i][j] << " in binary: ";
                util::printInBinary(lwe_vec[i][j]);            
            }
            lwe_vec[i][j] = std::round((double) lwe_vec[i][j] * down_scale);
            if(i==0&&j==0){
                std::cout << "olwe: " << lwe_vec[i][j] << " in binary: ";
                util::printInBinary(lwe_vec[i][j]);                
            }
        }
    }

    return;
}

void Cryptor::lwe_sub(const std::vector<LWECipher> &ilwe_1, const std::vector<LWECipher> &ilwe_2, const uint64_t &Q, std::vector<LWECipher> &olwe) const
{
    util::print_example_banner("LWE Sub");
    // Modulus mod_q(RLWEParams::plain_modulus);
    Modulus mod_Q(Q);
    olwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        olwe[i].resize(seal::RLWEParamsLittle::poly_modulus_degree + 1);
        for(int j=0; j<seal::RLWEParamsLittle::poly_modulus_degree + 1; j++){
            olwe[i][j] = util::sub_uint_mod(ilwe_1[i][j], ilwe_2[i][j], mod_Q);
            if(j==0&&i==0){
                std::cout << "ilwe_1: " << ilwe_1[i][j] << " in binary: ";
                util::printInBinary(ilwe_1[i][j]);
                std::cout << "ilwe_2: " << ilwe_2[i][j] << " in binary: ";
                util::printInBinary(ilwe_2[i][j]);
                std::cout << "olwe: " << olwe[i][j] << " in binary: ";
                util::printInBinary(olwe[i][j]);                
            }
        }
    }
    return;
}

void Cryptor::lwe_add_beta(const std::vector<LWECipher> &ilwe, const uint64_t &Q, const uint64_t &beta, std::vector<LWECipher> &olwe, const bool &if_print) const
{
    if(if_print)
        util::print_example_banner("LWE add beta");
    // Modulus mod_q(RLWEParams::plain_modulus);
    Modulus mod_Q(Q);
    olwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        olwe[i].resize(seal::RLWEParamsLittle::poly_modulus_degree + 1);
        for(int j=0; j<seal::RLWEParamsLittle::poly_modulus_degree + 1; j++){
            olwe[i][j] = util::multiply_uint_mod(ilwe[i][j], 1, mod_Q);
            if(j==0){
                olwe[i][j] = util::add_uint_mod(ilwe[i][j], beta, mod_Q);
                if(i==0 && if_print){
                    std::cout << "ilwe: " << ilwe[i][j] << " in binary: ";
                    util::printInBinary(ilwe[i][j]);
                    std::cout << "olwe: " << olwe[i][j] << " in binary: ";
                    util::printInBinary(olwe[i][j]);
                }
                
            }
        }
    }
    return;
}

void Cryptor::lwe_mod_q(const std::vector<LWECipher> &lwe_Q, std::vector<LWECipher> &lwe_q) const
{
    util::print_example_banner("LWE mod q");
    // Modulus mod_q(RLWEParams::plain_modulus);
    Modulus mod_q(65536);
    lwe_q.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        lwe_q[i].resize(seal::RLWEParamsLittle::poly_modulus_degree + 1);
        for(int j=0; j<seal::RLWEParamsLittle::poly_modulus_degree + 1; j++){
            lwe_q[i][j] = util::multiply_uint_mod(lwe_Q[i][j], 1, mod_q);
            if(i==0&&j==0){
                std::cout << "lwe_Q: " << lwe_Q[i][j] << " in binary: ";
                util::printInBinary(lwe_Q[i][j]);
                std::cout << "lwe_q: " << lwe_q[i][j] << " in binary: ";
                util::printInBinary(lwe_q[i][j]);
            }
        }
    }
    return;
}

void Cryptor::construct_lwe_XOR(const uint64_t &bit, const uint64_t &Q, std::vector<LWECipher> &vec_lwe) const
{   
    util::print_example_banner("Construct LWE");

    // limitation is bit < RLWELittleParms::plain_modulus (we can expand RLWELittleParms::plain_modulus)

    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    time_start = std::chrono::high_resolution_clock::now();
    // Strandard Initialize b-As TODO: implement (p,t=q) lwe apart from(t, Q) lwe in SEAL and modswitch
    seal::Plaintext ptxt_initial(seal::RLWEParamsLittle::poly_modulus_degree);  // ptxt of all 0 result should be t/3
    for(int i=0; i<seal::RLWEParamsLittle::poly_modulus_degree; i++){
        ptxt_initial.data()[i] = bit;
    }
    seal::RLWECipher ctxt_initial;
    encrypt(ptxt_initial, ctxt_initial, seal::ParamSet::RLWELittle);
    // we should mod switch to last when meet multi level
    rlwe_evaluator_little_->mod_switch_to_inplace(ctxt_initial, rlwe_context_little_->last_parms_id());
    std::vector<seal::LWECipher> lwe_initial_vec;
    lwe_initial_vec.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        SampleExtract(ctxt_initial, lwe_initial_vec[i], i%(seal::RLWEParamsLittle::poly_modulus_degree), false, seal::ParamSet::LWE);
    }
    vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(lwe_initial_vec[i], 65537, Q, vec_lwe[i]);
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Initial LWE Done [" << time_diff.count() << " microseconds]" << std::endl;
    // DEBUG
    uint64_t manual_result = 0;
    lwe_manual_decrypt(vec_lwe[index], manual_result, true, Q, 65537);
    return;
}

void Cryptor::construct_lwe_AES(const uint64_t &Q, std::vector<LWECipher> &vec_lwe) const
{   
    util::print_example_banner("Construct LWE");

    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    time_start = std::chrono::high_resolution_clock::now();
    seal::Plaintext ptxt_initial(seal::RLWEParamsLittle::poly_modulus_degree);  // ptxt of all 0 result should be t/3
    for(int i=0; i<seal::RLWEParamsLittle::poly_modulus_degree; i++){
        ptxt_initial.data()[i] = ((i % 16) + 1) * 128;
    }
    seal::RLWECipher ctxt_initial;
    encrypt(ptxt_initial, ctxt_initial, seal::ParamSet::RLWELittle);
    // we should mod switch to last when meet multi level
    rlwe_evaluator_little_->mod_switch_to_inplace(ctxt_initial, rlwe_context_little_->last_parms_id());
    std::vector<seal::LWECipher> lwe_initial_vec;
    lwe_initial_vec.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        SampleExtract(ctxt_initial, lwe_initial_vec[i], i%(seal::RLWEParamsLittle::poly_modulus_degree), false, seal::ParamSet::LWE);
    }
    vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(lwe_initial_vec[i], 65537, Q, vec_lwe[i]);
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Initial LWE Done [" << time_diff.count() << " microseconds]" << std::endl;
    // DEBUG
    uint64_t manual_result = 0;
    lwe_manual_decrypt(vec_lwe[index], manual_result, true, Q, 65537);
    return;
}

void Cryptor::construct_lwe_sign(const uint64_t &bit, const uint64_t &Q, std::vector<LWECipher> &vec_lwe) const
{   
    util::print_example_banner("Construct LWE");
    // limitation is bit < RLWELittleParms::plain_modulus (we can expand RLWELittleParms::plain_modulus)

    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    time_start = std::chrono::high_resolution_clock::now();
    // Strandard Initialize b-As TODO: implement (p,t=q) lwe apart from(t, Q) lwe in SEAL and modswitch
    // seal::VecData vec_initial(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL); // vector of all 0 result should be t/3
    seal::Plaintext ptxt_initial(seal::RLWEParamsLittle::poly_modulus_degree);  // ptxt of all 0 result should be t/3
    for(int i=0; i<seal::RLWEParamsLittle::poly_modulus_degree; i++){
        // vec_initial[i] = 21845;
        if(bit >= RLWEParamsLittle::plain_modulus){
            ptxt_initial.data()[i] = 0; // we later add to b of LWE
        }
        else{
            ptxt_initial.data()[i] = bit;
        }
    }
    seal::RLWECipher ctxt_initial;
    // cryptor.encrypt(vec_initial, ctxt_initial, seal::ParamSet::RLWELittle);
    encrypt(ptxt_initial, ctxt_initial, seal::ParamSet::RLWELittle);
    // we should mod switch to last when meet multi level
    rlwe_evaluator_little_->mod_switch_to_inplace(ctxt_initial, rlwe_context_little_->last_parms_id());
    std::vector<seal::LWECipher> lwe_initial_vec;
    lwe_initial_vec.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        SampleExtract(ctxt_initial, lwe_initial_vec[i], i%(seal::RLWEParamsLittle::poly_modulus_degree), false, seal::ParamSet::LWE);
    }
    // std::cout << index << "-th LWE decryption: " << decrypt(lwe_initial_vec[index], seal::ParamSet::RLWELittle) << " in binary: ";
    // util::printInBinary(decrypt(lwe_initial_vec[index], seal::ParamSet::RLWELittle));
    // std::vector<seal::LWECipher> lwe_initial_vec_ms;
    vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();
    if(bit >= RLWEParamsLittle::plain_modulus){
        uint64_t bias = (RLWEParamsLittle::plain_modulus-1) * vec_mod[0].value() / RLWEParamsLittle::plain_modulus;
        std::cout << "bias: " << bias << "in binary: ";
        util::printInBinary(bias);
        #pragma omp parallel for num_threads(num_th)
        for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
            lwe_add_b(lwe_initial_vec[i], bias, *vec_mod[0].data());
        }
        
    }
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(lwe_initial_vec[i], 65537, Q, vec_lwe[i]);
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Initial LWE Done [" << time_diff.count() << " microseconds]" << std::endl;
    // DEBUG
    uint64_t manual_result = 0;
    lwe_manual_decrypt(vec_lwe[index], manual_result, true, Q, 65537);
    // std::cout << index << "-th LWE manual decryption: " << manual_result << " in binary: ";
    // util::printInBinary(manual_result);
    return;
}

void Cryptor::lwe_add_b (LWECipher &ilwe, const uint64_t &bias, const uint64_t &Q) const
{
    // std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();
    // uint64_t mod_coef = *vec_mod[0].data();
    // Modulus mod_q(mod_coef);
    Modulus mod_q(Q);
    ilwe[0] = util::add_uint_mod(ilwe[0], bias, mod_q);
    return;
}

void Cryptor::LWEpreinverse(LWECipher &lwe, const uint64_t scale) const
{
    for (size_t i = 0; i < RGSWParams::coeff_modulus_size; i++) {
        auto &modulus = rgsw_parms_->coeff_modulus()[i];
        for (size_t j = 0; j < RGSWParams::poly_modulus_degree + 1; j++)
            lwe[i * (RGSWParams::poly_modulus_degree + 1) + j] =
                util::multiply_uint_mod(lwe[i * (RGSWParams::poly_modulus_degree + 1) + j], util::multiply_uint_mod(scale, mod_inv[i], modulus), modulus);
    }
}

void Cryptor::beta_detection() const
{

    uint64_t message = 32768;
    std::cout << "message is: " << message << std::endl;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    seal::Plaintext ptxt_initial(seal::RLWEParamsLittle::poly_modulus_degree);  // ptxt of all 0 result should be t/3
    for(int i=0; i<seal::RLWEParamsLittle::poly_modulus_degree; i++){
        // vec_initial[i] = 21845;
        ptxt_initial.data()[i] = message;
    }
    seal::RLWECipher ctxt_initial;
    // cryptor.encrypt(vec_initial, ctxt_initial, seal::ParamSet::RLWELittle);
    encrypt(ptxt_initial, ctxt_initial, seal::ParamSet::RLWELittle);
    std::vector<seal::LWECipher> lwe_initial_vec;
    lwe_initial_vec.resize(seal::RLWEParams::poly_modulus_degree);
    std::vector<seal::LWECipher> ms_lwe;
    ms_lwe.resize(seal::RLWEParams::poly_modulus_degree);


    // find qulified prime number
    // int bit_size = 29;
    std::cout << "=================" << std::endl;
    for(int bit_size = 12; bit_size<30; bit_size++){
        uint64_t lower_bound = uint64_t(0x1) << (bit_size - 1);
        // std::cout << "lower bound: " << lower_bound << std::endl;
        // uint64_t factor = 2 * RLWEParamsLittle::poly_modulus_degree; // wrong
        uint64_t factor = 2 * 32768; // correct
        // std::cout << "factor: " << factor << std::endl;
        uint64_t value = ((uint64_t(0x1) << bit_size) - 1) / factor * factor + 1;
        // std::cout << "Initial value: " << value << std::endl; 
        while (value > lower_bound)
        {
            // std::cout << "Now value: " << value << std::endl;
            Modulus new_mod(value);
            if (new_mod.is_prime())
            {
                std::cout << "bit size: " << bit_size << " find prime: " << value << std::endl;
                #pragma omp parallel for num_threads(num_th)
                for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
                    SampleExtract(ctxt_initial, lwe_initial_vec[i], i%(seal::RLWEParamsLittle::poly_modulus_degree), false, seal::ParamSet::LWE);
                    ModSwitchLWE(lwe_initial_vec[i], 65537,value, ms_lwe[i]);
                }
                uint64_t dec_result = 0;
                lwe_manual_decrypt(ms_lwe[index], dec_result, true, value, 65537); // remember last line of lwe_manual_decrypt should be changed
                std::cout << "message: " << 32768 * value / 65537 << std::endl;
                std::cout << index << "-th LWE decryption: " << dec_result << std::endl;
                std::cout << "Decryption correct!" << std::endl;
                uint64_t max_beta = 0;
                uint64_t min_beta = UINT64_MAX;
                for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
                    uint64_t temp_dec = 0;
                    lwe_manual_decrypt(ms_lwe[i], temp_dec, true, value, 65537);
                    if(max_beta < temp_dec){
                        max_beta = temp_dec;
                        // std::cout << "max beta update: " << max_beta << std::endl;
                    }
                    if(min_beta > temp_dec){
                        min_beta = temp_dec;
                        // std::cout << "min beta update: " << min_beta << std::endl;
                    }
                }
                if(max_beta > 32768 * value / 65537){
                    std::cout << "max beta is: " << max_beta - 32768 * value / 65537 << std::endl;
                }
                else{
                    std::cout << "max beta is: " << 0 << std::endl;
                }
                if(min_beta < 32768 * value / 65537){
                    std::cout << "min beta is: " << 32768 * value / 65537 - min_beta << std::endl;
                }
                else{
                    std::cout << "min beta is: " << 0 << std::endl;
                }
                std::cout << "=================" << std::endl;
                break;
            }
            value -= factor;
        }
    }


    return;
}

void Cryptor::print_noise(const RLWECipher &rlwe, const ParamSet paramset) const
{
    if (paramset == ParamSet::RLWE){
        std::cout <<"long rlwe noise budget: " << rlwe_decryptor_->invariant_noise_budget(rlwe) << " bits" << std::endl;
    }
    else if(paramset == ParamSet::RLWELittle){
        std::cout <<"short rlwe noise budget: " << rlwe_decryptor_little_->invariant_noise_budget(rlwe) << " bits" << std::endl;
    }
    else{
        std::cout << "paramset must be RLWE or RLWELittle";
    }
    return;
}

void Cryptor::construct_lwe(const uint64_t &message, std::vector<LWECipher> &vec_lwe) const
{
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    time_start = std::chrono::high_resolution_clock::now();
    // Strandard Initialize b-As TODO: implement (p,t=q) lwe apart from(t, Q) lwe in SEAL and modswitch
    // seal::VecData vec_initial(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL); // vector of all 0 result should be t/3
    seal::Plaintext ptxt_initial(seal::RLWEParamsLittle::poly_modulus_degree);  // ptxt of all 0 result should be t/3
    for(int i=0; i<seal::RLWEParamsLittle::poly_modulus_degree; i++){
        // vec_initial[i] = 21845;
        ptxt_initial.data()[i] = message;
    }
    seal::RLWECipher ctxt_initial;
    // cryptor.encrypt(vec_initial, ctxt_initial, seal::ParamSet::RLWELittle);
    encrypt(ptxt_initial, ctxt_initial, seal::ParamSet::RLWELittle);
    std::vector<seal::LWECipher> lwe_initial_vec;
    lwe_initial_vec.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        SampleExtract(ctxt_initial, lwe_initial_vec[i], i%(seal::RLWEParamsLittle::poly_modulus_degree), false, seal::ParamSet::LWE);
    }
    std::cout << index << "-th LWE decryption: " << decrypt(lwe_initial_vec[index], seal::ParamSet::RLWELittle) << std::endl;
    // std::vector<seal::LWECipher> lwe_initial_vec_ms;
    vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(lwe_initial_vec[i], 65537, 65537, vec_lwe[i]);
    }
    // we do LWE-addition here
    seal::Modulus mod_plain(seal::RLWEParamsLittle::plain_modulus);
    uint64_t q_6 = seal::RLWEParamsLittle::plain_modulus / 6;
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        for(int j=0; j<seal::RLWEParamsLittle::poly_modulus_degree+1; j++){
            // std::cout << "Before addition: "<< vec_lwe[i][j] << " ";
            vec_lwe[i][j] = seal::util::add_uint_mod(vec_lwe[i][j], vec_lwe[i][j], mod_plain);
            if(j==0){ // b + q/6
                vec_lwe[i][j] = seal::util::add_uint_mod(vec_lwe[i][j], q_6, mod_plain);
            }
            // std::cout << "After addition: "<< vec_lwe[i][j] << std::endl;
        }
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Initial LWE Done [" << time_diff.count() << " microseconds]" << std::endl;
    // DEBUG
    uint64_t manual_result = 0;
    lwe_manual_decrypt(vec_lwe[index], manual_result, true, 65537, 65537);
    std::cout << index << "-th LWE manual decryption: " << manual_result << std::endl;

    return;
}

void Cryptor::Batch_Customize(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe, const util::DRaMOp& dramOp) const
{
    util::print_example_banner("Batch PBS for " + dramOp.getFileSuffix());
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // 1. LT
    seal::Plaintext ptxt_b; 
    initial_b(input_vec_lwe, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    initial_A(input_vec_lwe, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);

    // DEBUG
    // for(int i=0; i<128; i++){
    //     std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
    //     // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // 2. BSGS for Polynomial Evaluation
    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    // seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    seal::util::test_customize_poly(seal::RLWEParams::plain_modulus, dramOp);
    // Specify the path
    // std::string path = "PolyGenerator/poly/"; 
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(seal::RLWEParams::plain_modulus) + "_" + dramOp.getFileSuffix() + ".txt";
    // A vector to hold the coefficients
    seal::VecData coefficients;
    // Check if the file exists
    time_start = std::chrono::high_resolution_clock::now();
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        std::cout << "File not exist!" << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Poly Initialize Done [" << time_diff.count() << " microseconds]" << std::endl;
    std::cout <<  "size of coeff: " << coefficients.size() << std::endl;

    // compute expected result

    double expected_result = dramOp(m_b_as[index], seal::RLWEParams::plain_modulus); 
    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Poly input is: " << m_b_as[index] << " Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // 3. KeySwitch
    // Improvement: Perform KeySwitch
    generate_rlwe_switchkeys();
    // generate_rlwe_switchkeys_arbitary();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    // rlwekeyswitch_arbitary(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;

    // 4. S2C and Extract
    std::vector<seal::LWECipher> vec_lwe;
    S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;

    // 5. ModSwitch
    // std::vector<seal::LWECipher> vec_lwe_ms;
    high4_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(vec_lwe[i], seal::RLWEParamsLittle::plain_modulus, Q, high4_vec_lwe[i]);
    }

    // 6. add 1 to noise
    // output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    // lwe_add_beta(vec_lwe_ms, Q, 1, output_vec_lwe, false);

    // DEBUG
    // uint64_t ms_result = 0; // Modswitch decryption result
    // lwe_manual_decrypt(high4_vec_lwe[index], ms_result, true, Q, seal::RLWEParamsLittle::plain_modulus);
    // // std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
    // std::cout << "Scale up result: " << ms_result << " in binary: ";
    // util::printInBinary(ms_result);

    return;
}

void Cryptor::KeyAddition(const uint64_t &Q, std::vector<LWECipher> &state_vec_lwe, const std::vector<LWECipher> &key_vec_lwe) const
{
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    uint64_t message_debug = 0;

    // function to extract low 4bit
    auto dram_L4 = [](int x, int t) -> int {
        size_t bias = 7;
        uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.
        uint8_t result = 0;
        result |= ((down_x >> 6) & 0x01) << 6; // Extract x7 and place at x6
        result |= ((down_x >> 4) & 0x01) << 4; // Extract x5 and place at x4
        result |= ((down_x >> 2) & 0x01) << 2; // Extract x3 and place at x2
        result |= ((down_x) & 0x01);        // Extract x1 and place at x0
        return result << bias;
    };
    seal::util::DRaMOp dramOp_L4(dram_L4, "L4");
    auto dram_LXOR = [](int x, int t) -> int {
        size_t bias = 7;
        uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.
        uint8_t result = 0;
        // Process each pair of bits and combine them into the result.
        result |= seal::util::process_low_pair((down_x >> 6) & 0x03) << 6; // Process x7x6 and place at x7x6
        result |= seal::util::process_low_pair((down_x >> 4) & 0x03) << 4; // Process x5x4 and place at x5x4
        result |= seal::util::process_low_pair((down_x >> 2) & 0x03) << 2; // Process x3x2 and place at x3x2
        result |= seal::util::process_low_pair(down_x & 0x03);              // Process x1x0 and place at x1x0
        return result << bias;
    };
    seal::util::DRaMOp dramOp_LXOR(dram_LXOR, "Low_XOR");
    auto dram_HXOR9bit = [](int x, int t) -> int {
        size_t bias = 7;
        uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.
        
        uint8_t result = 0;
        // Process each pair of bits and combine them into the result.
        result |= seal::util::process_high_pair((down_x >> 7) & 0x03) << 6; // Process x7x6 and place at x7x6
        result |= seal::util::process_high_pair((down_x >> 5) & 0x03) << 4; // Process x5x4 and place at x5x4
        result |= seal::util::process_high_pair((down_x >> 3) & 0x03) << 2; // Process x3x2 and place at x3x2
        result |= seal::util::process_high_pair((down_x >> 1) & 0x03) << 1; // Process x1x0 and place at x1x0
        return result << bias;
    };
    seal::util::DRaMOp dramOp_HXOR9bit(dram_HXOR9bit, "High_XOR_9bit");
    
    
    // 1. Extract high and low 4 bit
    
    // c1 low four bit 0_X6_0_X4_0_X2_0_X0
    std::vector<seal::LWECipher> c1_l4_vec_lwe;
    Batch_Customize(Q, state_vec_lwe, c1_l4_vec_lwe, dramOp_L4);
    // cryptor.Batch_ExtractLow4bit(Q, c1_vec_lwe, c1_l4_vec_lwe);
    // c1 high four bit X7_0_X5_0_X3_0_X1_0 using lwe substract
    std::vector<seal::LWECipher> c1_h4_vec_lwe;
    lwe_sub(state_vec_lwe, c1_l4_vec_lwe, Q, c1_h4_vec_lwe);
    // DEBUG
    lwe_manual_decrypt(c1_h4_vec_lwe[index], message_debug, true, Q, 65537);
    
    // c2 low four bit 0_X6_0_X4_0_X2_0_X0
    std::vector<seal::LWECipher> c2_l4_vec_lwe;
    Batch_Customize(Q, key_vec_lwe, c2_l4_vec_lwe, dramOp_L4);
    // cryptor.Batch_ExtractLow4bit(Q, c2_vec_lwe, c2_l4_vec_lwe);
    // c1 high four bit X7_0_X5_0_X3_0_X1_0 using lwe substract
    std::vector<seal::LWECipher> c2_h4_vec_lwe;
    lwe_sub(key_vec_lwe, c2_l4_vec_lwe, Q, c2_h4_vec_lwe);
    // DEBUG
    lwe_manual_decrypt(c2_h4_vec_lwe[index], message_debug, true, Q, 65537);
    
    // 2. XOR( LOW(C1) + LOW(C2) )
    std::vector<seal::LWECipher> add_l4_vec_lwe;
    lwe_add(c1_l4_vec_lwe, c2_l4_vec_lwe, Q, add_l4_vec_lwe);
    lwe_manual_decrypt(add_l4_vec_lwe[index], message_debug, true, Q, 65537);
    std::vector<seal::LWECipher> xor_l4_vec_lwe;
    Batch_Customize(Q, add_l4_vec_lwe, xor_l4_vec_lwe, dramOp_LXOR);
    // cryptor.Batch_LowXOR(Q, add_l4_vec_lwe, xor_l4_vec_lwe);
    
    // 3. XOR( HIGH(C1) + HIGH(C2) )
    std::vector<seal::LWECipher> add_h4_vec_lwe;
    lwe_add(c1_h4_vec_lwe, c2_h4_vec_lwe, Q, add_h4_vec_lwe);
    lwe_manual_decrypt(add_h4_vec_lwe[index], message_debug, true, Q, 65537);
    std::vector<seal::LWECipher> xor_h4_vec_lwe;
    Batch_Customize(Q, add_h4_vec_lwe, xor_h4_vec_lwe, dramOp_HXOR9bit);
    // cryptor.Batch_HighXOR9bit(Q, add_h4_vec_lwe, xor_h4_vec_lwe);

    // 4. XOR( LOW4(a) + LOW4(b) ) + XOR( HIGH4(a) + HIGH4(b) )
    std::vector<seal::LWECipher> final_vec_lwe;
    lwe_add(xor_h4_vec_lwe, xor_l4_vec_lwe, Q, final_vec_lwe);
    // cryptor.lwe_add_beta(xor_h4_vec_lwe, Q, 80, final_vec_lwe); // forbide round zero problem
    // lwe_manual_decrypt(final_vec_lwe[index], message_debug, true, Q, 65537);

    lwe_copy(final_vec_lwe, state_vec_lwe);

    // std::cout << "Golden: " << (message1 ^ message2) * Delta << std::endl;
    return;
}

void Cryptor::SubBytes(const uint64_t &Q, std::vector<LWECipher> &state_vec_lwe) const
{
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    uint64_t message_debug = 0;

    
    // function to extract low 4bit
    auto dram_SubBytes = [](int x, int t) -> int {
        size_t bias = 7;
        uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.
        uint8_t result = 0;
        uint8_t row = (down_x >> 4) & 0x0F; // Most significant 4 bits for row
        uint8_t col = down_x & 0x0F;        // Least significant 4 bits for column
        return inverse_sbox[row][col] << bias;
    };
    seal::util::DRaMOp dramOp_SubBytes(dram_SubBytes, "SubBytes");

    // 1. Extract high and low 4 bit
    
    // c1 low four bit 0_X6_0_X4_0_X2_0_X0
    std::vector<seal::LWECipher> c1_l4_vec_lwe;
    Batch_Customize(Q, state_vec_lwe, c1_l4_vec_lwe, dramOp_SubBytes);
    lwe_copy(c1_l4_vec_lwe, state_vec_lwe);
    // DEBUG
    // if(lwe_dec) lwe_manual_decrypt(state_vec_lwe[index], message_debug, true, Q, 65537);

    // std::cout << "Golden: " << (message1 ^ message2) * Delta << std::endl;
    return;
}

void Cryptor::ShiftRows(const uint64_t &Q, std::vector<LWECipher> &state_vec_lwe) const
{
    size_t N = seal::RLWEParams::poly_modulus_degree;
    size_t pack_amount = N / 16;
    std::vector<LWECipher> temp_vec_lwe;
    temp_vec_lwe.resize(N);
    lwe_copy(state_vec_lwe, temp_vec_lwe);

    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<pack_amount; i++){
        state_vec_lwe[i*16+4]  = temp_vec_lwe[i*16+7];  state_vec_lwe[i*16+5]  = temp_vec_lwe[i*16+4];   state_vec_lwe[i*16+6]  = temp_vec_lwe[i*16+5];  state_vec_lwe[i*16+7]  = temp_vec_lwe[i*16+6];
        state_vec_lwe[i*16+8]  = temp_vec_lwe[i*16+10]; state_vec_lwe[i*16+9]  = temp_vec_lwe[i*16+11];  state_vec_lwe[i*16+10] = temp_vec_lwe[i*16+8];  state_vec_lwe[i*16+11] = temp_vec_lwe[i*16+9];
        state_vec_lwe[i*16+12] = temp_vec_lwe[i*16+13]; state_vec_lwe[i*16+13] = temp_vec_lwe[i*16+14];  state_vec_lwe[i*16+14] = temp_vec_lwe[i*16+15]; state_vec_lwe[i*16+15] = temp_vec_lwe[i*16+12];
    }

    return;
}

void Cryptor::MixColum(const uint64_t &Q, std::vector<LWECipher> &state_vec_lwe) const
{
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    uint64_t message_debug = 0;

    // Get Mixcolum plaintext lwe(we just simply generate it)
    std::vector<seal::LWECipher> mixcolum_vec_lwe;
    construct_lwe_XOR(12800, Q, mixcolum_vec_lwe);

    // function to extract low 4bit
    auto dram_SubBytes = [](int x, int t) -> int {
        size_t bias = 7;
        uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.
        uint8_t result = 0;
        uint8_t row = (down_x >> 4) & 0x0F; // Most significant 4 bits for row
        uint8_t col = down_x & 0x0F;        // Least significant 4 bits for column
        return inverse_sbox[row][col] << bias;
    };
    seal::util::DRaMOp dramOp_SubBytes(dram_SubBytes, "SubBytes");

    // 1. Extract high and low 4 bit
    
    // c1 low four bit 0_X6_0_X4_0_X2_0_X0
    std::vector<seal::LWECipher> c1_l4_vec_lwe;
    Batch_Customize(Q, state_vec_lwe, c1_l4_vec_lwe, dramOp_SubBytes);
    lwe_copy(c1_l4_vec_lwe, state_vec_lwe);
    // DEBUG
    // if(lwe_dec) lwe_manual_decrypt(state_vec_lwe[index], message_debug, true, Q, 65537);

    // std::cout << "Golden: " << (message1 ^ message2) * Delta << std::endl;
    return;
}

void Cryptor::Batch_ExtractHigh4bit(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe) const
{
    util::print_example_banner("Batch PBS for High 4bit Extraction");
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // 1. LT
    seal::Plaintext ptxt_b; 
    initial_b(input_vec_lwe, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    initial_A(input_vec_lwe, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);

    // DEBUG
    // for(int i=0; i<128; i++){
    //     std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
    //     // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // 2. BSGS for Polynomial Evaluation
    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    // seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    seal::util::test_H4_poly(seal::RLWEParams::plain_modulus);
    // Specify the path
    // std::string path = "PolyGenerator/poly/"; 
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(seal::RLWEParams::plain_modulus) + "_H4_Poly.txt";
    // A vector to hold the coefficients
    seal::VecData coefficients;
    // Check if the file exists
    time_start = std::chrono::high_resolution_clock::now();
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        std::cout << "File not exist!" << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Poly Initialize Done [" << time_diff.count() << " microseconds]" << std::endl;
    std::cout <<  "size of coeff: " << coefficients.size() << std::endl;

    // compute expected result

    double expected_result = seal::util::DRaM_H4(m_b_as[index], seal::RLWEParams::plain_modulus); 
    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Poly input is: " << m_b_as[index] << " Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // 3. KeySwitch
    // Improvement: Perform KeySwitch
    generate_rlwe_switchkeys();
    // generate_rlwe_switchkeys_arbitary();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    // rlwekeyswitch_arbitary(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;


    // 4. S2C and Extract
    std::vector<seal::LWECipher> vec_lwe;
    S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;


    // 5. ModSwitch
    // std::vector<seal::LWECipher> vec_lwe_ms;
    high4_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(vec_lwe[i], seal::RLWEParamsLittle::plain_modulus, Q, high4_vec_lwe[i]);
    }

    uint64_t message_debug = 0;
    if(lwe_dec) lwe_manual_decrypt(high4_vec_lwe[index], message_debug, true, Q, 65537);

    // 6. add 1 to noise
    // output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    // lwe_add_beta(vec_lwe_ms, Q, 1, output_vec_lwe, false);

    // DEBUG
    // uint64_t ms_result = 0; // Modswitch decryption result
    // lwe_manual_decrypt(high4_vec_lwe[index], ms_result, true, Q, seal::RLWEParamsLittle::plain_modulus);
    // // std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
    // std::cout << "Scale up result: " << ms_result << " in binary: ";
    // util::printInBinary(ms_result);

    return;
}

void Cryptor::Batch_ExtractLow4bit(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe) const
{
    util::print_example_banner("Batch PBS for Low 4bit Extraction");
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // 1. LT
    seal::Plaintext ptxt_b; 
    initial_b(input_vec_lwe, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    initial_A(input_vec_lwe, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);

    // DEBUG
    // for(int i=0; i<128; i++){
    //     std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
    //     // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // 2. BSGS for Polynomial Evaluation
    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    // seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    seal::util::test_L4_poly(seal::RLWEParams::plain_modulus);
    // Specify the path
    // std::string path = "PolyGenerator/poly/"; 
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(seal::RLWEParams::plain_modulus) + "_L4_Poly.txt";
    // A vector to hold the coefficients
    seal::VecData coefficients;
    // Check if the file exists
    time_start = std::chrono::high_resolution_clock::now();
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        std::cout << "File not exist!" << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Poly Initialize Done [" << time_diff.count() << " microseconds]" << std::endl;
    std::cout <<  "size of coeff: " << coefficients.size() << std::endl;

    // compute expected result

    double expected_result = seal::util::DRaM_L4(m_b_as[index], seal::RLWEParams::plain_modulus); 
    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Poly input is: " << m_b_as[index] << " Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // 3. KeySwitch
    // Improvement: Perform KeySwitch
    generate_rlwe_switchkeys();
    // generate_rlwe_switchkeys_arbitary();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    // rlwekeyswitch_arbitary(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;


    // 4. S2C and Extract
    std::vector<seal::LWECipher> vec_lwe;
    S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;


    // 5. ModSwitch
    // std::vector<seal::LWECipher> vec_lwe_ms;
    high4_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(vec_lwe[i], seal::RLWEParamsLittle::plain_modulus, Q, high4_vec_lwe[i]);
    }

    uint64_t message_debug = 0;
    if(lwe_dec)
        lwe_manual_decrypt(high4_vec_lwe[index], message_debug, true, Q, 65537);

    // 6. add 1 to noise
    // output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    // lwe_add_beta(vec_lwe_ms, Q, 1, output_vec_lwe, false);

    // DEBUG
    // uint64_t ms_result = 0; // Modswitch decryption result
    // lwe_manual_decrypt(high4_vec_lwe[index], ms_result, true, Q, seal::RLWEParamsLittle::plain_modulus);
    // // std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
    // std::cout << "Scale up result: " << ms_result << " in binary: ";
    // util::printInBinary(ms_result);

    return;
}

void Cryptor::Batch_HighXOR(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe) const
{
    util::print_example_banner("Batch PBS for XOR High 4bit Extraction");
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // 1. LT
    seal::Plaintext ptxt_b; 
    initial_b(input_vec_lwe, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    initial_A(input_vec_lwe, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);

    // DEBUG
    // for(int i=0; i<128; i++){
    //     std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
    //     // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // 2. BSGS for Polynomial Evaluation
    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    // seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    seal::util::test_highxor_poly(seal::RLWEParams::plain_modulus);
    // Specify the path
    // std::string path = "PolyGenerator/poly/"; 
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(seal::RLWEParams::plain_modulus) + "_highxor_Poly.txt";
    // A vector to hold the coefficients
    seal::VecData coefficients;
    // Check if the file exists
    time_start = std::chrono::high_resolution_clock::now();
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        std::cout << "File not exist!" << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Poly Initialize Done [" << time_diff.count() << " microseconds]" << std::endl;
    std::cout <<  "size of coeff: " << coefficients.size() << std::endl;

    // compute expected result

    double expected_result = seal::util::DRaM_highxor(m_b_as[index], seal::RLWEParams::plain_modulus); 
    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Poly input is: " << m_b_as[index] << " Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // 3. KeySwitch
    // Improvement: Perform KeySwitch
    generate_rlwe_switchkeys();
    // generate_rlwe_switchkeys_arbitary();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    // rlwekeyswitch_arbitary(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;


    // 4. S2C and Extract
    std::vector<seal::LWECipher> vec_lwe;
    S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;


    // 5. ModSwitch
    // std::vector<seal::LWECipher> vec_lwe_ms;
    high4_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(vec_lwe[i], seal::RLWEParamsLittle::plain_modulus, Q, high4_vec_lwe[i]);
    }

    uint64_t message_debug = 0;
    if(lwe_dec)
        lwe_manual_decrypt(high4_vec_lwe[index], message_debug, true, Q, 65537);

    // 6. add 1 to noise
    // output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    // lwe_add_beta(vec_lwe_ms, Q, 1, output_vec_lwe, false);

    // DEBUG
    // uint64_t ms_result = 0; // Modswitch decryption result
    // lwe_manual_decrypt(high4_vec_lwe[index], ms_result, true, Q, seal::RLWEParamsLittle::plain_modulus);
    // // std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
    // std::cout << "Scale up result: " << ms_result << " in binary: ";
    // util::printInBinary(ms_result);

    return;
}

void Cryptor::Batch_HighXOR9bit(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe) const
{
    util::print_example_banner("Batch PBS for XOR High 4bit Extraction");
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // 1. LT
    seal::Plaintext ptxt_b; 
    initial_b(input_vec_lwe, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    initial_A(input_vec_lwe, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);

    // DEBUG
    // for(int i=0; i<128; i++){
    //     std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
    //     // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // 2. BSGS for Polynomial Evaluation
    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    // seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    seal::util::test_highxor9bit_poly(seal::RLWEParams::plain_modulus);
    // Specify the path
    // std::string path = "PolyGenerator/poly/"; 
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(seal::RLWEParams::plain_modulus) + "_highxor9bit_Poly.txt";
    // A vector to hold the coefficients
    seal::VecData coefficients;
    // Check if the file exists
    time_start = std::chrono::high_resolution_clock::now();
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        std::cout << "File not exist!" << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Poly Initialize Done [" << time_diff.count() << " microseconds]" << std::endl;
    std::cout <<  "size of coeff: " << coefficients.size() << std::endl;

    // compute expected result

    double expected_result = seal::util::DRaM_highxor9bit(m_b_as[index], seal::RLWEParams::plain_modulus); 
    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Poly input is: " << m_b_as[index] << " Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // 3. KeySwitch
    // Improvement: Perform KeySwitch
    generate_rlwe_switchkeys();
    // generate_rlwe_switchkeys_arbitary();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    // rlwekeyswitch_arbitary(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;


    // 4. S2C and Extract
    std::vector<seal::LWECipher> vec_lwe;
    S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;


    // 5. ModSwitch
    // std::vector<seal::LWECipher> vec_lwe_ms;
    high4_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(vec_lwe[i], seal::RLWEParamsLittle::plain_modulus, Q, high4_vec_lwe[i]);
    }

    uint64_t message_debug = 0;
    if(lwe_dec)
        lwe_manual_decrypt(high4_vec_lwe[index], message_debug, true, Q, 65537);

    // 6. add 1 to noise
    // output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    // lwe_add_beta(vec_lwe_ms, Q, 1, output_vec_lwe, false);

    // DEBUG
    // uint64_t ms_result = 0; // Modswitch decryption result
    // lwe_manual_decrypt(high4_vec_lwe[index], ms_result, true, Q, seal::RLWEParamsLittle::plain_modulus);
    // // std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
    // std::cout << "Scale up result: " << ms_result << " in binary: ";
    // util::printInBinary(ms_result);

    return;
}

void Cryptor::Batch_LowXOR(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &high4_vec_lwe) const
{
    util::print_example_banner("Batch PBS for XOR Low 4bit Extraction");
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // 1. LT
    seal::Plaintext ptxt_b; 
    initial_b(input_vec_lwe, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    initial_A(input_vec_lwe, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);

    // DEBUG
    // for(int i=0; i<128; i++){
    //     std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
    //     // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // 2. BSGS for Polynomial Evaluation
    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    // seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    seal::util::test_lowxor_poly(seal::RLWEParams::plain_modulus);
    // Specify the path
    // std::string path = "PolyGenerator/poly/"; 
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(seal::RLWEParams::plain_modulus) + "_lowxor_Poly.txt";
    // A vector to hold the coefficients
    seal::VecData coefficients;
    // Check if the file exists
    time_start = std::chrono::high_resolution_clock::now();
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        std::cout << "File not exist!" << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Poly Initialize Done [" << time_diff.count() << " microseconds]" << std::endl;
    std::cout <<  "size of coeff: " << coefficients.size() << std::endl;

    // compute expected result

    double expected_result = seal::util::DRaM_lowxor(m_b_as[index], seal::RLWEParams::plain_modulus); 
    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Poly input is: " << m_b_as[index] << " Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // 3. KeySwitch
    // Improvement: Perform KeySwitch
    generate_rlwe_switchkeys();
    // generate_rlwe_switchkeys_arbitary();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    // rlwekeyswitch_arbitary(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;


    // 4. S2C and Extract
    std::vector<seal::LWECipher> vec_lwe;
    S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;


    // 5. ModSwitch
    // std::vector<seal::LWECipher> vec_lwe_ms;
    high4_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(vec_lwe[i], seal::RLWEParamsLittle::plain_modulus, Q, high4_vec_lwe[i]);
    }

    uint64_t message_debug = 0;
    if(lwe_dec)
        lwe_manual_decrypt(high4_vec_lwe[index], message_debug, true, Q, 65537);

    // 6. add 1 to noise
    // output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    // lwe_add_beta(vec_lwe_ms, Q, 1, output_vec_lwe, false);

    // DEBUG
    // uint64_t ms_result = 0; // Modswitch decryption result
    // lwe_manual_decrypt(high4_vec_lwe[index], ms_result, true, Q, seal::RLWEParamsLittle::plain_modulus);
    // // std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
    // std::cout << "Scale up result: " << ms_result << " in binary: ";
    // util::printInBinary(ms_result);

    return;
}

void Cryptor::Batch_sign(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe) const
{
    util::print_example_banner("Batch PBS for Sign Extract");
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // 1. LT
    seal::Plaintext ptxt_b; 
    initial_b(input_vec_lwe, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    initial_A(input_vec_lwe, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);

    // DEBUG
    // for(int i=0; i<128; i++){
    //     std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
    //     // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // 2. BSGS for Polynomial Evaluation
    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    // seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    seal::util::test_sign_poly(seal::RLWEParams::plain_modulus, Q);
    // Specify the path
    // std::string path = "PolyGenerator/poly/"; 
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(seal::RLWEParams::plain_modulus) + "_" + std::to_string(Q) + "_sign_Poly.txt";
    // A vector to hold the coefficients
    seal::VecData coefficients;
    // Check if the file exists
    time_start = std::chrono::high_resolution_clock::now();
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        std::cout << "File not exist!" << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Poly Initialize Done [" << time_diff.count() << " microseconds]" << std::endl;
    std::cout <<  "size of coeff: " << coefficients.size() << std::endl;

    // compute expected result

    double expected_result = seal::util::DRaM_sign(m_b_as[index], seal::RLWEParams::plain_modulus, Q); 
    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Poly input is: " << m_b_as[index] << " Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // 3. KeySwitch
    // Improvement: Perform KeySwitch
    generate_rlwe_switchkeys();
    // generate_rlwe_switchkeys_arbitary();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    // rlwekeyswitch_arbitary(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;


    // 4. S2C and Extract
    std::vector<seal::LWECipher> vec_lwe;
    S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;


    // 5. ModSwitch
    // std::vector<seal::LWECipher> vec_lwe_ms;
    output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(vec_lwe[i], seal::RLWEParamsLittle::plain_modulus, Q, output_vec_lwe[i]);
    }

    // 6. add 1 to noise
    // output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    // lwe_add_beta(vec_lwe_ms, Q, 1, output_vec_lwe, false);

    // DEBUG
    // uint64_t ms_result = 0; // Modswitch decryption result
    // lwe_manual_decrypt(output_vec_lwe[index], ms_result, true, Q, seal::RLWEParamsLittle::plain_modulus);
    // // std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
    // std::cout << "Scale up result: " << ms_result << " in binary: ";
    // util::printInBinary(ms_result);

    return;
}

void Cryptor::Batch_f0(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe) const
{
    util::print_example_banner("Batch PBS for f0");
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // 1. LT
    seal::Plaintext ptxt_b; 
    initial_b(input_vec_lwe, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    initial_A(input_vec_lwe, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);

    // DEBUG
    // for(int i=0; i<128; i++){
    //     std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
    //     // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // 2. BSGS for Polynomial Evaluation
    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    // seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    seal::util::test_f0_poly(seal::RLWEParams::plain_modulus, Q);
    // Specify the path
    // std::string path = "PolyGenerator/poly/"; 
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(seal::RLWEParams::plain_modulus) + "_" + std::to_string(Q) + "_f0_Poly.txt";
    // A vector to hold the coefficients
    seal::VecData coefficients;
    // Check if the file exists
    time_start = std::chrono::high_resolution_clock::now();
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        std::cout << "File not exist!" << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Poly Initialize Done [" << time_diff.count() << " microseconds]" << std::endl;
    std::cout <<  "size of coeff: " << coefficients.size() << std::endl;

    // compute expected result

    double expected_result = seal::util::DRaM_f0(m_b_as[index], seal::RLWEParams::plain_modulus, Q); 
    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Poly input is: " << m_b_as[index] << " Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // 3. KeySwitch
    // Improvement: Perform KeySwitch
    generate_rlwe_switchkeys();
    // generate_rlwe_switchkeys_arbitary();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    // rlwekeyswitch_arbitary(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;


    // 4. S2C and Extract
    std::vector<seal::LWECipher> vec_lwe;
    S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;


    // 5. ModSwitch
    seal::LWECipher lwe_ms;
    output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(vec_lwe[i], seal::RLWEParamsLittle::plain_modulus, Q, output_vec_lwe[i]);
    }
    // DEBUG
    // uint64_t ms_result = 0; // Modswitch decryption result
    // lwe_manual_decrypt(output_vec_lwe[index], ms_result, true, Q, seal::RLWEParamsLittle::plain_modulus);
    // // std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
    // std::cout << "Scale up result: " << ms_result << " in binary: ";
    // util::printInBinary(ms_result);

    return;
}

void Cryptor::Batch_f1(const uint64_t &Q, const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe) const
{
    util::print_example_banner("Batch PBS for f1");
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // 1. LT
    seal::Plaintext ptxt_b; 
    initial_b(input_vec_lwe, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    initial_A(input_vec_lwe, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);

    // DEBUG
    // for(int i=0; i<128; i++){
    //     std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
    //     // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // 2. BSGS for Polynomial Evaluation
    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    // seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    seal::util::test_f1_poly(seal::RLWEParams::plain_modulus, Q);
    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(seal::RLWEParams::plain_modulus) + "_" + std::to_string(Q) + "_f1_Poly.txt";
    // A vector to hold the coefficients
    seal::VecData coefficients;
    // Check if the file exists
    time_start = std::chrono::high_resolution_clock::now();
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        std::cout << "File not exist!" << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Poly Initialize Done [" << time_diff.count() << " microseconds]" << std::endl;
    std::cout <<  "size of coeff: " << coefficients.size() << std::endl;

    // compute expected result

    double expected_result = seal::util::DRaM_f1(m_b_as[index], seal::RLWEParams::plain_modulus, Q); 
    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Poly input is: " << m_b_as[index] << " Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // 3. KeySwitch
    // Improvement: Perform KeySwitch
    generate_rlwe_switchkeys();
    // generate_rlwe_switchkeys_arbitary();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    // rlwekeyswitch_arbitary(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;


    // 4. S2C and Extract
    std::vector<seal::LWECipher> vec_lwe;
    S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;


    // 5. ModSwitch
    seal::LWECipher lwe_ms;
    output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(vec_lwe[i], seal::RLWEParamsLittle::plain_modulus, Q, output_vec_lwe[i]);
    }
    // DEBUG
    // uint64_t ms_result = 0; // Modswitch decryption result
    // lwe_manual_decrypt(output_vec_lwe[index], ms_result, true, Q, seal::RLWEParamsLittle::plain_modulus);
    // // std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
    // std::cout << "Scale up result: " << ms_result << " in binary: ";
    // util::printInBinary(ms_result);

    return;
}

void Cryptor::BatchPBS(const std::vector<LWECipher> &input_vec_lwe, std::vector<LWECipher> &output_vec_lwe) const
{
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // 1. LT
    seal::Plaintext ptxt_b; 
    initial_b(input_vec_lwe, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    initial_A(input_vec_lwe, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);

    // DEBUG
    // for(int i=0; i<128; i++){
    //     std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
    //     // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // 2. BSGS for Polynomial Evaluation
    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    // seal::util::test_NAND_poly(383);
    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(seal::RLWEParams::plain_modulus) + "_NAND_Poly.txt";
    // test Liuzeyu 383
    // std::string filename = path + std::to_string(383) + "_NAND_Poly.txt";
    // A vector to hold the coefficients
    seal::VecData coefficients;
    // Check if the file exists
    time_start = std::chrono::high_resolution_clock::now();
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        std::cout << "File not exist!" << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Poly Initialize Done [" << time_diff.count() << " microseconds]" << std::endl;
    std::cout <<  "size of coeff: " << coefficients.size() << std::endl;

    // compute expected result

    double expected_result = seal::util::DRaM_NAND(m_b_as[index], seal::RLWEParams::plain_modulus); 
    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Poly input is: " << m_b_as[index] << " Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // 3. KeySwitch
    // Improvement: Perform KeySwitch
    generate_rlwe_switchkeys();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;


    // 4. S2C and Extract
    std::vector<seal::LWECipher> vec_lwe;
    S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;


    // 5. ModSwitch
    seal::LWECipher lwe_ms;
    output_vec_lwe.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        ModSwitchLWE(vec_lwe[i], seal::RLWEParamsLittle::plain_modulus, seal::RLWEParamsLittle::plain_modulus, output_vec_lwe[i]);
    }
    // DEBUG
    uint64_t ms_result = 0; // Modswitch decryption result
    lwe_manual_decrypt(output_vec_lwe[index], ms_result, true, seal::RLWEParamsLittle::plain_modulus, seal::RLWEParamsLittle::plain_modulus);
    std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
    std::cout << "Scale up result: " << ms_result << std::endl;

    return;
}

void Cryptor::initial_A(const std::vector<LWECipher> &vec_lwe, MatrixData &matrix_A) const
{
    size_t long_poly_degree = RLWEParams::poly_modulus_degree;
    size_t short_poly_degree = RLWEParamsLittle::poly_modulus_degree;
    matrix_A.resize(long_poly_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<long_poly_degree; i++){
        matrix_A[i].resize(short_poly_degree);
        for(int j=0; j<short_poly_degree; j++){
            matrix_A[i][j] = vec_lwe[i][1+j];
        }
    }

    // DEBUG
    // std::cout << "Initial A: " << std::endl;
    // for(int i=0; i<16; i++){
    //     for(int j=0; j<16; j++){
    //         std::cout << matrix_A[i][j] << " ";
    //     }
    //     std::cout << std::endl;
    // }

    return;
}

void Cryptor::initial_b(const std::vector<LWECipher> &vec_lwe, Plaintext &ptxt_b) const
{
    size_t long_poly_degree = RLWEParams::poly_modulus_degree;
    VecData vec_b;
    vec_b.resize(long_poly_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<long_poly_degree; i++){
        vec_b[i] = vec_lwe[i][0];
    }

    // DEBUG
    // std::cout << "initial b: " << std::endl;
    // for(int i=0; i<16; i++){
    //     std::cout << vec_b[i] << " ";
    // }
    // std::cout << std::endl;
    
    encode(vec_b, ptxt_b, ParamSet::RLWE);
    return;
}

void Cryptor::initial_s(Ciphertext &ctxt_seckey) const
{
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();
    uint64_t mod_coef = *vec_mod[0].data();
    uint64_t mod_plain = RLWEParams::plain_modulus;
    size_t long_poly_degree = RLWEParams::poly_modulus_degree;
    size_t short_poly_degree = LWEParams::poly_modulus_degree;
    size_t npoly = long_poly_degree / short_poly_degree;
    SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey, short_poly_degree, *pool_)
    std::copy_n(rlwe_seckey_little_->data().data(), short_poly_degree, (uint64_t *)inv_seckey);
    util::inverse_ntt_negacyclic_harvey(inv_seckey, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
    VecData vec_seckey(long_poly_degree, 0ULL);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<npoly; i++){
        for (int j=0; j<short_poly_degree; j++){
            vec_seckey[j + i*short_poly_degree] = inv_seckey[j];
            if(vec_seckey[j + i*short_poly_degree] == mod_coef-1){
                vec_seckey[j + i*short_poly_degree] = mod_plain - 1;
            }
        }
    }

    // DEBUG
    // std::cout << "initial s: " << std::endl;
    // for(int i=0; i<16; i++){
    //     std::cout << vec_seckey[i] << " ";
    // }
    // std::cout << std::endl;

    encrypt(vec_seckey, ctxt_seckey, ParamSet::RLWE);
    return;
}

void Cryptor::encrypt(const Plaintext &ptxt, RLWECipher &rlwe, const ParamSet paramset) const
{
    std::cout << "global_variables::noise_max_deviation: " << seal::util::global_variables::noise_max_deviation << std::endl;
    std::cout << "global_variables::noise_standard_deviation: " << seal::util::global_variables::noise_standard_deviation << std::endl;
    std::cout << "util::seal_he_std_parms_error_std_dev: " << seal::util::seal_he_std_parms_error_std_dev << std::endl;
    // // According to RLWEParams, there is no use_special_prime, so we directly use the else part
    // rlwe_encryptor_->encrypt_zero_symmetric(rlwe_context_->key_parms_id(), rlwe);
    // util::multiply_add_plain_with_scaling_variant(ptxt, *rlwe_context_->key_context_data(), util::RNSIter(rlwe.data(), RLWEParams::poly_modulus_degree));
    if(paramset == ParamSet::RLWE){
        rlwe_encryptor_->encrypt(ptxt, rlwe);
    }
    else if(paramset == ParamSet::RLWELittle){
        rlwe_encryptor_little_->encrypt(ptxt, rlwe);
    }
    else
        std::cout << "Parameter set must be RLWE or RLWELittle" << std::endl;
    
    return;
}

void Cryptor::encrypt(const VecData &plain, RLWECipher &cipher, const ParamSet paramset) const
{
    if(paramset == ParamSet::RLWE){
        Plaintext ptxt;
        rlwe_batch_encoder_->encode(plain, ptxt);
        // rlwe_evaluator_->mod_switch_to_next_inplace(ptxt);
        rlwe_encryptor_->encrypt(ptxt, cipher);
    }
    else if(paramset == ParamSet::RLWELittle){
        Plaintext ptxt;
        rlwe_batch_encoder_little_->encode(plain, ptxt);
        // rlwe_evaluator_->mod_switch_to_next_inplace(ptxt);
        rlwe_encryptor_little_->encrypt(ptxt, cipher);
    }
    else
        std::cout << "Parameter set must be RLWE or RLWELittle" << std::endl;
    
    return;
}

void Cryptor::encrypt(const util::RNSIter &new_key, KSRLevCipher &rlev) const
{
    size_t coeff_count = rlwe_context_->key_context_data()->parms().poly_modulus_degree();
    size_t decomp_mod_count = rlwe_context_->first_context_data()->parms().coeff_modulus().size();
    auto &key_context_data = *rlwe_context_->key_context_data();
    auto &key_parms = key_context_data.parms();
    auto &key_modulus = key_parms.coeff_modulus();
    // KSwitchKeys data allocated from pool given by MemoryManager::GetPool.
    rlev.resize(decomp_mod_count);
    SEAL_ITERATE(util::iter(new_key, key_modulus, rlev, size_t(0)), decomp_mod_count, [&](auto I) {
        SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, MemoryManager::GetPool());
        util::encrypt_zero_symmetric(
            *rlwe_seckey_, *rlwe_context_, key_context_data.parms_id(), true, false, get<2>(I).data());
        uint64_t factor = util::barrett_reduce_64(key_modulus.back().value(), get<1>(I));
        util::multiply_poly_scalar_coeffmod(get<0>(I), coeff_count, factor, get<1>(I), temp);
        // We use the SeqIter at get<3>(I) to find the i-th RNS factor of the first destination polynomial.
        util::CoeffIter destination_iter = (*util::iter(get<2>(I).data()))[get<3>(I)];
        util::add_poly_coeffmod(destination_iter, temp, coeff_count, get<1>(I), destination_iter);
    });
}

void Cryptor::encrypt(const uint64_t key, KSRGSWCipher &rgsw) const
{
    if (RLWEParams::use_special_prime) {
        rgsw.data().resize(2);
        SecretKey new_key(*rlwe_seckey_);
        auto &coeff_modulus = rlwe_context_->key_context_data()->parms().coeff_modulus();
        util::RNSIter new_key_iter(new_key.data().data(), RLWEParams::poly_modulus_degree);
        util::multiply_poly_scalar_coeffmod(new_key_iter, RLWEParams::coeff_modulus_size, key, coeff_modulus, new_key_iter);
        encrypt(new_key_iter, rgsw.data()[1]);
        // for (size_t i = 0; i < RLWEParams::coeff_modulus_size; i++)
        std::fill_n(new_key.data().data(), RLWEParams::poly_modulus_degree * coeff_modulus.size(), key);
        encrypt(new_key_iter, rgsw.data()[0]);
        return;
    } else {
    }
}

void Cryptor::encrypt(const util::RNSIter &new_key, RLevCipher &rlev, const ParamSet paramset) const
{
    bool islwe = paramset == ParamSet::LWE;
    auto context = islwe ? lwe_context_ : rgsw_context_;
    auto encryptor = islwe ? lwe_encryptor_ : rlwe_encryptor_;
    auto decompose_level = islwe ? LWEParams::decompose_level : RGSWParams::decompose_level;
    auto decompose_log_base = islwe ? LWEParams::decompose_log_base : RGSWParams::decompose_log_base;
    auto lognmod = islwe ? LWEParams::lognmod : RGSWParams::lognmod;
    auto coeff_modulus = context->first_context_data()->parms().coeff_modulus();
    auto coeff_modulus_size = coeff_modulus.size();
    auto poly_modulus_degree = new_key.poly_modulus_degree();
    auto rnstool = islwe ? lwe_rnstool_ : rgsw_rnstool_;
    size_t qlen = context->first_context_data()->total_coeff_modulus_bit_count() + lognmod;
    // size_t qlen = 60;
    uint64_t GadVal[decompose_level][coeff_modulus_size];
    rlev.reserve(decompose_level);
    for (size_t i = 0; i < decompose_level; i++) {
        RLWECipher temp(*context);
        encryptor->encrypt_zero_symmetric(temp);
        util::ntt_negacyclic_harvey(temp, 2, lwe_context_->first_context_data()->small_ntt_tables());
        temp.is_ntt_form() = true;
        rlev.emplace_back(temp);
    }
    for (size_t i = 0; i < decompose_level; i++){
        for (size_t j = 0; j < coeff_modulus_size; j++){
            // std::cout << "qlen - (i + 1) * decompose_log_base: " << qlen - (i + 1) * decompose_log_base << std::endl;
            GadVal[i][j] = util::pow2mod(qlen - (i + 1) * decompose_log_base, coeff_modulus[j]);
            // GadVal[i][j] = seal::util::exponentiate_uint_mod(2, qlen - (i + 1) * decompose_log_base, coeff_modulus[j]);
            // std::cout << "GadVal[i][j]: " << GadVal[i][j] << std::endl;
        }
    }
    SEAL_ALLOCATE_GET_RNS_ITER(scaled_key, poly_modulus_degree, coeff_modulus_size, *pool_)
    uint64_t *new_key_ptr = (uint64_t *)new_key;
    uint64_t *scaled_key_ptr = (uint64_t *)scaled_key;
    for (size_t i = 0; i < decompose_level; i++) {
        for (size_t j = 0; j < coeff_modulus_size; j++)
            util::multiply_poly_scalar_coeffmod(new_key_ptr + j * poly_modulus_degree, poly_modulus_degree, GadVal[i][j], coeff_modulus[j], scaled_key_ptr + j * poly_modulus_degree);
        util::add_poly_coeffmod(scaled_key, util::RNSIter(rlev[i].data(0), poly_modulus_degree), coeff_modulus_size, coeff_modulus, util::RNSIter(rlev[i].data(0), poly_modulus_degree));
    }
}

void Cryptor::encode(const VecData &message, Plaintext &ptxt, ParamSet paramset) const
{
    if(paramset == ParamSet::RLWE){
        rlwe_batch_encoder_->encode(message, ptxt);
    }
    else if(paramset == ParamSet::RLWELittle){
        rlwe_batch_encoder_little_->encode(message, ptxt);
    }
    else
        std::cout << "Parameter set must be RLWE or RLWELittle" << std::endl;
    
    return;
    
}

void Cryptor::encode_manual(const VecData &message, Plaintext &ptxt) const
{
    size_t values_matrix_size = message.size();

    // Generate Transform Matrix Manually
    MatrixData matrix_encode;
    GenEncodeMatrix(matrix_encode);

    // std::cout << "encode matrix is: " << std::endl;
    // for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+2048) {
    //     for (size_t j = 0; j < RLWEParams::poly_modulus_degree; j=j+2048) {
    //         std::cout << matrix_encode[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    std::cout << "encode matrix is: " << std::endl;
    for (size_t i = 0; i < 4; i=i+1) {
        for (size_t j = 0; j < 4; j=j+1) {
            std::cout << matrix_encode[i][j] << " ";
        }
            std::cout << std::endl;
    }

    VecData temp(values_matrix_size, 0);
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        temp[i] = message[i];
    }

    // Matrix-Vector Multiplication
    Modulus mod_plain = rlwe_parms_->plain_modulus();
    VecData encode_result_vector(temp.size(), 0);
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < matrix_encode.size(); i++)
    {
        for (size_t j = 0; j < matrix_encode[i].size(); j++)
        {
            // Multiply the matrix element by the vector element and sum the result
            encode_result_vector[i] = seal::util::add_uint_mod(encode_result_vector[i], 
                            seal::util::multiply_uint_mod(matrix_encode[i][j], temp[j], mod_plain), mod_plain);
        }
    }
    

    // Using SEAL to encode 
    Plaintext ptxt_golden;
    rlwe_batch_encoder_->encode(message, ptxt_golden);

    // Check if ptxt equals to ptxt_golden
    // #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        if (encode_result_vector[i] != ptxt_golden[i])
        {
            std::cout << "Index: " << i << " | ptxt: " << encode_result_vector[i] << " | ptxt_golden: " << ptxt_golden[i] << std::endl;
        }
    }

    std::cout << "encode check done" << std::endl;

    ptxt = ptxt_golden;

    return;

}

void Cryptor::decode(const Plaintext &ptxt, VecData &message, ParamSet paramset) const
{
    
    if(paramset == ParamSet::RLWE){
        rlwe_batch_encoder_->decode(ptxt, message);
    }
    else if(paramset == ParamSet::RLWELittle){
        rlwe_batch_encoder_little_->decode(ptxt, message);
    }
    else
        std::cout << "Parameter set must be RLWE or RLWELittle" << std::endl;
    
    return;
    
}

void Cryptor::decode_manual(const Plaintext &ptxt, VecData &message) const
{
    
    // Generate Transform Matrix Manually
    MatrixData matrix_decode;
    GenDecodeMatrix(matrix_decode);

    std::cout << "decode matrix is: " << std::endl;
    for (size_t i = 0; i < 4; i=i+1) {
        for (size_t j = 0; j < 4; j=j+1) {
            std::cout << matrix_decode[i][j] << " ";
        }
            std::cout << std::endl;
    }

    // std::cout << "decode matrix is: " << std::endl;
    // for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+64) {
    //     for (size_t j = 0; j < RLWEParams::poly_modulus_degree; j=j+64) {
    //         std::cout << matrix_decode[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    size_t values_matrix_size = matrix_decode.size();
    
    
    VecData decode_result_vector(values_matrix_size, 0);
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        for (size_t j = 0; j < matrix_decode[i].size(); j++)
        {
            // Multiply the matrix element by the vector element and sum the result
            // std::cout << "matrix: " << dwt_matrix[i][j] << std::endl;
            decode_result_vector[i] = seal::util::add_uint_mod(decode_result_vector[i], 
                            seal::util::multiply_uint_mod(matrix_decode[i][j], ptxt.data()[j], rlwe_parms_->plain_modulus()), rlwe_parms_->plain_modulus());
        }
    }

    // std::cout << "decode_result_vector is: " << std::endl;
    // for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+1024) {
    //     std::cout << decode_result_vector[i] << " ";
    // }
    // std::cout << std::endl;

    VecData vec_golden;
    rlwe_batch_encoder_->decode(ptxt, vec_golden);

    // Check if ptxt equals to ptxt_golden
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        if (decode_result_vector[i] != vec_golden[i])
        {
            std::cout << "Index: " << i << " | decode_result_vector: " << decode_result_vector[i] << " | vec_golden: " << vec_golden[i] << std::endl;
        }
    }

    std::cout << "decode check done" << std::endl;

    message.resize(values_matrix_size);
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        message[i] = decode_result_vector[i];
    }

    return;
}

void Cryptor::NTT_manual(const Plaintext &ptxt) const
{
    // Encrypt ptxt
    RLWECipher ctxt;
    encrypt(ptxt, ctxt);
    // mod switch to last one
    rlwe_evaluator_->mod_switch_to_inplace(ctxt, rlwe_context_->last_parms_id());

    // generate golden
    RLWECipher ctxt_ntt_golden;
    rlwe_evaluator_->transform_to_ntt(ctxt,ctxt_ntt_golden);

    // Generate Transform Matrix Manually
    MatrixData matrix_NTT;
    GenNttMatrix(matrix_NTT);

    int N = seal::RLWEParams::poly_modulus_degree;
    std::cout << "NTT matrix is: " << std::endl;
    for (size_t i = 0; i < 8; i=i+1) {
        for (size_t j = 0; j < 8; j=j+1) {
            std::cout << matrix_NTT[i][j] << " ";
        }
            std::cout << std::endl;
    }

    // std::cout << "decode matrix is: " << std::endl;
    // for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+64) {
    //     for (size_t j = 0; j < RLWEParams::poly_modulus_degree; j=j+64) {
    //         std::cout << matrix_decode[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    size_t values_matrix_size = matrix_NTT.size();

    // get prime number
    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    
    std::cout << "NTT checking" << std::endl;
    VecData ntt_result_vector(values_matrix_size, 0);

    int check_step = 1;
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < values_matrix_size; i=i+check_step)
    // for (size_t i = 0; i < values_matrix_size; i++)
    {
        for (size_t j = 0; j < matrix_NTT[i].size(); j++)
        {
            // Multiply the matrix element by the vector element and sum the result
            // std::cout << "matrix: " << dwt_matrix[i][j] << std::endl;
            // std::cout << "i: " << i << "j: " << j << std::endl;
            ntt_result_vector[i] = seal::util::add_uint_mod(ntt_result_vector[i], 
                            seal::util::multiply_uint_mod(matrix_NTT[i][j], ctxt.data()[j], *vec_mod[0].data()), *vec_mod[0].data());
        }
    }

    // Check if ptxt equals to ptxt_golden
    // #pragma omp parallel for num_threads(num_th)
    // for (size_t i = 0; i < values_matrix_size; i++)
    for (size_t i = 0; i < values_matrix_size; i=i+check_step)
    {
        if (ntt_result_vector[i] != ctxt_ntt_golden.data()[i])
        {
            std::cout << "Index: " << i << " | ntt_result_vector: " << ntt_result_vector[i] << " | vec_golden: " << ctxt_ntt_golden.data()[i] << std::endl;
        }
    }

    std::cout << "NTT check done" << std::endl;

    // ptxt_ntt.resize(values_matrix_size);
    // for (size_t i = 0; i < values_matrix_size; i++)
    // {
    //     ptxt_ntt.data()[i] = ptxt_golden.data()[i];
    // }

    return;
}

void Cryptor::iNTT_manual(const Plaintext &ptxt) const
{
    // encrypt ptxt
    RLWECipher ctxt;
    encrypt(ptxt, ctxt);

    // Generate Transform Matrix Manually
    MatrixData matrix_iNTT;
    GeniNttMatrix(matrix_iNTT);
    // modswtich to last one
    rlwe_evaluator_->mod_switch_to_inplace(ctxt, rlwe_context_->last_parms_id());

    int N = seal::RLWEParams::poly_modulus_degree;
    std::cout << "iNTT matrix is: " << std::endl;
    for (size_t i = 0; i < 8; i=i+1) {
        for (size_t j = 0; j < 8; j=j+1) {
            std::cout << matrix_iNTT[i][j] << " ";
        }
            std::cout << std::endl;
    }


    size_t values_matrix_size = matrix_iNTT.size();

    RLWECipher ctxt_ntt;
    rlwe_evaluator_->transform_to_ntt(ctxt,ctxt_ntt);
    // decrypt(ctxt_intt, ptxt_intt_golden);

    // get prime number
    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();

    VecData intt_result_vector(values_matrix_size, 0);
    std::cout << "iNTT Checking" << std::endl;

    int check_step = 1;
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < values_matrix_size; i=i+check_step) //just check some position
    // for (size_t i = 0; i < values_matrix_size; i++)
    {
        for (size_t j = 0; j < matrix_iNTT[i].size(); j++)
        {
            // Multiply the matrix element by the vector element and sum the result
            // std::cout << "matrix: " << dwt_matrix[i][j] << std::endl;
            // std::cout << "i: " << i << "j: " << j << std::endl;
            intt_result_vector[i] = seal::util::add_uint_mod(intt_result_vector[i], 
                            seal::util::multiply_uint_mod(matrix_iNTT[i][j], ctxt_ntt.data()[j], *vec_mod[0].data()), *vec_mod[0].data());
        }
    }



    // Check if ptxt equals to ptxt_golden
    // #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < values_matrix_size; i=i+check_step)
    // for (size_t i = 0; i < values_matrix_size; i++)
    {
        if (intt_result_vector[i] != ctxt.data()[i])
        {
            std::cout << "Index: " << i << " | intt result: " << intt_result_vector[i] << " | intt golden: " << ctxt_ntt.data()[i] << std::endl;
        }
    }

    std::cout << "iNTT check done" << std::endl;

    return;
}

void Cryptor::NTT_manual_trans(const VecData &poly, VecData &result) const
{   

    Modulus mod = get_first_modulus();

    result.resize(RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<RLWEParams::poly_modulus_degree; i++){
        result[i] = 0;
    }
    MatrixData matrix_ntt;
    GenNTTMatrixManual(matrix_ntt);
    int step=4;
    std::cout << "NTT Manual Matrix is" << std::endl;
    for (int i=0; i<step; i++){
        for (int j=0; j<step; j++){
            std::cout << matrix_ntt[i][j] << " ";
        }
        std::cout << std::endl;
    }

    int check_step = 1;
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+check_step)
    {
        for (size_t j = 0; j < matrix_ntt[i].size(); j++)
        {
            result[i] = seal::util::add_uint_mod(result[i], 
                            seal::util::multiply_uint_mod(matrix_ntt[i][j], poly.data()[j], mod), mod);
        }
    }

    return;
}

void Cryptor::iNTT_manual_trans(const VecData &poly, VecData &result) const
{

    Modulus mod = get_first_modulus();

    result.resize(RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<RLWEParams::poly_modulus_degree; i++){
        result[i] = 0;
    }
    MatrixData matrix_intt;
    GeniNTTMatrixManual(matrix_intt);
    int step=4;
    std::cout << "iNTT Manual Matrix is" << std::endl;
    for (int i=0; i<step; i++){
        for (int j=0; j<step; j++){
            std::cout << matrix_intt[i][j] << " ";
        }
        std::cout << std::endl;
    }
    int check_step = 1;
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+check_step)
    {
        for (size_t j = 0; j < matrix_intt[i].size(); j++)
        {
            result[i] = seal::util::add_uint_mod(result[i], 
                            seal::util::multiply_uint_mod(matrix_intt[i][j], poly.data()[j], mod), mod);
        }
    }

    return;
}

void Cryptor::NTT_manual_seal(const VecData &poly, VecData &result) const
{
    Modulus mod = get_first_modulus();

    result.resize(RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<RLWEParams::poly_modulus_degree; i++){
        result[i] = 0;
    }
    MatrixData matrix_ntt;
    GenNttMatrix(matrix_ntt);
    int check_step = 1;
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+check_step)
    {
        for (size_t j = 0; j < matrix_ntt[i].size(); j++)
        {
            result[i] = seal::util::add_uint_mod(result[i], 
                            seal::util::multiply_uint_mod(matrix_ntt[i][j], poly.data()[j], mod), mod);
        }
    }

    return;
}

void Cryptor::iNTT_manual_seal(const VecData &poly, VecData &result) const
{

    Modulus mod = get_first_modulus();


    result.resize(RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<RLWEParams::poly_modulus_degree; i++){
        result[i] = 0;
    }
    MatrixData matrix_intt;
    GeniNttMatrix(matrix_intt);
    int check_step = 1;
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+check_step)
    {
        for (size_t j = 0; j < matrix_intt[i].size(); j++)
        {
            result[i] = seal::util::add_uint_mod(result[i], 
                            seal::util::multiply_uint_mod(matrix_intt[i][j], poly.data()[j], mod), mod);
        }
    }

    return;
}

void Cryptor::doubleNTT_manual(const Plaintext &ptxt) const{

    // encrypt ptxt
    RLWECipher ctxt;
    encrypt(ptxt, ctxt);

    // Generate Transform Matrix Manually
    MatrixData matrix_iNTT, matrix_NTT;
    GeniNttMatrix(matrix_iNTT);
    // GenNttMatrix(matrix_NTT);
    GenNTTMatrixManual(matrix_NTT);
    // modswtich to last one
    rlwe_evaluator_->mod_switch_to_inplace(ctxt, rlwe_context_->last_parms_id());

    int N = seal::RLWEParams::poly_modulus_degree;

    size_t values_matrix_size = matrix_iNTT.size();

    // get prime number
    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();

    VecData ntt_result_vector(values_matrix_size, 0);
    std::cout << "Doing NTT" << std::endl;

    int check_step = 1;
    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < values_matrix_size; i=i+check_step) //just check some position
    // for (size_t i = 0; i < values_matrix_size; i++)
    {
        for (size_t j = 0; j < matrix_iNTT[i].size(); j++)
        {
            // Multiply the matrix element by the vector element and sum the result
            // std::cout << "matrix: " << dwt_matrix[i][j] << std::endl;
            // std::cout << "i: " << i << "j: " << j << std::endl;
            ntt_result_vector[i] = seal::util::add_uint_mod(ntt_result_vector[i], 
                            seal::util::multiply_uint_mod(matrix_NTT[i][j], ctxt.data()[j], *vec_mod[0].data()), *vec_mod[0].data());
        }
    }

    VecData intt_result_vector(values_matrix_size, 0);
    std::cout << "Doing iNTT" << std::endl;

    #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < values_matrix_size; i=i+check_step) //just check some position
    // for (size_t i = 0; i < values_matrix_size; i++)
    {
        for (size_t j = 0; j < matrix_iNTT[i].size(); j++)
        {
            // Multiply the matrix element by the vector element and sum the result
            // std::cout << "matrix: " << dwt_matrix[i][j] << std::endl;
            // std::cout << "i: " << i << "j: " << j << std::endl;
            intt_result_vector[i] = seal::util::add_uint_mod(intt_result_vector[i], 
                            seal::util::multiply_uint_mod(matrix_iNTT[i][j], ntt_result_vector[j], *vec_mod[0].data()), *vec_mod[0].data());
        }
    }

    std::cout << "Checking result" << std::endl;

    // Check if ptxt equals to ptxt_golden
    // #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < values_matrix_size; i=i+check_step)
    // for (size_t i = 0; i < values_matrix_size; i++)
    {
        if ((intt_result_vector[i] != ctxt.data()[i]))
        {
            std::cout << "Index: " << i << " | intt result: " << intt_result_vector[i] << " | intt golden: " << ctxt.data()[i] << std::endl;
        }
    }

    std::cout << "double NTT check done" << std::endl;

    return;
}

void Cryptor::decrypt(const RLWECipher &rlwe, Plaintext &ptxt, ParamSet paramset) const
{
    
    if(paramset == ParamSet::RLWE){
        rlwe_decryptor_->decrypt(rlwe, ptxt);
    }
    else if(paramset == ParamSet::RLWELittle){
        rlwe_decryptor_little_->decrypt(rlwe, ptxt);
    }
    else
        std::cout << "Parameter set must be RLWE or RLWELittle" << std::endl;
    
    return;
}

void Cryptor::decrypt(const RLWECipher &cipher, VecData &plain, ParamSet paramset) const
{

    if(paramset == ParamSet::RLWE){
        Plaintext ptxt;
        rlwe_decryptor_->decrypt(cipher, ptxt);
        rlwe_batch_encoder_->decode(ptxt, plain);
    }
    else if(paramset == ParamSet::RLWELittle){
        Plaintext ptxt;
        rlwe_decryptor_little_->decrypt(cipher, ptxt);
        rlwe_batch_encoder_little_->decode(ptxt, plain);
    }
    else
        std::cout << "Parameter set must be RLWE or RLWELittle" << std::endl;
    
    return;

    
}

uint64_t Cryptor::decrypt(const LWECipher &lwe, const ParamSet paramset) const
{
    if (paramset == ParamSet::RLWE){
        Plaintext plain(rlwe_parms_->poly_modulus_degree());
        RLWECipher rlwe(*rlwe_context_);
        LWEtoRLWE(lwe, rlwe);
        rlwe_decryptor_->decrypt(rlwe, plain);
        return plain.data()[0];
    }
    else if(paramset == ParamSet::LWE){
        Plaintext plain(lwe_parms_->poly_modulus_degree());
        RLWECipher rlwe(*lwe_context_);
        LWEtoRLWE(lwe, rlwe);
        // DEBUG: invalid encryption for parameter
        // std::cout << "Condition 1: " << seal::is_data_valid_for(rlwe, *lwe_context_) << std::endl;
        // std::cout << "Condition 2: " << seal::is_metadata_valid_for(rlwe, *lwe_context_) << std::endl;
        // // Check the data
        // auto context_data_ptr = lwe_context_->get_context_data(rlwe.parms_id());
        // const auto &coeff_modulus = context_data_ptr->parms().coeff_modulus();
        // size_t coeff_modulus_size = coeff_modulus.size();
        // const Ciphertext::ct_coeff_type *ptr = rlwe.data();
        // auto size = rlwe.size();
        // for (size_t i = 0; i < size; i++)
        // {
        //     for (size_t j = 0; j < coeff_modulus_size; j++)
        //     {
        //         uint64_t modulus = coeff_modulus[j].value();
        //         auto poly_modulus_degree = rlwe.poly_modulus_degree();
        //         for (; poly_modulus_degree--; ptr++)
        //         {
        //             if (*ptr >= modulus)
        //             {
        //                 std::cout << "i: " << i << " j: " << j << std::endl;
        //                 std::cout << "*ptr: " << *ptr << std::endl;
        //                 std::cout << "modulus: " << modulus << std::endl;
        //             }
        //         }
        //     }
        // }

        lwe_decryptor_->decrypt(rlwe, plain);
        return plain.data()[0];
    }
    else if(paramset == ParamSet::RLWELittle){
        Plaintext plain(rlwe_parms_little_->poly_modulus_degree());
        RLWECipher rlwe(*rlwe_context_little_);
        LWEtoRLWE(lwe, rlwe);
        rlwe_decryptor_little_->decrypt(rlwe, plain);
        return plain.data()[0];
    }
    else{
        std::cout << "Should be RLWE or LWE" << std::endl;
        return 0;
    }
}

void Cryptor::lwe_manual_decrypt(const LWECipher &lwe, uint64_t &result, const bool &have_modswitched, uint64_t new_mod, uint64_t new_plain) const
{
    std::cout << "--------------------" << std::endl;
    std::cout << "DEBUG: Doing Mannual Decryption" << std::endl;
    // Warning: now restrict to LWE from RLWELittle -> Extract LWE
    size_t n = RLWEParamsLittle::poly_modulus_degree;
    size_t print_length = 4;
    size_t degree_count = util::get_power_of_two(n);
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();    
    // std::cout << "LWE Modulus: " << *vec_mod[0].data() << std::endl;
    Modulus mod_plain(0);
    Modulus mod_coeff(0);
    if(have_modswitched){
        mod_plain = new_plain;
        mod_coeff = new_mod;
    }
    else{
        mod_plain = RLWEParamsLittle::plain_modulus;
        mod_coeff = *vec_mod[0].data();
    }
    
    uint64_t lwe_b = lwe[0];
    VecData lwe_a(n, 0ULL);
    // std::cout << "lwe[n]: " << lwe[n] << std::endl;
    for(int i=1; i<n+1; i++){
        lwe_a[i-1] = lwe[i];
    }
    // std::cout << "lwe-b: " << lwe_b << std::endl; 
    // for (int i=n-print_length; i<n; i++){
    //     std::cout << i << "-th lwe-a: " << lwe_a[i] << std::endl; 
    // }
    // do b - <a,s>
    // generate secret key
    SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey_lwe, n, *pool_);
    std::copy_n(rlwe_seckey_little_->data().data(), n, (uint64_t *)inv_seckey_lwe);
    util::inverse_ntt_negacyclic_harvey(inv_seckey_lwe, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
    if(have_modswitched){
        // OMP ready
        #pragma omp parallel for num_threads(num_th)
        for(int i=0; i<n; i++){
            if(inv_seckey_lwe[i] == *vec_mod[0].data() - 1){
                // std::cout << inv_seckey_lwe[i] << std::endl;
                inv_seckey_lwe[i] = mod_coeff.value() - 1;
                // std::cout << inv_seckey_lwe[i] << std::endl;
            }
        }
    }
    // for(int i=0; i<print_length; i++){
    //     std::cout << i << "-th skey: " << inv_seckey_lwe[i] << std::endl;
    // }
    // do <a,s>
    uint64_t inner_a_s = 0;
    for(uint64_t i=0; i<n; i++){
        inner_a_s = util::add_uint_mod(inner_a_s, util::multiply_uint_mod(lwe_a[i], inv_seckey_lwe[i], mod_coeff), mod_coeff);
        // if (i > n-4){
        //     std::cout << i << "-th inner-a-s: " << inner_a_s << std::endl;
        // }
    }
    // do b + <a,s>
    // inner_a_s = util::add_uint_mod(inner_a_s, lwe_b, mod_coeff);
    inner_a_s = util::add_uint_mod(inner_a_s, util::multiply_uint_mod(lwe_b, 1, mod_coeff), mod_coeff);
    std::cout << "In " << new_mod << " ";
    util::printInBinary(new_mod);
    std::cout << "mannual decryption result is: " << inner_a_s << " in binary: ";
    util::printInBinary(inner_a_s);
    // std::cout << "final inner-a-s: " << inner_a_s << std::endl;
    double scale_inner = (double) mod_coeff.value() / (double) mod_plain.value();
    uint64_t scale = std::round(scale_inner);
    std::cout << "modulus: " << mod_coeff.value() << " plain: " << mod_plain.value() << " scale: " << scale << std::endl; 
    // double inner_result = (double) inner_a_s / (double) scale;
    double inner_result = (double) inner_a_s * (double) mod_plain.value() / (double) mod_coeff.value();
    // std::cout << "mannual lwe decryption: " << inner_result << std::endl;
    result = std::round(inner_result);
    // result = inner_a_s; // should be hidden!
    std::cout << "--------------------" << std::endl;
    return;
}

void Cryptor::decrypt_manual_test(void) const
{
    size_t n = RLWEParamsLittle::poly_modulus_degree;
    size_t print_length = 4;
    size_t degree_count = util::get_power_of_two(n);
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();    
    Modulus mod_coeff = *vec_mod[0].data();
    Modulus mod_plain(RLWEParamsLittle::plain_modulus);
    double scale = (double) mod_coeff.value() / (double) mod_plain.value();
    VecData vec_test(1, n);
    Plaintext ptxt_test(n);
    for(int i=0; i<n; i++){
        ptxt_test.data()[i] = i;
    }
    RLWECipher ctxt_test;
    encrypt(ptxt_test, ctxt_test, ParamSet::RLWELittle);
    std::cout << "oringinal ";
    print_noise(ctxt_test,ParamSet::RLWELittle);

    // get secret key
    SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey, n, *pool_);
    std::copy_n(rlwe_seckey_little_->data().data(), n, (uint64_t *)inv_seckey);
    // check seckey
    std::cout << "modulus: " << *vec_mod[0].data() << std::endl;
    std::cout << "scale: " << scale << std::endl;

    // mannual decryption
    auto ntt_table = rlwe_context_little_->first_context_data()->small_ntt_tables();
    SEAL_ALLOCATE_GET_COEFF_ITER(c0, n, *pool_);
    SEAL_ALLOCATE_GET_COEFF_ITER(c1, n, *pool_);
    std::copy_n(ctxt_test.data(0), n, (uint64_t *)c0); // c0 = b
    std::copy_n(ctxt_test.data(1), n, (uint64_t *)c1); // c1 = a
    util::ntt_negacyclic_harvey_lazy(c1, *ntt_table);
    util::dyadic_product_coeffmod(c1, inv_seckey, n, mod_coeff, c1); // c1 = a * s 
    util::inverse_ntt_negacyclic_harvey(c1, *ntt_table);
    util::add_poly_coeffmod(c1, c0, n, mod_coeff, c0); // c0 = b + as
    std::cout << "decryption in plain: " ;
    for(int i=0; i<print_length; i++){
        std::cout << (double)c0[i] / (double)scale << " ";
    }
    std::cout << std::endl;

    // decryption correct, we then test lwe decryption
    LWECipher lwe_test;
    int idx = 17;
    SampleExtract(ctxt_test, lwe_test, idx, false, ParamSet::LWE);
    double dec_lwe = (double) decrypt(lwe_test, ParamSet::RLWELittle) / 1;
    std::cout << "LWE decryption in plain: " << dec_lwe << std::endl; // auto decryption correct

    // how about mannual decryption?
    uint64_t lwe_b = lwe_test[0];
    VecData lwe_a(n, 0ULL);
    for(int i=1; i<n+1; i++){
        lwe_a[i-1] = lwe_test[i];
    }
    // do b - <a,s>
    // generate secret key
    SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey_lwe, n, *pool_);
    std::copy_n(rlwe_seckey_little_->data().data(), n, (uint64_t *)inv_seckey_lwe);
    util::inverse_ntt_negacyclic_harvey(inv_seckey_lwe, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
    uint64_t inner_a_s = 0;
    for(uint64_t i=0; i<n; i++){
        inner_a_s = util::add_uint_mod(inner_a_s, util::multiply_uint_mod(lwe_a[i], inv_seckey_lwe[i], mod_coeff), mod_coeff);
    }
    inner_a_s = util::add_uint_mod(inner_a_s, lwe_b, mod_coeff);
    std::cout << "mannual lwe decryption: " << (double) inner_a_s / (double) scale << std::endl;
    // mannual decryption also correct

    return;
}

const Evaluator &Cryptor::get_evaluator(void) const
{
    return *rlwe_evaluator_;
}

void Cryptor::mod_to_last(RLWECipher &rlwe)
{
    rlwe_evaluator_->mod_switch_to_inplace(rlwe, rlwe_context_->last_parms_id());
}

void Cryptor::LinearTransform(RLWECipher &bfvct, MatrixData A) const
{   
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    VecData vec_bfvct(RLWEParams::poly_modulus_degree, 0ull);
    decrypt(bfvct, vec_bfvct);
    int print_bound = 16;

    int N = A.size();
    int row_size = N / 2;
    // std::cout << "N: " << N << std::endl;
    int n = A[0].size();
    int rt = sqrt(n); // assuming n is a perfect square

    std::cout << "n: " << n << std::endl;
    std::cout << "rt: " << rt << std::endl;

    // Step 1 is assumed to be done
    // bfvct encrypts a vector v ∈ Z^n_t by repeating v N/n times 
    // and encrypting the concatenation of those N/n repetitions.
    
    // Step 2
    std::vector<RLWECipher> bfvct_rot;
    bfvct_rot.resize(rt);
    // time_start = std::chrono::high_resolution_clock::now();
    #pragma omp parallel for num_threads(num_th)
    for (int i = 0; i < rt; i++) {
        RLWECipher temp = bfvct;
        if (((i+1)*rt) < n ){
            rlwe_evaluator_->rotate_rows_inplace(temp, (i+1)*rt, *rlwe_galoiskeys_);
        }
        bfvct_rot[i]= temp;
    }
    // time_end = std::chrono::high_resolution_clock::now();
    // time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    // std::cout << "BS Rotation Done [" << time_diff.count() << " microseconds]" << std::endl;

    // Step 3
    std::vector<RLWECipher> res(rt);
    #pragma omp parallel for num_threads(num_th)
    for(auto &r : res){
        // all zero ciphertext
        rlwe_encryptor_->encrypt_zero(r);
        rlwe_evaluator_->mod_switch_to_inplace(r, bfvct.parms_id());
    }

    // Step 4
    // DEBUG
    if (m_verbose)
        std::cout << "A with row: " << A.size() << " column: " << A[0].size() << std::endl;


    // just for time, this is wrong!!!
    // VecData tmp(N, 1ULL);
    // Plaintext ptxt;
    // rlwe_batch_encoder_->encode(tmp, ptxt);

    time_start = std::chrono::high_resolution_clock::now();
    #pragma omp parallel for num_threads(num_th)
    for (int k = 0; k < rt; k++) {
        for (int i = 0; i < rt; i++) {
            VecData tmp(N, 0); // initialized with 0's
            for (int j = 0; j < row_size; j++) {
                int ind_ct = (j-k+row_size) % row_size; // ERROR occurs:j-k<0
                int ind_a = (j+(i+1)*rt) % n;
                tmp[j] = A[ind_ct][ind_a];
                tmp[j+row_size] = A[ind_ct+row_size][ind_a];
            }
            
            Plaintext ptxt;
            RLWECipher c;
            rlwe_batch_encoder_->encode(tmp, ptxt);
            rlwe_evaluator_->multiply_plain(bfvct_rot[i],ptxt,c);
            rlwe_evaluator_->add_inplace(res[k], c);
        }
    }

    // Step 5
    for (int i = 0; i < rt - 1; i++) {
        RLWECipher c = res[rt - i - 1];
        rlwe_evaluator_->rotate_rows_inplace(c, 1, *rlwe_galoiskeys_);
        rlwe_evaluator_->add_inplace(res[rt - i - 2], c);
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Mul and GS Rotation Done(Zeyu LT Time) [" << time_diff.count() << " microseconds]" << std::endl;

    // The result
    bfvct = res[0];
}

void Cryptor::TestDoubleLT(RLWECipher &bfvct, MatrixData TestMatrix) const{

    std::cout << "TestMatrix.size(): " << TestMatrix.size() << std::endl;
    std::cout << "TestMatrix[0].size(): " << TestMatrix[0].size() << std::endl;
    RLWECipher temp1, temp2;
    temp1 = bfvct;
    rlwe_evaluator_->rotate_columns(temp1, *rlwe_galoiskeys_ ,temp2);

    VecData vec_temp1(RLWEParams::poly_modulus_degree, 0ull);
    decrypt(temp1, vec_temp1);
    std::cout << "temp1 vector is: " << std::endl;
    for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+1024) {
        std::cout << vec_temp1[i] << " ";
    }
    std::cout << std::endl;

    VecData vec_temp2(RLWEParams::poly_modulus_degree, 0ull);
    decrypt(temp2, vec_temp2);
    std::cout << "temp2 vector is: " << std::endl;
    for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+1024) {
        std::cout << vec_temp2[i] << " ";
    }
    std::cout << std::endl;

    MatrixData matrix_left, matrix_right;
    matrix_left.resize(RLWEParams::poly_modulus_degree, VecData(RLWEParams::poly_modulus_degree/2));
    matrix_right.resize(RLWEParams::poly_modulus_degree, VecData(RLWEParams::poly_modulus_degree/2));
    // split dwt_matrix
    for (int i = 0; i < RLWEParams::poly_modulus_degree; i++)
    {
        if (i < RLWEParams::poly_modulus_degree/2)
        {
            for (int j = 0; j < RLWEParams::poly_modulus_degree/2; j++)
            {
                matrix_left[i][j] = TestMatrix[i][j];
                matrix_right[i][j] = TestMatrix[i][j+RLWEParams::poly_modulus_degree/2];
            }
        }
        else
        {
            for (int j = 0; j < RLWEParams::poly_modulus_degree/2; j++)
            {
                matrix_right[i][j] = TestMatrix[i][j];
                matrix_left[i][j] = TestMatrix[i][j+RLWEParams::poly_modulus_degree/2];
            }
        }
    }

    std::cout << "left matrix is: " << std::endl;
    for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+1024) {
        for (size_t j = 0; j < RLWEParams::poly_modulus_degree/2; j=j+1024) {
            std::cout << matrix_left[i][j] << " ";
        }
            std::cout << std::endl;
    }

    std::cout << "right matrix is: " << std::endl;
    for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+1024) {
        for (size_t j = 0; j < RLWEParams::poly_modulus_degree/2; j=j+1024) {
            std::cout << matrix_right[i][j] << " ";
        }
            std::cout << std::endl;
    }

    std::cout << "matrix_left.size(): " << matrix_left.size() << std::endl;
    std::cout << "matrix_left[0].size(): " << matrix_left[0].size() << std::endl;
    std::cout << "matrix_right.size(): " << matrix_right.size() << std::endl;
    std::cout << "matrix_right[0].size(): " << matrix_right[0].size() << std::endl;
    LinearTransform(temp1, matrix_left);
    std::cout <<"temp 1 noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp1) << " bits" << std::endl;
    std::cout << "LT 1 Done" << std::endl;
    VecData result1(RLWEParams::poly_modulus_degree, 0ull);
    decrypt(temp1, result1);
    std::cout << "LT 1 vector is: " << std::endl;
    for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+1024) {
        std::cout << result1[i] << " ";
    }
    std::cout << std::endl;
    LinearTransform(temp2, matrix_right);
    std::cout <<"temp 2 noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp2) << " bits" << std::endl;
    std::cout << "LT 2 Done" << std::endl;
    VecData result2(RLWEParams::poly_modulus_degree, 0ull);
    decrypt(temp2, result2);
    std::cout << "LT 2 vector is: " << std::endl;
    for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+1024) {
        std::cout << result2[i] << " ";
    }
    std::cout << std::endl;
    rlwe_evaluator_->add(temp1, temp2, bfvct);
    // std::cout << "LT here" << std::endl;

    return;
}

void Cryptor::Compute_all_powers(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers) const
{
    powers.resize(degree+1);

    // Initialized powers
    for (int i = 1; i<degree+1; i++)
        powers[i] = icipher;

    std::vector<int> levels(degree +1, 0);
    levels[1] = 0;
    levels[0] = 0;

    // count number of multiply execution
    int num_mul = 0;

    // vector to keep track of number of multiplications each ciphertext has gone through
    std::vector<int> mul_count(degree+1, 0);

    for (int i = 2; i <= degree; i++){

        // Print debugging info
        std::cout << "i: " << i << std::endl;

        // compute x^i 
        int minlevel = i;
        int cand = -1; 
        for (int j = 1; j <= i/2; j++){
            int k =  i - j; 
            //
            int newlevel = std::max(levels[j], levels[k]) + 1;
            if( newlevel < minlevel){
                cand = j;
                minlevel = newlevel;
            }
        }
        levels[i] = minlevel; 

        // DEBUG
        std::cout << "cand: " << cand << ", i-cand: " << i-cand << std::endl;
        std::cout << "Before switch - powers[cand] chain index: " 
                << rlwe_context_->get_context_data(powers[cand].parms_id())->chain_index() << std::endl;
        std::cout << "Before switch - powers[i-cand] chain index: " 
                << rlwe_context_->get_context_data(powers[i-cand].parms_id())->chain_index() << std::endl;

        // use cand 
        if (cand < 0) throw std::runtime_error("error"); 
        //cout << "levels " << i << " = " << levels[i] << endl; 
        // cand <= i - cand by definition 
        Ciphertext temp = powers[cand]; 
        rlwe_evaluator_->mod_switch_to_inplace(temp, powers[i-cand].parms_id()); 
        rlwe_evaluator_->multiply(temp, powers[i-cand], powers[i]);
        num_mul++;
        rlwe_evaluator_->relinearize_inplace(powers[i], *rlwe_relinkeys_);  

        // Increase the mul_count for both powers[cand] and powers[i-cand]
        mul_count[i] = mul_count[i-cand] + mul_count[i] + 1;


        // Print mul_count for debugging
        for (int count : mul_count) {
            std::cout << "Mul_count: " << count << std::endl;
        }

        rlwe_evaluator_->mod_switch_to_next_inplace(powers[i]);

        // Print details about all current RLWECipher objects in powers
        for (int j = 1; j <= i; j++) {
            std::cout << "powers[" << j << "] chain index: " 
                    << rlwe_context_->get_context_data(powers[j].parms_id())->chain_index() << std::endl;
        }

    }

    std::cout << "number of multiplication = " << num_mul << std::endl;
    return; 
}

void Cryptor::Compute_all_powers_bound(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers, int switch_bound, std::vector<int> mul_count) const
{
    powers.resize(degree+1);


    // Initialized powers
    for (int i = 1; i<degree+1; i++)
        powers[i] = icipher;

    std::vector<int> levels(degree +1, 0);
    levels[1] = 0;
    levels[0] = 0;

    // count number of multiply execution
    int num_mul = 0;

    // // vector to keep track of number of multiplications each ciphertext has gone through
    // std::vector<int> mul_count(degree+1, 0);

    for (int i = 2; i <= degree; i++){

        // Print debugging info
        if (m_verbose)
            std::cout << "i: " << i << std::endl;

        // compute x^i 
        int minlevel = i;
        int cand = -1; 
        for (int j = 1; j <= i/2; j++){
            int k =  i - j; 
            //
            int newlevel = std::max(levels[j], levels[k]) + 1;
            if( newlevel < minlevel){
                cand = j;
                minlevel = newlevel;
            }
        }
        levels[i] = minlevel; 

        // DEBUG
        if(m_verbose)
        {
            std::cout << "cand: " << cand << ", i-cand: " << i-cand << std::endl;
            std::cout << "Before switch - powers[cand] chain index: " 
                << rlwe_context_->get_context_data(powers[cand].parms_id())->chain_index() << std::endl;
            std::cout << "Before switch - powers[i-cand] chain index: " 
                << rlwe_context_->get_context_data(powers[i-cand].parms_id())->chain_index() << std::endl;
        }


        // use cand 
        if (cand < 0) throw std::runtime_error("error"); 
        // cand <= i - cand by definition 
        Ciphertext temp = powers[cand]; 
        rlwe_evaluator_->mod_switch_to_inplace(temp, powers[i-cand].parms_id()); 
        // if (rlwe_context_->get_context_data(powers[i-cand].parms_id())->chain_index() > 
        //     rlwe_context_->get_context_data(temp.parms_id())->chain_index() )
        //     rlwe_evaluator_->mod_switch_to_inplace(powers[i-cand], temp.parms_id());
        // else
        //     rlwe_evaluator_->mod_switch_to_inplace(temp, powers[i-cand].parms_id()); 

        rlwe_evaluator_->multiply(temp, powers[i-cand], powers[i]);
        num_mul++;
        rlwe_evaluator_->relinearize_inplace(powers[i], *rlwe_relinkeys_);  

        // Increase the mul_count for both powers[cand] and powers[i-cand]
        mul_count[i] = mul_count[i-cand] + mul_count[i] + 1;

        // Print mul_count for debugging
        // if(m_verbose)
        // {
        //     for (int count : mul_count) {
        //     std::cout << "Mul_count: " << count << std::endl;
        //     }
        // }


        // Check if the mul_count is 2 for powers[i]
        // If yes, do mod_switch_to_next_inplace (if it's not already at the highest level) and reset the counter
        if (mul_count[i] == switch_bound) {
            rlwe_evaluator_->mod_switch_to_next_inplace(powers[i]);
            mul_count[i] = 0;
        }

         // Print details about all current RLWECipher objects in powers
        // if(m_verbose)
        // {
        //     for (int j = 1; j <= i; j++) {
        //     std::cout << "powers[" << j << "] chain index: " 
        //             << rlwe_context_->get_context_data(powers[j].parms_id())->chain_index() << std::endl;
        //     }
        // }
    }

    std::cout << "number of multiplication = " << num_mul << std::endl;
    return; 
}

void Cryptor::Compute_all_powers_square_opt(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers, int switch_bound, std::vector<int> mul_count) const
{
    powers.resize(degree+1);

    // Initialized powers
    for (int i = 1; i<degree+1; i++)
        powers[i] = icipher;

    std::vector<int> levels(degree +1, 0);
    levels[1] = 0;
    levels[0] = 0;

    // count number of multiply execution
    int num_mul = 0;
    // count number of relin execution
    int num_relin = 0;

    // // vector to keep track of number of multiplications each ciphertext has gone through
    // std::vector<int> mul_count(degree+1, 0);

    for (int i = 2; i <= degree; i++){

        // Print debugging info
        if (m_verbose)
            std::cout << "i: " << i << std::endl;

        // compute x^i 
        int minlevel = i;
        int cand = -1; 
        for (int j = 1; j <= i/2; j++){
            int k =  i - j; 
            //
            int newlevel = std::max(levels[j], levels[k]) + 1;
            if( newlevel < minlevel){
                cand = j;
                minlevel = newlevel;
            }
        }
        levels[i] = minlevel; 

        // DEBUG
        if(m_verbose)
        {
            std::cout << "cand: " << cand << ", i-cand: " << i-cand << std::endl;
            std::cout << "Before switch - powers[cand] chain index: " 
                << rlwe_context_->get_context_data(powers[cand].parms_id())->chain_index() << std::endl;
            std::cout << "Before switch - powers[i-cand] chain index: " 
                << rlwe_context_->get_context_data(powers[i-cand].parms_id())->chain_index() << std::endl;
        }


        // use cand 
        if (cand < 0) throw std::runtime_error("error"); 
        // cand <= i - cand by definition 
        Ciphertext temp = powers[cand]; 
        rlwe_evaluator_->mod_switch_to_inplace(temp, powers[i-cand].parms_id()); 
        // if (rlwe_context_->get_context_data(powers[i-cand].parms_id())->chain_index() > 
        //     rlwe_context_->get_context_data(temp.parms_id())->chain_index() )
        //     rlwe_evaluator_->mod_switch_to_inplace(powers[i-cand], temp.parms_id());
        // else
        //     rlwe_evaluator_->mod_switch_to_inplace(temp, powers[i-cand].parms_id()); 
        
        // optimization for square
        // Time counter
        std::chrono::high_resolution_clock::time_point mul_start, mul_end;
        std::chrono::microseconds mul_diff;
        mul_start = std::chrono::high_resolution_clock::now();
        if (cand != (i-cand))
            rlwe_evaluator_->multiply(temp, powers[i-cand], powers[i]);
        else
            rlwe_evaluator_->square(temp, powers[i]);
        mul_end = std::chrono::high_resolution_clock::now();
        mul_diff = std::chrono::duration_cast<std::chrono::microseconds>(mul_end - mul_start);
        num_mul++;
        if (m_verbose)
            std::cout << i << "-th Ctxt Mul: " << mul_diff.count() << " microseconds" << std::endl;

        // Time counter
        std::chrono::high_resolution_clock::time_point relin_start, relin_end;
        std::chrono::microseconds relin_diff;
        relin_start = std::chrono::high_resolution_clock::now();
        rlwe_evaluator_->relinearize_inplace(powers[i], *rlwe_relinkeys_);  
        relin_end = std::chrono::high_resolution_clock::now();
        num_relin++;
        relin_diff = std::chrono::duration_cast<std::chrono::microseconds>(relin_end - relin_start);
        if (m_verbose)
            std::cout << i << "-th relin: " << relin_diff.count() << " microseconds" << std::endl;

        // Increase the mul_count for both powers[cand] and powers[i-cand]
        mul_count[i] = mul_count[i-cand] + mul_count[i] + 1;

        // Print mul_count for debugging
        // if(m_verbose)
        // {
        //     for (int count : mul_count) {
        //     std::cout << "Mul_count: " << count << std::endl;
        //     }
        // }


        // Check if the mul_count is 2 for powers[i]
        // If yes, do mod_switch_to_next_inplace (if it's not already at the highest level) and reset the counter
        if (mul_count[i] == switch_bound) {
            rlwe_evaluator_->mod_switch_to_next_inplace(powers[i]);
            mul_count[i] = 0;
        }

        // Print details about all current RLWECipher objects in powers
        // if(m_verbose)
        // {
        //     for (int j = 1; j <= i; j++) {
        //     std::cout << "powers[" << j << "] chain index: " 
        //             << rlwe_context_->get_context_data(powers[j].parms_id())->chain_index() << std::endl;
        //     }
        // }

                // Noise budget
        if(m_verbose)
        {
            std::cout << i <<"-th Noise budget: " << rlwe_decryptor_->invariant_noise_budget(powers[i]) << " bits" << std::endl;
            std::cout << "===================================" << std::endl;
        }
    }

    std::cout << "number of multiplication = " << num_mul << std::endl;
    std::cout << "number of relin = " << num_relin << std::endl;

    if(m_verbose)
        std::cout << "Powers Done" << std::endl;

    return; 
}

void Cryptor::Compute_all_powers_in_parallel(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers, int switch_bound, std::vector<int> mul_count) const
{
    if(m_verbose)
    {
        std::cout << "input power chain index: " 
            << rlwe_context_->get_context_data(icipher.parms_id())->chain_index() << std::endl;
    }
    
    // Initialized powers
    powers.resize(degree+1);
    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i<degree+1; i++)
        powers[i] = icipher;

    // count number of multiply execution
    int num_mul = 0;
    // count number of relin execution
    int num_relin = 0;

    // get biggest power-of-2 number less than degree
    int p_2 = floor(log2(degree));
    if(m_verbose){
        std::cout << "power-of-" << degree << " is: " << p_2 << std::endl;
    }
    
    // compute all powers-of-2 ciphertext
    if (m_verbose){
        std::cout << "compute power of 2" << std::endl;
        std::cout << "===================================" << std::endl;
    }
    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < p_2+1; i++)
    {   
        if (m_verbose){
            std::cout << "powers: " << (1<<i) << std::endl;
        }
        int index = 1 << i;
        for (int j = 0; j < i; j++)
        {
            rlwe_evaluator_->square_inplace(powers[1<<i]);
            rlwe_evaluator_->relinearize_inplace(powers[1<<i], *rlwe_relinkeys_);
            mul_count[1<<i]++;
            num_relin++;
            num_mul++;
            if (m_verbose){
                std::cout << "mul_count[" << (1<<i) << "]: " << mul_count[1<<i] << std::endl;
                std::cout << "switch_bound: " << switch_bound << std::endl;
            }
            if (mul_count[1<<i] == switch_bound){
                rlwe_evaluator_->mod_switch_to_next_inplace(powers[1<<i]);
                mul_count[1<<i] = 0;
            }
        }
        if(m_verbose)
        {
            std::cout << (1<<i) << "-th power chain index: " 
                << rlwe_context_->get_context_data(powers[1<<i].parms_id())->chain_index() << std::endl;
            std::cout << (1<<i) <<"-th power Noise budget: " << rlwe_decryptor_->invariant_noise_budget(powers[1<<i]) << " bits" << std::endl;
            std::cout << "===================================" << std::endl;
        }
    }

    // compute all non-powers-of-2 ciphertext
    if (m_verbose){
        std::cout << "compute non power of 2" << std::endl;
        std::cout << "===================================" << std::endl;
    }
    #pragma omp parallel for num_threads(num_th)
    for (int i = 3; i < degree+1; i++)
    {
        if (!seal::util::isPowerOf2(i)) // if it's not power-of-2
        {
            if (m_verbose){
                std::cout << "powers: " << i << std::endl;
            }
            int temp = i >> 1;
            int j = 0;
            while (temp > 0)
            {
                if (m_verbose){
                        std::cout << "temp: " << temp << std::endl;
                        std::cout << "temp & 1: " << (temp & 1) << std::endl;
                }
                if (temp & 1)
                {
                    if (m_verbose){
                        std::cout << "i: " << i << ", 1 << (j+1): " << (1 << (j+1)) << std::endl;
                        std::cout << i << "-th power chain index: " 
                        << rlwe_context_->get_context_data(powers[i].parms_id())->chain_index() << std::endl;
                        std::cout << (1 << (j+1)) << "-th power chain index: " 
                        << rlwe_context_->get_context_data(powers[1 << (j+1)].parms_id())->chain_index() << std::endl;
                    }
                    rlwe_evaluator_->mod_switch_to_inplace(powers[i], powers[1 << (j+1)].parms_id());
                    rlwe_evaluator_->multiply_inplace(powers[i], powers[1 << (j+1)]);
                    rlwe_evaluator_->relinearize_inplace(powers[i], *rlwe_relinkeys_);
                    mul_count[i] = mul_count[1 << (j+1)] + 1;
                    num_relin++;
                    num_mul++;
                    if (mul_count[i] == switch_bound){
                        rlwe_evaluator_->mod_switch_to_next_inplace(powers[i]);
                        mul_count[i] = 0;
                    }
                }
                temp >>= 1;
                j++;
            }
        }
        if(m_verbose)
        {
            std::cout << i << "-th power chain index: " 
                << rlwe_context_->get_context_data(powers[i].parms_id())->chain_index() << std::endl;
            std::cout << i <<"-th power Noise budget: " << rlwe_decryptor_->invariant_noise_budget(powers[i]) << " bits" << std::endl;
            std::cout << "===================================" << std::endl;
        }
    }


    std::cout << "number of multiplication = " << num_mul << std::endl;
    std::cout << "number of relin = " << num_relin << std::endl;

    if(m_verbose)
        std::cout << "Powers Done" << std::endl;

    return; 
}

void Cryptor::Compute_all_powers_in_pyramid(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers, int switch_bound, std::vector<int> mul_count) const
{
    if (degree < 0) {
        std::cerr << "Invalid degree. It should be non-negative." << std::endl;
        return;
    }

    // Initialized powers
    powers.resize(degree+1);
    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i<degree+1; i++){
        powers[i] = icipher;
    }
	rlwe_encryptor_->encrypt_zero(powers[0]);

    // count number of multiply execution
    int num_mul = 0;
    // count number of relin execution
    int num_relin = 0;


    for (int i = 1; i <= degree; i *= 2) {
        int max_j = (2*i) <= degree ? i+1 : degree - i + 1;
         #pragma omp parallel for num_threads(num_th)
        for (int j = 1; j < max_j; ++j) {
            int cand_left = i/2 + 1;
            int cand_right = (i+j) - cand_left;
            while(cand_right>i){
                cand_right--;
                cand_left++;
            }
            if (cand_left == cand_right){
                rlwe_evaluator_->square(powers[cand_left], powers[cand_left+cand_right]);
                rlwe_evaluator_->relinearize_inplace(powers[cand_left+cand_right], *rlwe_relinkeys_);
                if (m_verbose){
                    std::cout << "powers: " << (cand_left+cand_right) << " = " << cand_left << " square " << std::endl;
                }
            }
            else {
                rlwe_evaluator_->mod_switch_to_inplace(powers[cand_right], powers[cand_left].parms_id());
                rlwe_evaluator_->multiply(powers[cand_left], powers[cand_right], powers[cand_left+cand_right]);
                
                rlwe_evaluator_->relinearize_inplace(powers[cand_left+cand_right], *rlwe_relinkeys_);
                if (m_verbose){
                    std::cout << "powers: " << (cand_left+cand_right) << " = " << cand_left << " * " << cand_right << std::endl;
                }
            }
            mul_count[cand_left+cand_right] = i;
            num_relin++;
            num_mul++;
            if (mul_count[cand_left+cand_right] == switch_bound){
                rlwe_evaluator_->mod_switch_to_next_inplace(powers[cand_left+cand_right]);
                mul_count[cand_left+cand_right] = 0;
            }
            if(m_verbose)
            {
                std::cout << (cand_left+cand_right) << "-th power chain index: " 
                    << rlwe_context_->get_context_data(powers[cand_left+cand_right].parms_id())->chain_index() << std::endl;
                std::cout << (cand_left+cand_right) <<"-th power Noise budget: " << rlwe_decryptor_->invariant_noise_budget(powers[cand_left+cand_right]) << " bits" << std::endl;
                std::cout << "===================================" << std::endl;
            }
        }
    }

    std::cout << "number of multiplication = " << num_mul << std::endl;
    std::cout << "number of relin = " << num_relin << std::endl;

    if(m_verbose)
        std::cout << "Powers Done" << std::endl;

	return;
    
}

void Cryptor::Compute_all_powers_relin_improve(const RLWECipher &icipher, int degree, std::vector<RLWECipher> &powers, int switch_bound, std::vector<int> mul_count) const
{
    powers.resize(degree+1);

    // Max power of 2 number less than degree/2
    int max_power = ceil(log2(degree)) - 1;
    max_power = 1 << max_power;
    if (m_verbose)
        std::cout << "Max power of 2 number less than degree/2: " << max_power << std::endl;

    // Initialized powers
    for (int i = 1; i<degree+1; i++)
        powers[i] = icipher;

    std::vector<int> levels(degree +1, 0);
    levels[1] = 0;
    levels[0] = 0;

    // count number of multiply execution
    int num_mul = 0;
    // count number of relin execution
    int num_relin = 0;

    // // vector to keep track of number of multiplications each ciphertext has gone through
    // std::vector<int> mul_count(degree+1, 0);

    if (m_verbose)
    {
        std::cout << "Compute all powers start" << std::endl;
        std::cout << "================================" << std::endl;
    }

    for (int i = 2; i <= degree; i++){

        // Print debugging info
        if (m_verbose)
            std::cout << "i: " << i << std::endl;

        // compute x^i 
        int minlevel = i;
        int cand = -1; 
        for (int j = 1; j <= i/2; j++){
            int k =  i - j; 
            //
            int newlevel = std::max(levels[j], levels[k]) + 1;
            if( newlevel < minlevel){
                cand = j;
                minlevel = newlevel;
            }
        }
        levels[i] = minlevel; 

        // DEBUG
        if(m_verbose)
        {
            std::cout << "cand: " << cand << ", i-cand: " << i-cand << std::endl;
            std::cout << "Before switch - powers[cand] chain index: " 
                << rlwe_context_->get_context_data(powers[cand].parms_id())->chain_index() << std::endl;
            std::cout << "Before switch - powers[i-cand] chain index: " 
                << rlwe_context_->get_context_data(powers[i-cand].parms_id())->chain_index() << std::endl;
        }


        // use cand 
        if (cand < 0) throw std::runtime_error("error"); 
        // cand <= i - cand by definition 
        Ciphertext temp = powers[cand]; 
        rlwe_evaluator_->mod_switch_to_inplace(temp, powers[i-cand].parms_id()); 
        // if (rlwe_context_->get_context_data(powers[i-cand].parms_id())->chain_index() > 
        //     rlwe_context_->get_context_data(temp.parms_id())->chain_index() )
        //     rlwe_evaluator_->mod_switch_to_inplace(powers[i-cand], temp.parms_id());
        // else
        //     rlwe_evaluator_->mod_switch_to_inplace(temp, powers[i-cand].parms_id()); 

        // Time counter
        std::chrono::high_resolution_clock::time_point mul_start, mul_end;
        std::chrono::microseconds mul_diff;
        mul_start = std::chrono::high_resolution_clock::now();
        rlwe_evaluator_->multiply(temp, powers[i-cand], powers[i]);
        mul_end = std::chrono::high_resolution_clock::now();
        mul_diff = std::chrono::duration_cast<std::chrono::microseconds>(mul_end - mul_start);
        num_mul++;
        if (m_verbose)
            std::cout << i << "-th Ctxt Mul: " << mul_diff.count() << " microseconds" << std::endl;

        // Relin Improvement
        if(i <= max_power)
        {   
            // Time counter
            std::chrono::high_resolution_clock::time_point relin_start, relin_end;
            std::chrono::microseconds relin_diff;
            Ciphertext &relin_temp = powers[i];
            if (m_verbose)
            {
                std::cout << "Before Relin Index: " << i << " size: " << relin_temp.size() << std::endl;
            }
            relin_start = std::chrono::high_resolution_clock::now();
            if (relin_temp.size() == 3)
                rlwe_evaluator_->relinearize_inplace(powers[i], *rlwe_relinkeys_);
            // else if (relin_temp.size() == 3)
            //     rlwe_evaluator_->relinearize_inplace(powers[i], *rlwe_relinkeys2_);
            else{
                if (m_verbose)
                    std::cout << "Execute Relin 3" << std::endl;
                rlwe_evaluator_->relinearize_inplace(powers[i], *rlwe_relinkeys3_);
            }
            relin_end = std::chrono::high_resolution_clock::now();
            relin_diff = std::chrono::duration_cast<std::chrono::microseconds>(relin_end - relin_start);
            if (m_verbose)
            {
                std::cout << "After Relin Index: " << i << " size: " << relin_temp.size() << std::endl;
                std::cout << i << "-th Relin: " << relin_diff.count() << " microseconds" << std::endl;
                num_relin++;
            }
        }
        else
        {   
            if (m_verbose)
            {
                Ciphertext &relin_temp = powers[i];
                std::cout << "Before Relin Index: " << i << " size: " << relin_temp.size() << std::endl;
            }
        }

        // Increase the mul_count for both powers[cand] and powers[i-cand]
        mul_count[i] = mul_count[i-cand] + mul_count[i] + 1;

        // Print mul_count for debugging
        // if(m_verbose)
        // {
        //     for (int count : mul_count) {
        //     std::cout << "Mul_count: " << count << std::endl;
        //     }
        // }


        // Check if the mul_count is 2 for powers[i]
        // If yes, do mod_switch_to_next_inplace (if it's not already at the highest level) and reset the counter
        if (mul_count[i] == switch_bound) {
            rlwe_evaluator_->mod_switch_to_next_inplace(powers[i]);
            mul_count[i] = 0;
        }

         // Print details about all current RLWECipher objects in powers
        // if(m_verbose)
        // {
        //     for (int j = 1; j <= i; j++) {
        //     std::cout << "powers[" << j << "] chain index: " 
        //             << rlwe_context_->get_context_data(powers[j].parms_id())->chain_index() << std::endl;
        //     }
        // }

        // Noise budget
        if(m_verbose)
        {
            std::cout << i <<"-th Noise budget: " << rlwe_decryptor_->invariant_noise_budget(powers[i]) << " bits" << std::endl;
            std::cout << "===================================" << std::endl;
        }
    }

    std::cout << "number of multiplication = " << num_mul << std::endl;
    std::cout << "number of relin = " << num_relin << std::endl;
    return; 
}

void Cryptor::PolyEvalTree(const VecData &coefficients, const RLWECipher &icipher, RLWECipher &ocipher) const
{   
    // compute degree according to polynomial coefficients
    size_t degree = util::Degree(coefficients);

    // compute the depth of the tree
    int depth = ceil(log2(degree));

    // compute all powers
    std::vector<Ciphertext> powers(degree+1); 
    Compute_all_powers(icipher, degree, powers);

    // encode coefficients
    std::vector<Plaintext> plain_coeffs(degree+1);
    for (size_t i = 0; i < degree + 1; i++) {
        // a vector full of coefficients[i] RLWEParams::PolyModulusDegree times
        VecData tmp(RLWEParams::poly_modulus_degree, coefficients[i]);
        rlwe_batch_encoder_->encode(tmp, plain_coeffs[i]);
    }

    rlwe_encryptor_->encrypt(plain_coeffs[0], ocipher);

    // DEBUG
    // VecData debug;
    // decrypt(ocipher,debug);
    // std::cout << "debug = " << std::endl;
    // for (int i=0; i<RLWEParams::poly_modulus_degree; i++){
    //     std::cout << debug[i] << " ";
    // }
    // std::cout << std::endl;

    RLWECipher temp; 
    for (int i = 1; i <= degree; i++){  

        //cout << i << "-th sum started" << endl; 
        
        // DEBUG
        // std::cout << "i=" << i << std::endl;
        // auto a = is_valid_for(plain_coeffs[i], *rlwe_context_);
        // std::cout << a << std::endl;
        // auto context_data_ptr = rlwe_context_->get_context_data(plain_coeffs[i].parms_id());
        // auto target_context_data_ptr = rlwe_context_->get_context_data(powers[i].parms_id());
        // std::cout << context_data_ptr << std::endl;
        // std::cout << target_context_data_ptr << std::endl;


        // rlwe_evaluator_->mod_switch_to_inplace(plain_coeffs[i], powers[i].parms_id()); 
        // rlwe_evaluator_->mod_switch_to_next_inplace(plain_coeffs[i]);
        rlwe_evaluator_->multiply_plain(powers[i], plain_coeffs[i], temp); 
        //cout << "got here " << endl; 
        rlwe_evaluator_->mod_switch_to_inplace(ocipher, temp.parms_id()); 
        rlwe_evaluator_->add_inplace(ocipher, temp);

        // DEBUG
        // decrypt(ocipher,debug);
        // std::cout << i << "round debug = " << std::endl;
        // for (int i=0; i<RLWEParams::poly_modulus_degree; i++){
        //     std::cout << debug[i] << " ";
        // }
        // std::cout << std::endl;

        // cout << i << "-th sum done" << endl; 
    }


}

void Cryptor::PolyEvalBSGS(const VecData &coefficients, const RLWECipher &icipher, RLWECipher &ocipher) const
{   

    // Noise budget
    if (m_verbose)
        std::cout << "Original Noise budget: " << rlwe_decryptor_->invariant_noise_budget(icipher) << " bits" << std::endl;
            
    // compute degree according to polynomial coefficients
    size_t degree = util::Degree(coefficients);
    if (m_verbose)
    {
        std::cout << "Poly degree: " << degree << std::endl;
    }

    // if degree = 0, return
    if (degree == 0)
    {
        VecData tmp(RLWEParams::poly_modulus_degree, coefficients[0]);
        Plaintext plain_coeffs;
        rlwe_batch_encoder_->encode(tmp, plain_coeffs);
        rlwe_evaluator_->multiply_plain(icipher,plain_coeffs,ocipher);
        return;
    }

    // compute the depth of the tree
    int depth = ceil(log2(degree));

    int n1 = std::ceil(std::sqrt(degree + 1));
    int n2 = std::ceil(std::sqrt(degree + 1));

    // Modify the step
    while (n1 * n2 - (degree + 1) > n1){
        n2--;
    }

    std::cout << "n1 = " << n1 << std::endl;
    std::cout << "n2 = " << n2 << std::endl;

    std::vector<RLWECipher> powers_bs(n1+1); 
    std::vector<RLWECipher> powers_gs(n2);

    // modswicth when meet switch_bound
    int switch_bound = 2;
    // vector to keep track of number of multiplications each ciphertext has gone through
    std::vector<int> mul_count_bs(degree+1, 0);
    std::vector<int> mul_count_gs(degree+1, 0);

    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;
    time_start = std::chrono::high_resolution_clock::now();
    // Compute_all_powers(icipher, n1, powers_bs);
    // Compute_all_powers_bound(icipher, n1, powers_bs, switch_bound, mul_count_bs);
    // Compute_all_powers_square_opt(icipher, n1, powers_bs, switch_bound, mul_count_bs);
    // Compute_all_powers_in_parallel(icipher, n1, powers_bs, switch_bound, mul_count_bs);
    Compute_all_powers_in_pyramid(icipher, n1, powers_bs, switch_bound, mul_count_bs);
    // /////////////////// This is a part ////////////////////////
    // Compute_all_powers_relin_improve(icipher, n1, powers_bs, switch_bound, mul_count_bs);
    // // relin powers[n1] to 2
    // RLWECipher powers_bs_n1;
    // rlwe_evaluator_->relinearize(powers_bs[n1], *rlwe_relinkeys_, powers_bs_n1);
    // //////////////////     End  ///////////////////////////
    // std::cout << "bs done" << std::endl;
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "power 1 time: " << time_diff.count() << " microseconds" << std::endl;

    time_start = std::chrono::high_resolution_clock::now();
    // Compute_all_powers(powers_bs[n1], n2, powers_gs); 
    // Compute_all_powers_bound(powers_bs[n1], n2, powers_gs, switch_bound, mul_count_gs); 
    mul_count_gs[1] = mul_count_bs[n1];
    // Compute_all_powers_square_opt(powers_bs[n1], n2, powers_gs, switch_bound, mul_count_gs); 
    // Compute_all_powers_in_parallel(powers_bs[n1], n2, powers_gs, switch_bound, mul_count_gs);
    Compute_all_powers_in_pyramid(powers_bs[n1], n2, powers_gs, switch_bound, mul_count_gs);
    // Compute_all_powers_relin_improve(powers_bs_n1, n2, powers_gs, switch_bound, mul_count_gs); 
    // std::cout << "gs done" << std::endl;
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "power 2 time: " << time_diff.count() << " microseconds" << std::endl;

    powers_bs.pop_back(); // remove last

    std::cout << "all powers compute" << std::endl;
    // Optimization: we mod switch all ciphertext to last ciphertext of gs step
    size_t lowest_chain_idx = rlwe_context_->get_context_data(powers_gs[n2].parms_id())->chain_index();
    size_t dest_chain_idx = 1;
    if(m_verbose){
        std::cout << "lowest chian idx of all power: " << lowest_chain_idx << std::endl;
        std::cout << "destination chain idx: " << dest_chain_idx << std::endl;
    }
    for(size_t i=0; i<lowest_chain_idx-dest_chain_idx; i++){
        rlwe_evaluator_->mod_switch_to_next_inplace(powers_gs[n2]);
    }
    auto gs_last_id = powers_gs[n2].parms_id();

    #pragma omp parallel for num_threads(32)
    for(size_t i=1; i<n1+n2; i++){
        if(i<n1){
            rlwe_evaluator_->mod_switch_to_inplace(powers_bs[i], gs_last_id);
        }
        else if(n1<i<n1+n2-1){
            rlwe_evaluator_->mod_switch_to_inplace(powers_gs[i-n1], gs_last_id);
        }
    }

    int num_mul = 0;
    int mul_count = 0;

    // for parallel
    std::vector<RLWECipher> vec_temp;
    vec_temp.resize(n2);

    // main loop for dotproduct
    // encode coefficients
    // std::vector<Plaintext> plain_coeffs(degree+1);
    // #pragma omp parallel for num_threads(num_th)
    // for (size_t i = 0; i < degree + 1; i++) {
    //     // a vector full of coefficients[i] RLWEParams::PolyModulusDegree times
    //     VecData tmp(RLWEParams::poly_modulus_degree, coefficients[i]);
    //     rlwe_batch_encoder_->encode(tmp, plain_coeffs[i]);
    // }
    time_start = std::chrono::high_resolution_clock::now();
    #pragma omp parallel for num_threads(num_th)
    for (int j = 0; j < n2; j++){
        if(j*n1 == degree){
            RLWECipher temp = powers_gs[j]; 
            std::cout << "j: "<<j<< std::endl;
            auto &context_data = *rlwe_context_->get_context_data(powers_gs[j].parms_id()); // we assume all ctxt share same parms id
            auto &parms = context_data.parms();
            size_t coeff_count = parms.poly_modulus_degree();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            std::cout << "coeff_count: " << coeff_count << " coeff_modulus_size: " << coeff_modulus_size << " powers_gs[j].size(): " << powers_gs[j].size() << " j*n1: " << j*n1 << "coefficients[j*n1]: " << coefficients[j*n1] << std::endl;
            util::multiply_poly_scalar_coeffmod(
                    util::ConstPolyIter(powers_gs[j].data(), coeff_count, coeff_modulus_size), powers_gs[j].size(), coefficients[j*n1],
                    coeff_modulus, util::PolyIter(temp.data(), coeff_count, coeff_modulus_size));
            if(temp.is_transparent()){
                rlwe_encryptor_->encrypt_zero(temp);
                rlwe_evaluator_->mod_switch_to_inplace(temp, powers_gs[j].parms_id());
            }
            vec_temp[j] = temp;
        }
        else if (j > 0){
            RLWECipher temp; 
            // Time counter
            std::chrono::high_resolution_clock::time_point dot_start, dot_end;
            std::chrono::microseconds dot_diff;
            dot_start = std::chrono::high_resolution_clock::now();
            // dot_product(plain_coeffs, j*n1, powers_bs, temp); 
            dot_product_vec(coefficients, j*n1, powers_bs, temp);
            dot_end = std::chrono::high_resolution_clock::now();
            dot_diff = std::chrono::duration_cast<std::chrono::microseconds>(dot_end - dot_start);
            if (m_verbose)
            {
                std::cout << j << "-th dot product result size: " << temp.size() << std::endl;
                std::cout << j << "-th dot product chain index: " << rlwe_context_->get_context_data(temp.parms_id())->chain_index() << std::endl;
                std::cout << j << "-th dot product time: " << dot_diff.count() << " microseconds" << std::endl; 
            }
            if (m_verbose)
            {
                std::cout << j << "-th giant step result size: " << powers_gs[j].size() << std::endl;
                std::cout << j << "-th giant step chain index: " << rlwe_context_->get_context_data(powers_gs[j].parms_id())->chain_index() << std::endl;
            }
            // need to decide which. 
            if (temp.coeff_modulus_size() > powers_gs[j].coeff_modulus_size()){
                rlwe_evaluator_->mod_switch_to_inplace(temp, powers_gs[j].parms_id());     
            } else if (temp.coeff_modulus_size() < powers_gs[j].coeff_modulus_size()){
                rlwe_evaluator_->mod_switch_to_inplace(powers_gs[j], temp.parms_id());
            }

            if (m_verbose)
            {
                std::cout << j << "-th dot product result size: " << temp.size() << std::endl;
                std::cout << j << "-th giant step ctxt size: " << powers_gs[j].size() << std::endl;
            }
            
            // Time counter
            std::chrono::high_resolution_clock::time_point mul_start, mul_end;
            std::chrono::microseconds mul_diff;
            mul_start = std::chrono::high_resolution_clock::now();
            rlwe_evaluator_->multiply_inplace(temp, powers_gs[j]);
            mul_end = std::chrono::high_resolution_clock::now();
            mul_diff = std::chrono::duration_cast<std::chrono::microseconds>(mul_end - mul_start);
            if (m_verbose){
                std::cout << j << "-th ctxt mul size: " << temp.size()  << std::endl;
                std::cout << j << "-th ctxt mul time: " << mul_diff.count() << " microseconds" << std::endl;
            }

            num_mul++;
            mul_count = mul_count_gs[j]++;

            if (mul_count == switch_bound)
                rlwe_evaluator_->mod_switch_to_next_inplace(temp); 

            if (m_verbose)
            {
                std::cout << j << "-th ctxt mul chain index: " << rlwe_context_->get_context_data(temp.parms_id())->chain_index() << std::endl;
                std::cout << j-1 << "-th result chain index: " << rlwe_context_->get_context_data(temp.parms_id())->chain_index() << std::endl;
            }
            // for parallel
            vec_temp[j] = temp;

            if (m_verbose){
                std::cout << j << "-th result size: " << vec_temp[j].size()  << std::endl;
                std::cout << j << "-th result chain index: " << rlwe_context_->get_context_data(vec_temp[j].parms_id())->chain_index() << std::endl;
                std::cout << j <<"-round Noise budget: " << rlwe_decryptor_->invariant_noise_budget(vec_temp[j]) << " bits" << std::endl;
                std::cout << "============================================" << std::endl;
            }
        }
        else{
            RLWECipher temp; 
            // Time counter
            std::chrono::high_resolution_clock::time_point dot_start, dot_end;
            std::chrono::microseconds dot_diff;
            dot_start = std::chrono::high_resolution_clock::now();
            // dot_product(plain_coeffs, j*n1, powers_bs, temp); 
            dot_product_vec(coefficients, j*n1, powers_bs, temp);
            dot_end = std::chrono::high_resolution_clock::now();
            dot_diff = std::chrono::duration_cast<std::chrono::microseconds>(dot_end - dot_start);
            if (m_verbose)
            {
                std::cout << j << "-th dot product result size: " << temp.size() << std::endl;
                std::cout << j << "-th dot product chain index: " << rlwe_context_->get_context_data(temp.parms_id())->chain_index() << std::endl;
                std::cout << j << "-th dot product time: " << dot_diff.count() << " microseconds" << std::endl; 
            }
            // for parallel 
            vec_temp[j] = temp; 
            // Noise budget
            if(m_verbose){
                std::cout << j << "-th result size: " << vec_temp[j].size()  << std::endl;
                std::cout << j << "-th result chain index: " << rlwe_context_->get_context_data(vec_temp[j].parms_id())->chain_index() << std::endl;
                std::cout << j <<"-round Noise budget: " << rlwe_decryptor_->invariant_noise_budget(vec_temp[j]) << " bits" << std::endl;
                std::cout << "============================================" << std::endl;
            }
        }
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "dot product time: " << time_diff.count() << " microseconds" << std::endl;

    // combine the result
    // set to same parameters
    #pragma omp parallel for num_threads(num_th)
    for (int i = 0; i < vec_temp.size()-1; i++){
        rlwe_evaluator_->mod_switch_to_inplace(vec_temp[i], vec_temp[n2-1].parms_id());
    }
    // for parallel
    time_start = std::chrono::high_resolution_clock::now();
    rlwe_evaluator_->add_many(vec_temp, ocipher);
    rlwe_evaluator_->relinearize_inplace(ocipher, *rlwe_relinkeys_);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "combine time: " << time_diff.count() << " microseconds" << std::endl;
    if (m_verbose)
    {
        std::cout << "final result size: " << ocipher.size() << std::endl;
        std::cout << "final chain index: " << rlwe_context_->get_context_data(ocipher.parms_id())->chain_index() << std::endl;
        std::cout << "final add time: " << time_diff.count() << " microseconds" << std::endl; 
    }

    std::cout << "number of out multiplication = " << num_mul << std::endl;

    // Improve:Modswitch to last one
    rlwe_evaluator_->mod_switch_to_inplace(ocipher, rlwe_context_->last_parms_id());
    std::cout <<"BSGS result noise budget: " << rlwe_decryptor_->invariant_noise_budget(ocipher) << " bits" << std::endl;
    std::cout << "BSGS result chain index: " 
                << rlwe_context_->get_context_data(ocipher.parms_id())->chain_index() << std::endl;

}

void Cryptor::PolyEvalHorner(const VecData &coefficients, const RLWECipher &icipher, RLWECipher &ocipher) const
{
    // compute degree according to polynomial coefficients
    size_t degree = util::Degree(coefficients);

    // encode coefficients
    std::vector<Plaintext> plain_coeffs(degree+1);
    for (size_t i = 0; i < degree + 1; i++) {
        // a vector full of coefficients[i] RLWEParams::PolyModulusDegree times
        VecData tmp(RLWEParams::poly_modulus_degree, coefficients[i]);
        rlwe_batch_encoder_->encode(tmp, plain_coeffs[i]);
    }


    RLWECipher temp; 
    encrypt(plain_coeffs[degree], temp);
    // DEBUG
    VecData DEBUG;
    decrypt(temp, DEBUG);
    std::cout << "round " << 0 << std::endl;
    std::cout << DEBUG[0] << " ";
    // for (int i = 0; i < RLWEParams::poly_modulus_degree; i++){
    //     std::cout << DEBUG[i] << " ";
    // }
    std::cout << std::endl;

    RLWECipher input_cipher = icipher;

    int num_mul = 0;

    for (int i = degree - 1; i >= 0; i--) {
       
        rlwe_evaluator_->mod_switch_to_inplace(input_cipher, temp.parms_id());
        rlwe_evaluator_->multiply_inplace(temp, input_cipher);
        num_mul++;

        rlwe_evaluator_->relinearize_inplace(temp, *rlwe_relinkeys_);

        rlwe_evaluator_->mod_switch_to_next_inplace(temp); 
    
        rlwe_evaluator_->add_plain_inplace(temp, plain_coeffs[i]);
        // DEBUG
        VecData DEBUG;
        decrypt(temp, DEBUG);
        std::cout << "round " << i << std::endl;
        std::cout << DEBUG[0] << " ";
        std::cout << "Noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp) << " bits" << std::endl;
        // for (int i = 0; i < RLWEParams::poly_modulus_degree; i++){
        //     std::cout << DEBUG[i] << " ";
        // }
        std::cout << std::endl;

    }

    std::cout << "number of multiplication = "  << num_mul << std::endl;

    ocipher = temp;

}

void Cryptor::dot_product(std::vector<Plaintext> &pts, int skip, const std::vector<RLWECipher> &ctx, RLWECipher &destination) const
{   

    // std::cout << "dot product start" << std::endl;

    // TODO: Switch to parallel one
    
    // for parallel
    // std::vector<RLWECipher> vec_destination;
    // vec_destination.resize(ctx.size()-1);

    RLWECipher temp; 

    //cout << "skip = " << skip << endl; 
    // #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < ctx.size();i++){
        // // for parallel
        // RLWECipher temp; 

        // std::cout << "i: " << i << std::endl;
        // if (!is_metadata_valid_for(ctx[i], *rlwe_context_)){
        //     std::cout << i << "-th not valid" << std::endl;
        // }

        // rlwe_evaluator_->mod_switch_to_inplace(pts[i+skip], ctx[i].parms_id()); 
        if(i + skip > pts.size() - 1){
            continue;
        }
        else{
            
            // get rid of transparent error
            // rlwe_evaluator_->multiply_plain(ctx[i], pts[i+skip], temp); 
            try {
                rlwe_evaluator_->multiply_plain(ctx[i], pts[i+skip], temp); 
            }
            catch (const std::logic_error& e) {
                // Check if the exception message is the one you expect
                if (std::string(e.what()) == "result ciphertext is transparent") {
                    rlwe_encryptor_->encrypt_zero(temp);
                    rlwe_evaluator_->mod_switch_to_inplace(temp,ctx[i].parms_id());
                } else {
                    // If it's a different logic_error, might want to rethrow or handle differently
                    throw;
                }
            }
        }

        // for parallel
        // vec_destination[i-1] = temp; 
        
        if (i == 1){
            destination = temp; 
        } else{
            
            // // DEBUG
            // std::cout << "DEBUG5" << std::endl;
            // std::cout << is_metadata_valid_for(destination, *rlwe_context_) << std::endl;
            // std::cout << is_buffer_valid(destination) << std::endl; 
            rlwe_evaluator_->mod_switch_to_inplace(destination, temp.parms_id()); 

            rlwe_evaluator_->add_inplace(destination, temp); 
        }
    }

    // for parallel
    // #pragma omp parallel for num_threads(num_th)
    // for (int i = 0 ; i < vec_destination.size()-1; i++){
    //     rlwe_evaluator_->mod_switch_to_inplace(vec_destination[i], vec_destination[vec_destination.size()-1].parms_id());
    // }
    // rlwe_evaluator_->add_many(vec_destination, destination);

    // std::cout << "DEBUG6" << std::endl;
    // std::cout << is_metadata_valid_for(destination, *rlwe_context_) << std::endl;
    // std::cout << is_buffer_valid(destination) << std::endl; 
    
    // have to do this?
    // rlwe_evaluator_->mod_switch_to_next_inplace(destination); 

    // rlwe_evaluator_->mod_switch_to_inplace(pts[skip], destination.parms_id()); 
    rlwe_evaluator_->add_plain_inplace(destination, pts[skip]); 

    return; 
}

void Cryptor::dot_product_vec(const VecData &vec_coeff, int skip, const std::vector<RLWECipher> &ctx, RLWECipher &destination) const
{   

    auto &context_data = *rlwe_context_->get_context_data(ctx[1].parms_id()); // we assume all ctxt share same parms id
    auto &parms = context_data.parms();
    size_t coeff_count = parms.poly_modulus_degree();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    

    for (int i = 1; i < ctx.size();i++){
        RLWECipher temp = ctx[i]; 
        if(i + skip > vec_coeff.size() - 1){
            continue;
        }
        else{
            try {
                // rlwe_evaluator_->multiply_plain(ctx[i], pts[i+skip], temp); 
                util::multiply_poly_scalar_coeffmod(
                    util::ConstPolyIter(ctx[i].data(), coeff_count, coeff_modulus_size), ctx[i].size(), vec_coeff[i+skip],
                    coeff_modulus, util::PolyIter(temp.data(), coeff_count, coeff_modulus_size));
                // #pragma omp parallel for num_threads(num_th)
                // for(int t=0; t<coeff_modulus_size; t++){
                //     Modulus mod_now(*coeff_modulus[t].data());
                //     for (int j=0; j<coeff_count; j++){
                //         temp.data(0)[j+t*coeff_count] = util::multiply_uint_mod(ctx[i].data(0)[j+t*coeff_count], vec_coeff[i+skip], mod_now);
                //         temp.data(1)[j+t*coeff_count] = util::multiply_uint_mod(ctx[i].data(1)[j+t*coeff_count], vec_coeff[i+skip], mod_now);
                //     }
                // }
                if(temp.is_transparent()){
                    rlwe_encryptor_->encrypt_zero(temp);
                    rlwe_evaluator_->mod_switch_to_inplace(temp,ctx[i].parms_id());
                }
            }
            catch (const std::logic_error& e) {
                if (std::string(e.what()) == "result ciphertext is transparent") {
                    rlwe_encryptor_->encrypt_zero(temp);
                    rlwe_evaluator_->mod_switch_to_inplace(temp,ctx[i].parms_id());
                } else {
                    throw;
                }
            }
        }

        if (i == 1){
            destination = temp; 
        } else{
            // rlwe_evaluator_->mod_switch_to_inplace(destination, temp.parms_id()); 
            rlwe_evaluator_->add_inplace(destination, temp); 
        }
    }
    VecData vec_temp(coeff_count, vec_coeff[skip]);
    Plaintext pts_temp;
    rlwe_batch_encoder_->encode(vec_temp, pts_temp);
    rlwe_evaluator_->add_plain_inplace(destination, pts_temp); 

    return; 
}

void Cryptor::Test_Square_Opt(const RLWECipher &icipher1, const RLWECipher &icipher2) const
{   

    RLWECipher temp;
    int launch_time = 10;
    
    // Run multiply 100 times and measure average time
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < launch_time; ++i)
    {
        rlwe_evaluator_->multiply(icipher1, icipher2, temp);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> multiply_time = (end - start) / launch_time;
    std::cout << "Average multiply time: " << multiply_time.count() << " microseconds" << std::endl;
    
    // Run square 100 times and measure average time
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < launch_time; ++i)
    {
        rlwe_evaluator_->square(icipher1, temp);
    }
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> square_time = (end - start) / launch_time;
    std::cout << "Average square time: " << square_time.count() << " microseconds" << std::endl;
}

void Cryptor::negate_add_plain(const RLWECipher &irlwe, const Plaintext &ptxt, RLWECipher &orlwe) const
{   
    rlwe_evaluator_->negate(irlwe, orlwe);
    rlwe_evaluator_->add_plain_inplace(orlwe, ptxt);
}

void Cryptor::ctxt_add_plain(const RLWECipher &irlwe, const Plaintext &ptxt, RLWECipher &orlwe) const
{
    rlwe_evaluator_->add_plain(irlwe, ptxt, orlwe);
    return;
}

void Cryptor::CtxtSlot2Coeff(const RLWECipher &ictxt, RLWECipher &octxt) const
{
    // rubbish code
    // // Store NTT element
    // VecData roots_vector;
    // MatrixData dwt_matrix;
    // store_NTT_element(roots_vector, dwt_matrix);
    // Plaintext roots_ptxt;
    // rlwe_batch_encoder_->encode(roots_vector, roots_ptxt);
    // // std::cout << "encode here" << std::endl;
    // // component-wise multiplication
    // RLWECipher temp1, temp2;
    // rlwe_evaluator_->multiply_plain(ictxt, roots_ptxt, temp1);
    // // std::cout << "multiply here" << std::endl;
    // // matrix-vector multiplication
    // rlwe_evaluator_->rotate_columns(temp1, *rlwe_galoiskeys_ ,temp2);
    // MatrixData dwt_left, dwt_right;
    // dwt_left.resize(RLWEParams::poly_modulus_degree, VecData(RLWEParams::poly_modulus_degree/2));
    // dwt_right.resize(RLWEParams::poly_modulus_degree, VecData(RLWEParams::poly_modulus_degree/2));
    // // split dwt_matrix
    // for (int i = 0; i < RLWEParams::poly_modulus_degree; i++)
    // {
    //     if (i < RLWEParams::poly_modulus_degree/2)
    //     {
    //         for (int j = 0; j < RLWEParams::poly_modulus_degree/2; j++)
    //         {
    //             dwt_left[i][j] = dwt_matrix[i][j];
    //             dwt_right[i][j] = dwt_matrix[i][j+RLWEParams::poly_modulus_degree/2];
    //         }
    //     }
    //     else
    //     {
    //         for (int j = 0; j < RLWEParams::poly_modulus_degree/2; j++)
    //         {
    //             dwt_right[i][j] = dwt_matrix[i][j];
    //             dwt_left[i][j] = dwt_matrix[i][j+RLWEParams::poly_modulus_degree/2];
    //         }
    //     }
    // }
    // LinearTransform(temp1, dwt_left);
    // LinearTransform(temp2, dwt_right);
    // rlwe_evaluator_->add(temp1, temp2, octxt);
    // // std::cout << "LT here" << std::endl;

    int print_num = 16;
    MatrixData matrix_decode;

    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    time_start = std::chrono::high_resolution_clock::now();
    GenDecodeMatrix(matrix_decode);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Initialize decode matrix: [" << time_diff.count() << " microseconds]" << std::endl;
    
    // std::cout << "decode matrix is: " << std::endl;
    // for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+2048) {
    //     for (size_t j = 0; j < RLWEParams::poly_modulus_degree; j=j+2048) {
    //         std::cout << matrix_decode[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    // std::cout << "decode matrix is: " << std::endl;
    // for (size_t i = 0; i < print_num; i=i+1) {
    //     for (size_t j = 0; j < print_num; j=j+1) {
    //         std::cout << matrix_decode[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    if(m_verbose){
        std::cout << "matrix_decode.size(): " << matrix_decode.size() << std::endl;
        std::cout << "matrix_decode[0].size(): " << matrix_decode[0].size() << std::endl;
    }

    // for (int i=0; i<RLWEParams::poly_modulus_degree; i++){
    //     for (int j = 0; j<RLWEParams::poly_modulus_degree; j++){
    //         std::cout << "Matrix[" << i << "," << j << "]: " <<  matrix_U_trans[i][j] << " ";
    //     }
    // }
    RLWECipher temp1, temp2;
    temp1 = ictxt;
    rlwe_evaluator_->rotate_columns(temp1, *rlwe_galoiskeys_ ,temp2);
    MatrixData matrix_left, matrix_right;
    matrix_left.resize(RLWEParams::poly_modulus_degree, VecData(RLWEParams::poly_modulus_degree/2));
    matrix_right.resize(RLWEParams::poly_modulus_degree, VecData(RLWEParams::poly_modulus_degree/2));
    // split dwt_matrix
    #pragma omp parallel for num_threads(num_th)
    for (int i = 0; i < RLWEParams::poly_modulus_degree; i++)
    {
        if (i < RLWEParams::poly_modulus_degree/2)
        {
            for (int j = 0; j < RLWEParams::poly_modulus_degree/2; j++)
            {
                matrix_left[i][j] = matrix_decode[i][j];
                matrix_right[i][j] = matrix_decode[i][j+RLWEParams::poly_modulus_degree/2];
            }
        }
        else
        {
            for (int j = 0; j < RLWEParams::poly_modulus_degree/2; j++)
            {
                matrix_right[i][j] = matrix_decode[i][j];
                matrix_left[i][j] = matrix_decode[i][j+RLWEParams::poly_modulus_degree/2];
            }
        }
    }
    // std::cout << "left matrix is: " << std::endl;
    // for (size_t i = 0; i < matrix_left.size(); i=i+2048) {
    //     for (size_t j = 0; j < matrix_left[0].size(); j=j+2048) {
    //         std::cout << matrix_left[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    // std::cout << "left matrix is: " << std::endl;
    // for (size_t i = 0; i < print_num; i=i+1) {
    //     for (size_t j = 0; j < print_num; j=j+1) {
    //         std::cout << matrix_left[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    // std::cout << "right matrix is: " << std::endl;
    // for (size_t i = 0; i < matrix_right.size(); i=i+2048) {
    //     for (size_t j = 0; j < matrix_right[0].size(); j=j+2048) {
    //         std::cout << matrix_right[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    // std::cout << "right matrix is: " << std::endl;
    // for (size_t i = 0; i < print_num; i=i+1) {
    //     for (size_t j = 0; j < print_num; j=j+1) {
    //         std::cout << matrix_right[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    if(m_verbose){
        std::cout << "matrix_left.size(): " << matrix_left.size() << std::endl;
        std::cout << "matrix_left[0].size(): " << matrix_left[0].size() << std::endl;
        std::cout << "matrix_right.size(): " << matrix_right.size() << std::endl;
        std::cout << "matrix_right[0].size(): " << matrix_right[0].size() << std::endl;
    }


    // #pragma omp parallel sections
    // {
    //     #pragma omp section
    //     {
    //         LinearTransform(temp1, matrix_left);
    //         std::cout << "LT 1 Done" << std::endl;
    //         std::cout << "temp 1 noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp1) << " bits" << std::endl;
    //     }

    //     #pragma omp section
    //     {
    //         LinearTransform(temp2, matrix_right);
    //         std::cout << "LT 2 Done" << std::endl;
    //         std::cout << "temp 2 noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp2) << " bits" << std::endl;
    //     }
    // }


    LinearTransform(temp1, matrix_left);
    std::cout << "LT 1 Done" << std::endl;
    std::cout <<"temp 1 noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp1) << " bits" << std::endl;
    
    LinearTransform(temp2, matrix_right);
    std::cout << "LT 2 Done" << std::endl;
    std::cout <<"temp 2 noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp2) << " bits" << std::endl;

    rlwe_evaluator_->add(temp1, temp2, octxt);
    std::cout <<"result noise budget: " << rlwe_decryptor_->invariant_noise_budget(octxt) << " bits" << std::endl;
    // std::cout << "LT here" << std::endl;

    return;
}

void Cryptor::CtxtCoeff2Slot(const RLWECipher &ictxt, RLWECipher &octxt) const
{
    // rubbish code
    // // Store NTT element
    // VecData roots_vector;
    // MatrixData dwt_matrix;
    // store_NTT_element(roots_vector, dwt_matrix);
    // Plaintext roots_ptxt;
    // rlwe_batch_encoder_->encode(roots_vector, roots_ptxt);
    // // std::cout << "encode here" << std::endl;
    // // component-wise multiplication
    // RLWECipher temp1, temp2;
    // rlwe_evaluator_->multiply_plain(ictxt, roots_ptxt, temp1);
    // // std::cout << "multiply here" << std::endl;
    // // matrix-vector multiplication
    // rlwe_evaluator_->rotate_columns(temp1, *rlwe_galoiskeys_ ,temp2);
    // MatrixData dwt_left, dwt_right;
    // dwt_left.resize(RLWEParams::poly_modulus_degree, VecData(RLWEParams::poly_modulus_degree/2));
    // dwt_right.resize(RLWEParams::poly_modulus_degree, VecData(RLWEParams::poly_modulus_degree/2));
    // // split dwt_matrix
    // for (int i = 0; i < RLWEParams::poly_modulus_degree; i++)
    // {
    //     if (i < RLWEParams::poly_modulus_degree/2)
    //     {
    //         for (int j = 0; j < RLWEParams::poly_modulus_degree/2; j++)
    //         {
    //             dwt_left[i][j] = dwt_matrix[i][j];
    //             dwt_right[i][j] = dwt_matrix[i][j+RLWEParams::poly_modulus_degree/2];
    //         }
    //     }
    //     else
    //     {
    //         for (int j = 0; j < RLWEParams::poly_modulus_degree/2; j++)
    //         {
    //             dwt_right[i][j] = dwt_matrix[i][j];
    //             dwt_left[i][j] = dwt_matrix[i][j+RLWEParams::poly_modulus_degree/2];
    //         }
    //     }
    // }
    // LinearTransform(temp1, dwt_left);
    // LinearTransform(temp2, dwt_right);
    // rlwe_evaluator_->add(temp1, temp2, octxt);
    // // std::cout << "LT here" << std::endl;

    int print_num = 16;
    MatrixData matrix_encode;

    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    time_start = std::chrono::high_resolution_clock::now();
    // GenDecodeMatrix(matrix_decode);
    GenEncodeMatrix(matrix_encode);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Initialize decode matrix: [" << time_diff.count() << " microseconds]" << std::endl;
    
    // std::cout << "decode matrix is: " << std::endl;
    // for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+2048) {
    //     for (size_t j = 0; j < RLWEParams::poly_modulus_degree; j=j+2048) {
    //         std::cout << matrix_decode[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    // std::cout << "decode matrix is: " << std::endl;
    // for (size_t i = 0; i < print_num; i=i+1) {
    //     for (size_t j = 0; j < print_num; j=j+1) {
    //         std::cout << matrix_decode[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    if(m_verbose){
        std::cout << "matrix_encode.size(): " << matrix_encode.size() << std::endl;
        std::cout << "matrix_encode[0].size(): " << matrix_encode[0].size() << std::endl;
    }

    // for (int i=0; i<RLWEParams::poly_modulus_degree; i++){
    //     for (int j = 0; j<RLWEParams::poly_modulus_degree; j++){
    //         std::cout << "Matrix[" << i << "," << j << "]: " <<  matrix_U_trans[i][j] << " ";
    //     }
    // }
    RLWECipher temp1, temp2;
    temp1 = ictxt;
    rlwe_evaluator_->rotate_columns(temp1, *rlwe_galoiskeys_ ,temp2);
    MatrixData matrix_left, matrix_right;
    matrix_left.resize(RLWEParams::poly_modulus_degree, VecData(RLWEParams::poly_modulus_degree/2));
    matrix_right.resize(RLWEParams::poly_modulus_degree, VecData(RLWEParams::poly_modulus_degree/2));
    // split dwt_matrix
    #pragma omp parallel for num_threads(num_th)
    for (int i = 0; i < RLWEParams::poly_modulus_degree; i++)
    {
        if (i < RLWEParams::poly_modulus_degree/2)
        {
            for (int j = 0; j < RLWEParams::poly_modulus_degree/2; j++)
            {
                matrix_left[i][j] = matrix_encode[i][j];
                matrix_right[i][j] = matrix_encode[i][j+RLWEParams::poly_modulus_degree/2];
            }
        }
        else
        {
            for (int j = 0; j < RLWEParams::poly_modulus_degree/2; j++)
            {
                matrix_right[i][j] = matrix_encode[i][j];
                matrix_left[i][j] = matrix_encode[i][j+RLWEParams::poly_modulus_degree/2];
            }
        }
    }
    // std::cout << "left matrix is: " << std::endl;
    // for (size_t i = 0; i < matrix_left.size(); i=i+2048) {
    //     for (size_t j = 0; j < matrix_left[0].size(); j=j+2048) {
    //         std::cout << matrix_left[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    // std::cout << "left matrix is: " << std::endl;
    // for (size_t i = 0; i < print_num; i=i+1) {
    //     for (size_t j = 0; j < print_num; j=j+1) {
    //         std::cout << matrix_left[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    // std::cout << "right matrix is: " << std::endl;
    // for (size_t i = 0; i < matrix_right.size(); i=i+2048) {
    //     for (size_t j = 0; j < matrix_right[0].size(); j=j+2048) {
    //         std::cout << matrix_right[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    // std::cout << "right matrix is: " << std::endl;
    // for (size_t i = 0; i < print_num; i=i+1) {
    //     for (size_t j = 0; j < print_num; j=j+1) {
    //         std::cout << matrix_right[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    if(m_verbose){
        std::cout << "matrix_left.size(): " << matrix_left.size() << std::endl;
        std::cout << "matrix_left[0].size(): " << matrix_left[0].size() << std::endl;
        std::cout << "matrix_right.size(): " << matrix_right.size() << std::endl;
        std::cout << "matrix_right[0].size(): " << matrix_right[0].size() << std::endl;
    }


    // #pragma omp parallel sections
    // {
    //     #pragma omp section
    //     {
    //         LinearTransform(temp1, matrix_left);
    //         std::cout << "LT 1 Done" << std::endl;
    //         std::cout << "temp 1 noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp1) << " bits" << std::endl;
    //     }

    //     #pragma omp section
    //     {
    //         LinearTransform(temp2, matrix_right);
    //         std::cout << "LT 2 Done" << std::endl;
    //         std::cout << "temp 2 noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp2) << " bits" << std::endl;
    //     }
    // }


    LinearTransform(temp1, matrix_left);
    std::cout << "LT 1 Done" << std::endl;
    std::cout <<"temp 1 noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp1) << " bits" << std::endl;
    
    LinearTransform(temp2, matrix_right);
    std::cout << "LT 2 Done" << std::endl;
    std::cout <<"temp 2 noise budget: " << rlwe_decryptor_->invariant_noise_budget(temp2) << " bits" << std::endl;

    rlwe_evaluator_->add(temp1, temp2, octxt);
    std::cout <<"result noise budget: " << rlwe_decryptor_->invariant_noise_budget(octxt) << " bits" << std::endl;
    // std::cout << "LT here" << std::endl;

    return;
}

void Cryptor::pack_mul_test(RLWECipher &ictxt, const uint64_t &message) const
{
    std::cout << "Sign Noise budget: " << rlwe_decryptor_little_->invariant_noise_budget(ictxt) << " bits" <<std::endl;

    Plaintext ptxt_mul(RLWEParamsLittle::poly_modulus_degree);
    VecData vec_mul(RLWEParamsLittle::poly_modulus_degree, 0ULL);
    encode(vec_mul, ptxt_mul, ParamSet::RLWELittle);
    ptxt_mul.data()[0] = message;
    
    RLWECipher ctxt_temp;
    Plaintext ptxt_temp;
    rlwe_evaluator_little_->multiply_plain(ictxt, ptxt_mul, ctxt_temp);
    decrypt(ctxt_temp, ptxt_temp, ParamSet::RLWELittle);
    std::cout << "Multiply plain result: " << ptxt_temp.data()[0] << std::endl;

    RLWECipher ctxt_mul;
    rlwe_encryptor_little_->encrypt(ptxt_mul, ctxt_mul);
    rlwe_evaluator_little_->multiply_inplace(ictxt, ctxt_mul);
    decrypt(ictxt, ptxt_mul, ParamSet::RLWELittle);
    // std::cout << "Multiply cipher result: " << ptxt_mul.data()[0] << std::endl;
    std::cout << "Final Noise budget: " << rlwe_decryptor_little_->invariant_noise_budget(ictxt) << " bits" <<std::endl;
    return;
}

void Cryptor::S2C_no_Add(const RLWECipher &ictxt, std::vector<LWECipher> &veclwe) const
{
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    auto poly_degree = RLWEParams::poly_modulus_degree;
    Modulus mod_plain(RLWEParams::plain_modulus);
    seal::MatrixData matrix_decode;
    matrix_decode.resize(poly_degree, VecData(poly_degree));
    time_start = std::chrono::high_resolution_clock::now();
    GenDecodeMatrix(matrix_decode);
    std::vector<Plaintext> ptxt_decode;
    ptxt_decode.resize(poly_degree);
    #pragma omp parallel for num_threads(num_th)
    for (int i=0; i<poly_degree; i++){
        ptxt_decode[i].resize(poly_degree);
        ptxt_decode[i].data()[0] = matrix_decode[i][0];
        for(int j=1; j<poly_degree; j++){
            ptxt_decode[i].data()[j] = matrix_decode[i][poly_degree-j];
            ptxt_decode[i].data()[j] = seal::util::negate_uint_mod(ptxt_decode[i].data()[j], mod_plain);
        }
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Initialize decode matrix: [" << time_diff.count() << " microseconds]" << std::endl;


    time_start = std::chrono::high_resolution_clock::now();
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<poly_degree; i++){
        // std::cout << "key switch i: " << i << std::endl;
        RLWECipher ctxt_result(*rlwe_context_);
        rlwe_evaluator_->multiply_plain(ictxt, ptxt_decode[i], ctxt_result);
        if(i==0){
            std::cout << "noise budget of rlwe before extract and after S2C: " << rlwe_decryptor_->invariant_noise_budget(ctxt_result) << " bits" <<std::endl;
        }
        LWECipher lwe_extract, lwe_keyswitch;
        // SampleExtract(ctxt_result,lwe_extract,0,0,ParamSet::RLWE);
        // lwekeyswitch(lwe_extract,lwe_keyswitch);
        // if (i==0){
        //     Plaintext ptxt_result;
        //     decrypt(ctxt_result, ptxt_result);
        //     std::cout <<"S2C result noise budget: " << rlwe_decryptor_->invariant_noise_budget(ctxt_result) << " bits" << std::endl;
        //     VecData vec_result(poly_degree, 0ULL);
        //     decrypt(ictxt, vec_result);
        //     // TODO: LWE keyswitch DEBUG
        //     uint64_t uint_keyswtich = decrypt(lwe_keyswitch, ParamSet::LWE);
        //     std::cout << i << "-th round RLWE result: " << ptxt_result.data()[0]  << " LWE result: " << uint_keyswtich << " golden: " << vec_result[i] << std::endl;
        // }
        // SampleExtract(ctxt_result, veclwe[i], 0, 0);
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "S2C duration: [" << time_diff.count() << " microseconds]" << std::endl;
    
    return;
}

void Cryptor::S2C_no_Add_after_KS(const std::vector<seal::RLWECipher> rlwe_l_vec, std::vector<LWECipher> &veclwe) const
{
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    auto poly_degree = RLWEParams::poly_modulus_degree;
    Modulus mod_plain(RLWEParams::plain_modulus);
    // seal::MatrixData matrix_decode;
    // matrix_decode.resize(poly_degree, VecData(poly_degree));
    // time_start = std::chrono::high_resolution_clock::now();
    // GenDecodeMatrix(matrix_decode);
    // std::vector<std::vector<Plaintext>> ptxt_decode_matrix;
    // ptxt_decode_matrix.resize(poly_degree);
    size_t npoly = RLWEParams::poly_modulus_degree/RLWEParamsLittle::poly_modulus_degree;
    // #pragma omp parallel for num_threads(num_th)
    // for (int i=0; i<poly_degree; i++){
    //     ptxt_decode_matrix[i].resize(npoly);
    // }
    // #pragma omp parallel for num_threads(num_th)
    // for(int i=0; i<poly_degree; i++){
    //     for(int j=0; j<npoly; j++){
    //         Plaintext ptxt_temp(RLWEParamsLittle::poly_modulus_degree);
    //         for(int t=0; t<RLWEParamsLittle::poly_modulus_degree; t++){
    //             if (t==0){
    //                 ptxt_temp.data()[0] = matrix_decode[i][j];
    //                 // std::cout << " ptxt_temp.data()[0] = matrix_decode["<< i << "]["<<j<< "]" << std::endl;
    //             }
    //             else{
    //                 ptxt_temp.data()[RLWEParamsLittle::poly_modulus_degree-t] = matrix_decode[i][t*npoly+j];
    //                 ptxt_temp.data()[RLWEParamsLittle::poly_modulus_degree-t] = seal::util::negate_uint_mod(ptxt_temp.data()[RLWEParamsLittle::poly_modulus_degree-t], mod_plain);
    //                 // std::cout << "ptxt_temp.data()["<<RLWEParamsLittle::poly_modulus_degree-t<<"] = matrix_decode["<<i<<"]["<<t*npoly+j<<"]" << std::endl;
    //             }
    //         }
    //         ptxt_decode_matrix[i][j] = ptxt_temp;
    //     }
    // }
    // time_end = std::chrono::high_resolution_clock::now();
    // time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    // std::cout << "Initialize decode matrix: [" << time_diff.count() << " microseconds]" << std::endl;

    // Do S2C
    std::vector<std::vector<RLWECipher>> ctxt_matrix;
    ctxt_matrix.resize(poly_degree);
    std::vector<RLWECipher> rlwe_result_vec;
    rlwe_result_vec.resize(poly_degree);
    veclwe.resize(poly_degree);
    #pragma omp parallel for num_threads(num_th)
    for (int i=0; i<poly_degree; i++){
        ctxt_matrix[i].resize(npoly);
    }
    
    time_start = std::chrono::high_resolution_clock::now();
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<poly_degree*npoly; i++){
        if(i==0){
            std::cout << "S2C before mul result ";
            print_noise(rlwe_l_vec[i%npoly], ParamSet::RLWELittle);
        }
        size_t row = i/npoly;
        size_t col = i%npoly;
        rlwe_evaluator_little_->multiply_plain(rlwe_l_vec[col], (ptxt_decode_matrix_)[row][col], ctxt_matrix[row][col]);
        if(i==0){
            std::cout << "S2C after mul result ";
            print_noise(ctxt_matrix[i/npoly][i%npoly], ParamSet::RLWELittle);
        }
    }
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<poly_degree; i++){
        std::vector<RLWECipher> rlwe_add_temp;
        rlwe_add_temp.resize(npoly);
        for(int j=0; j<npoly; j++){
            rlwe_add_temp[j] = ctxt_matrix[i][j];
        }
        rlwe_evaluator_little_->add_many(rlwe_add_temp,rlwe_result_vec[i]);
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "S2C duration: [" << time_diff.count() << " microseconds]" << std::endl;

    std::cout << "S2C add result ";
    print_noise(rlwe_result_vec[0], ParamSet::RLWELittle);

    time_start = std::chrono::high_resolution_clock::now();
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<poly_degree; i++){
        // std::cout << "i: " << i << std::endl;
        SampleExtract(rlwe_result_vec[i], veclwe[i], 0, false, seal::ParamSet::LWE);
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Extract duration: [" << time_diff.count() << " microseconds]" << std::endl;
    
    return;
}

void Cryptor::GenS2CPtxt(const size_t idx, Plaintext &ptxt_s2c) const
{
    const auto context_data = rlwe_context_->first_context_data();
    uint64_t root = context_data->plain_ntt_tables()->get_root();
    Modulus mod_plain(RLWEParams::plain_modulus);
    auto poly_degree = RLWEParams::poly_modulus_degree;
    ptxt_s2c.resize(poly_degree);
    Modulus mod_degree(2*poly_degree);
    uint64_t degree_neg;
    util::try_invert_uint_mod(poly_degree, mod_plain, degree_neg);

    Plaintext ptxt_temp(poly_degree);
    uint64_t w_neg_idx = util::sub_uint_mod(2*poly_degree, idx, mod_degree);
    // std::cout << "w_neg_idx: " << w_neg_idx << std::endl;
    w_neg_idx = util::exponentiate_uint_mod(root, w_neg_idx, mod_plain);
    // std::cout << "w_neg_idx: " << w_neg_idx << std::endl;
    ptxt_temp.data()[0] = w_neg_idx;
    // std::cout << "w_neg_idx: " << w_neg_idx << std::endl;
    ptxt_temp.data()[0] = util::multiply_uint_mod(degree_neg, ptxt_temp.data()[0], mod_plain);
    // std::cout << "ptxt_temp.data()[0]: " << ptxt_temp.data()[0] << std::endl;
    for (int i=1; i<poly_degree; i++){
        // std::cout << "i: " << i << std::endl;
        ptxt_temp.data()[i] = util::exponentiate_uint_mod(3, poly_degree-i, mod_degree);
        // std::cout << "ptxt_temp.data()[i]: " << ptxt_temp.data()[i] << std::endl;
        ptxt_temp.data()[i] = util::multiply_uint_mod(ptxt_temp.data()[i], idx, mod_degree);
        // std::cout << "ptxt_temp.data()[i]: " << ptxt_temp.data()[i] << std::endl;
        ptxt_temp.data()[i] = util::sub_uint_mod(2*poly_degree, ptxt_temp.data()[i], mod_degree);
        // std::cout << "ptxt_temp.data()[i]: " << ptxt_temp.data()[i] << std::endl;
        ptxt_temp.data()[i] = util::exponentiate_uint_mod(root, ptxt_temp.data()[i], mod_plain);
        // std::cout << "ptxt_temp.data()[i]: " << ptxt_temp.data()[i] << std::endl;
        ptxt_temp.data()[i] = util::negate_uint_mod(ptxt_temp.data()[i], mod_plain);
        // std::cout << "ptxt_temp.data()[i]: " << ptxt_temp.data()[i] << std::endl;
        ptxt_temp.data()[i] = util::multiply_uint_mod(degree_neg, ptxt_temp.data()[i], mod_plain);
        // std::cout << "ptxt_temp.data()[i]: " << ptxt_temp.data()[i] << std::endl;
    }    

    ptxt_s2c = ptxt_temp;
    std::cout << "Gen Done" << std::endl;
    return;
}

void Cryptor::GenEncodeMatrix(MatrixData& matrix_encode) const
{
    // TODO: Find relation between 2 trans matrix
    // size_t n = RLWEParams::poly_modulus_degree;
    // matrix_U_trans.resize(n, VecData(n)); // resize matrix_U_Trans
	// const auto context_data = rlwe_context_->first_context_data();
    // uint64_t root = context_data->plain_ntt_tables()->get_root(); // root is zeta
    // // uint64_t root = 65529;
    // for (size_t i = 0; i < n/2; i++) // First half of the matrix
    // {
    //     uint64_t zeta_j = seal::util::exponentiate_uint_mod(root, seal::util::exponentiate_uint_mod(3, i, 2*n), rlwe_parms_->plain_modulus());
    //     // uint64_t zeta_j = seal::util::exponentiate_uint_mod(root, 2*i+1, rlwe_parms_->plain_modulus());
    //     if (i==0)
    //         std::cout << "zeta_j: " << zeta_j << std::endl;
    //     for (size_t j = 0; j < n; j++)
    //     {
    //         // Trans Version
    //         // matrix_U_trans[j][i] = seal::util::exponentiate_uint_mod(zeta_j, j, rlwe_parms_->plain_modulus());
    //         // Origin Version
    //         matrix_U_trans[j][i] = seal::util::exponentiate_uint_mod(zeta_j, j, rlwe_parms_->plain_modulus());
    //     }
    // }
    // for (size_t i = n/2; i < n; i++) // Second half of the matrix
    // {
    //     uint64_t zeta_j = seal::util::exponentiate_uint_mod(root, seal::util::exponentiate_uint_mod(3, i - n/2, 2*n), rlwe_parms_->plain_modulus());
    //     // uint64_t zeta_j = seal::util::exponentiate_uint_mod(root, 2*i+1, rlwe_parms_->plain_modulus());
    //     uint64_t zeta_inv;
    //     if (!seal::util::try_invert_uint_mod(zeta_j, rlwe_parms_->plain_modulus(), zeta_inv))
    //     {
    //         // Handle error (zeta_j has no inverse)
    //         std::cout << "zeta_" << i << " has no inverse" << std::endl;
    //         return;
    //     }
    //     for (size_t j = 0; j < n; j++)
    //     {
    //         // Trans Version
    //         // matrix_U_trans[j][i] = seal::util::exponentiate_uint_mod(zeta_inv, j, rlwe_parms_->plain_modulus());
    //         // Origin Version
    //         matrix_U_trans[j][i] = seal::util::exponentiate_uint_mod(zeta_inv, j, rlwe_parms_->plain_modulus());
    //         // matrix_U_trans[i][j] = seal::util::exponentiate_uint_mod(zeta_j, j, rlwe_parms_->plain_modulus());
    //     }
    // }
    // MatrixData matrix_U_trans;
    const auto context_data = rlwe_context_->first_context_data();
    uint64_t root = context_data->plain_ntt_tables()->get_root();
    size_t n = RLWEParams::poly_modulus_degree;
    matrix_encode.resize(n, VecData(n)); 

    // Construct the file path
    // std::string file_path = "TransMatrix/"; 
    std::string file_path = "${workspaceFolder}/TransMatrix/";
    std::string file_name = std::to_string(RLWEParams::poly_modulus_degree) + "_"
                            + std::to_string(RLWEParams::plain_modulus) + "_"
                            + std::to_string(root) + "_matrix_encode.bin";
    file_path += file_name;

    // Check if file already exists
    // std::ifstream in(file_path);
    std::ifstream in(file_path, std::ios::binary);
    if (in.is_open()) // try to read
    {
        // File exists, read its contents to matrix_U_trans
        // std::string line;
        // for (size_t i = 0; i < n && std::getline(in, line); ++i)
        // {
        //     std::istringstream iss(line);
        //     for (size_t j = 0; j < n; ++j)
        //     {
        //         iss >> matrix_encode[i][j];
        //     }
        // }

        for (size_t i = 0; i < n; ++i)
        {
            in.read(reinterpret_cast<char*>(matrix_encode[i].data()), n * sizeof(matrix_encode[i][0]));
        }
        in.close();
        // return; // Exit the function since we've loaded the matrix
    }
    else // then generate
    {
        // If code reaches here, it means file doesn't exist. We generate its content.
        
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < RLWEParams::poly_modulus_degree; i++)
        {
            Plaintext ptxt_extract;
            VecData vec_extract(RLWEParams::poly_modulus_degree, 0ULL);
            vec_extract.data()[i] = 1;
            rlwe_batch_encoder_->encode(vec_extract, ptxt_extract);
            for (int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                matrix_encode[j][i] = ptxt_extract.data()[j];
            }
            vec_extract.data()[i] = 0;
        }

        // Open file for writing
        // std::ofstream out(file_path);
        std::filesystem::path path(file_path);
        if (!std::filesystem::exists(path.parent_path()))
        {
            if (!std::filesystem::create_directories(path.parent_path()))
            {
                std::cerr << "Failed to create directories for path: " << path.parent_path() << std::endl;
                return;
            }
        }
        std::ofstream out(file_path, std::ios::binary);
        if (!out.is_open())
        {
            std::cerr << "Failed to open file for writing: " << file_path << std::endl;
            return;
        }

        // Write the matrix to the file
        // for (size_t i = 0; i < n; ++i)
        // {
        //     std::ostringstream oss;
        //     for (size_t j = 0; j < n; ++j)
        //     {
        //         oss << matrix_encode[i][j];
        //         if (j != n - 1)
        //             oss << " ";
        //     }
        //     out << oss.str() << std::endl;
        // }

        for (size_t i = 0; i < n; ++i)
        {
            out.write(reinterpret_cast<const char*>(matrix_encode[i].data()), n * sizeof(matrix_encode[i][0]));
        }

        // Close the file after writing
        out.close();
    }

    // // // TODO: Then we generate the inverse matrix of matrix_U_trans, called matrix_U_trans_inv
    // // // which means matrix_U_trans * matrix_U_trans_inv is unit matrix
    // MatrixData matrix_U_trans_inv(n, VecData(n));
    // Modulus modulus = RLWEParams::plain_modulus;

    // // Construct the file path
    // std::string file_path_inv = "TransMatrix/";
    // std::string file_path_inv = "PolyGenerator/poly/";
    // std::string file_name_inv = std::to_string(RLWEParams::poly_modulus_degree) + "_"
    //                         + std::to_string(RLWEParams::plain_modulus) + "_"
    //                         + std::to_string(root) + "_matrix_inv.txt";
    // file_path_inv += file_name_inv;

    // std::cout << file_path_inv << std::endl;

    // // Check if file already exists
    // std::ifstream in_inv(file_path_inv);
    // if (in_inv.is_open()) // try to read
    // {
    //     // File exists, read its contents to matrix_U_trans
    //     for (size_t i = 0; i < n; ++i)
    //     {
    //         for (size_t j = 0; j < n; ++j)
    //         {
    //             in_inv >> matrix_U_trans_inv[i][j];
    //         }
    //     }
    //     in_inv.close();
    //     // return; // Exit the function since we've loaded the matrix
    // }
    // else
    // {
    //     // We'll also need a copy of matrix_U_trans for the Gauss-Jordan method
    //     MatrixData temp_matrix = matrix_U_trans;
    //     for (size_t i = 0; i < n; ++i)
    //     {
    //         for (size_t j = 0; j < n; ++j)
    //         {
    //             temp_matrix[i][j] = matrix_U_trans[i][j];
    //         }
    //     }
    //     // Start Gauss-Jordan method for inversion
    //     for (size_t i = 0; i < n; ++i)
    //     {
    //         matrix_U_trans_inv[i][i] = 1;
    //     }

    //     #pragma omp parallel for num_threads(num_th)
    //     for (size_t i = 0; i < n; ++i)
    //     {
    //         std::cout << "i: " << i << std::endl;
    //         // Find the pivot (we assume non-singular matrix)
    //         size_t pivot = i;
    //         for (size_t j = i + 1; j < n; ++j)
    //         {
    //             if (temp_matrix[j][i] != 0)
    //             {
    //                 pivot = j;
    //                 break;
    //             }
    //         }
            
    //         // Swap rows if required
    //         if (pivot != i)
    //         {
    //             temp_matrix[i].swap(temp_matrix[pivot]);
    //             matrix_U_trans_inv[i].swap(matrix_U_trans_inv[pivot]);
    //         }
            
    //         // Get multiplicative inverse of the diagonal entry
    //         // std::uint64_t inv = seal::util::exponentiate_uint_mod(matrix_U_trans[i][i], modulus - 2, modulus); // Fermat's Little Theorem
    //         std::uint64_t inv;
    //         seal::util::try_invert_uint_mod(temp_matrix[i][i], modulus, inv);
    //         // Scale row such that diagonal entry is 1
    //         for (size_t j = 0; j < n; ++j)
    //         {
    //             temp_matrix[i][j] = seal::util::multiply_uint_mod(temp_matrix[i][j], inv, modulus);
    //             matrix_U_trans_inv[i][j] = seal::util::multiply_uint_mod(matrix_U_trans_inv[i][j], inv, modulus);
    //         }

    //         // Eliminate non-zero entries from other rows
    //         for (size_t j = 0; j < n; ++j)
    //         {
    //             if (j != i && temp_matrix[j][i] != 0)
    //             {
    //                 std::uint64_t factor = temp_matrix[j][i];
    //                 for (size_t k = 0; k < n; ++k)
    //                 {
    //                     temp_matrix[j][k] = seal::util::sub_uint_mod(temp_matrix[j][k], seal::util::multiply_uint_mod(factor, temp_matrix[i][k], modulus), modulus);
    //                     matrix_U_trans_inv[j][k] = seal::util::sub_uint_mod(matrix_U_trans_inv[j][k], seal::util::multiply_uint_mod(factor, matrix_U_trans_inv[i][k], modulus), modulus);
    //                     // std::cout << "matrix_U_trans_inv: " << matrix_U_trans_inv[j][k] << " ";
    //                 }
    //             }
    //         }
    //     }

    //     // Open file for writing
    //     std::ofstream out_inv(file_path_inv);
    //     if (!out_inv.is_open())
    //     {
    //         std::cerr << "Failed to open file for writing: " << file_path_inv << std::endl;
    //         return;
    //     }

    //     // Write the matrix to the file
    //     for (size_t i = 0; i < n; ++i)
    //     {
    //         for (size_t j = 0; j < n; ++j)
    //         {
    //             out_inv << matrix_U_trans_inv[i][j];
    //             if (j != n - 1)
    //                 out_inv << " ";
    //         }
    //         out_inv << std::endl;
    //     }

    //     // Close the file after writing
    //     out_inv.close();
    // }
    // // Check if matrix_U_trans * matrix_U_trans_inv is unit matrix
    // for (size_t i = 0; i < n; ++i)
    // {
    //     for (size_t j = 0; j < n; ++j)
    //     {
    //         std::uint64_t sum = 0;
    //         for (size_t k = 0; k < n; ++k)
    //         {
    //             sum = seal::util::add_uint_mod(sum, seal::util::multiply_uint_mod(matrix_U_trans[i][k], matrix_U_trans_inv[k][j], modulus), modulus);
    //         }

    //         if (i == j)
    //         {
    //             // Diagonal should be 1
    //             if (sum != 1)
    //             {
    //                 std::cout << "i: " << i << "j: " << j << std::endl;
    //                 std::cerr << "Inverse matrix generation failed!" << std::endl;
    //                 return;
    //             }
    //         }
    //         else
    //         {
    //             // Off-diagonal should be 0
    //             if (sum != 0)
    //             {
    //                 std::cout << "i: " << i << "j: " << j << std::endl;
    //                 std::cerr << "Inverse matrix generation failed!" << std::endl;
    //                 return;
    //             }
    //         }
    //     }
    // }

    // // matrix_U_trans_inv is now the inverse matrix
    
    return;
}

void Cryptor::GenDecodeMatrix(MatrixData& matrix_decode) const
{
    std::cout << "Generate Decode Matrix" << std::endl;
    const auto context_data = rlwe_context_->first_context_data();
    uint64_t root = context_data->plain_ntt_tables()->get_root();
    size_t n = RLWEParams::poly_modulus_degree;
    matrix_decode.resize(n, VecData(n)); 

    // Construct the file path
    // std::string file_path = "TransMatrix/";
    std::string file_path = "TransMatrix/";
    std::string file_name = std::to_string(RLWEParams::poly_modulus_degree) + "_"
                            + std::to_string(RLWEParams::plain_modulus) + "_"
                            + std::to_string(root) + "_matrix_decode.bin";
    file_path += file_name;


    // Check if file already exists
    // std::ifstream in(file_path);
    std::ifstream in(file_path, std::ios::binary);
    if (in.is_open()) // try to read
    {   

        // File exists, read its contents to matrix_U_trans
        // std::string line;
        // for (size_t i = 0; i < n && std::getline(in, line); ++i)
        // {
        //     std::istringstream iss(line);
        //     for (size_t j = 0; j < n; ++j)
        //     {
        //         iss >> matrix_decode[i][j];
        //     }
        // }

        for (size_t i = 0; i < n; ++i)
        {
            in.read(reinterpret_cast<char*>(matrix_decode[i].data()), n * sizeof(matrix_decode[i][0]));
        }

        in.close();
        // return; // Exit the function since we've loaded the matrix
    }
    else // then generate
    {
        // If code reaches here, it means file doesn't exist. We generate its content.
        
        
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < RLWEParams::poly_modulus_degree; i++)
        {   
            VecData vec_extract(RLWEParams::poly_modulus_degree, 0ULL);
            Plaintext ptxt_extract(RLWEParams::poly_modulus_degree);
            // std::cout << "i: " << i << std::endl;
            for(int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                ptxt_extract.data()[j] = 0;
            }
            ptxt_extract.data()[i] = 1;
            rlwe_batch_encoder_->decode(ptxt_extract, vec_extract);
            for (int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                matrix_decode[j][i] = vec_extract.data()[j];
            }
        }

        // Open file for writing
        // std::ofstream out(file_path);
        std::filesystem::path path(file_path);
        if (!std::filesystem::exists(path.parent_path()))
        {
            if (!std::filesystem::create_directories(path.parent_path()))
            {
                std::cerr << "Failed to create directories for path: " << path.parent_path() << std::endl;
                return;
            }
        }
        std::ofstream out(file_path, std::ios::binary);
        if (!out.is_open())
        {
            std::cerr << "Failed to open file for writing: " << file_path << std::endl;
            return;
        }

        // Write the matrix to the file
        // for (size_t i = 0; i < n; ++i)
        // {
        //     std::ostringstream oss;
        //     for (size_t j = 0; j < n; ++j)
        //     {
        //         oss << matrix_decode[i][j];
        //         if (j != n - 1)
        //             oss << " ";
        //     }
        //     out << oss.str() << std::endl;
        // }

        for (size_t i = 0; i < n; ++i)
        {
            out.write(reinterpret_cast<const char*>(matrix_decode[i].data()), n * sizeof(matrix_decode[i][0]));
        }

        // Close the file after writing
        out.close();
    }


}

void Cryptor::GenNttMatrix(MatrixData& matrix_NTT) const
{

    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    for (int i = 0; i<vec_mod.size(); i++){
        std::cout << i <<"-th modulus is: " << *vec_mod[i].data()  << std::endl;
    }

    const auto context_data = rlwe_context_->first_context_data();
    // uint64_t root = context_data->plain_ntt_tables()->get_root();
    uint64_t root;
    seal::util::try_minimal_primitive_root(2*RLWEParams::poly_modulus_degree, *vec_mod[0].data(), root);
    std::cout << "root: " << root << std::endl;
    size_t n = RLWEParams::poly_modulus_degree;
    matrix_NTT.resize(n, VecData(n)); 

    // Construct the file path
    // std::string file_path = "TransMatrix/";
    std::string file_path = "${workspaceFolder}/TransMatrix/";
    std::string file_name = std::to_string(RLWEParams::poly_modulus_degree) + "_"
                            + std::to_string(*vec_mod[0].data()) + "_"
                            + std::to_string(root) + "_matrix_NTT.bin";
    file_path += file_name;


    // Check if file already exists
    // std::ifstream in(file_path);
    std::ifstream in(file_path, std::ios::binary);
    if (in.is_open()) // try to read
    {   

        for (size_t i = 0; i < n; ++i)
        {
            in.read(reinterpret_cast<char*>(matrix_NTT[i].data()), n * sizeof(matrix_NTT[i][0]));
        }

        in.close();
        // return; // Exit the function since we've loaded the matrix
    }
    else // then generate
    {
        // If code reaches here, it means file doesn't exist. We generate its content.
        // RLWECipher ctxt_extract, ctxt_ntt;
        VecData vec_extract(RLWEParams::poly_modulus_degree, 1ULL);
        
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < RLWEParams::poly_modulus_degree; i++)
        {   
            RLWECipher ctxt_extract, ctxt_ntt;
            encrypt(vec_extract, ctxt_extract);
            rlwe_evaluator_->mod_switch_to_inplace(ctxt_extract, rlwe_context_->last_parms_id());
            // Plaintext ptxt_ntt(RLWEParams::poly_modulus_degree);
            // Plaintext ptxt_extract(RLWEParams::poly_modulus_degree);
            
            for(int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                ctxt_extract.data()[j] = 0;
                // ptxt_ntt.data()[j] = 0;
            }
            // ptxt_extract.data()[i] = 1;
            ctxt_extract.data()[i] = 1;
            rlwe_evaluator_->transform_to_ntt(ctxt_extract, ctxt_ntt);
            // rlwe_batch_encoder_->decode(ptxt_extract, vec_extract);
            for (int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                matrix_NTT[j][i] = ctxt_ntt.data()[j];
            }
        }

        // Open file for writing
        // std::ofstream out(file_path);
        std::filesystem::path path(file_path);
        if (!std::filesystem::exists(path.parent_path()))
        {
            if (!std::filesystem::create_directories(path.parent_path()))
            {
                std::cerr << "Failed to create directories for path: " << path.parent_path() << std::endl;
                return;
            }
        }
        std::ofstream out(file_path, std::ios::binary);
        if (!out.is_open())
        {
            std::cerr << "Failed to open file for writing: " << file_path << std::endl;
            return;
        }

        for (size_t i = 0; i < n; ++i)
        {
            out.write(reinterpret_cast<const char*>(matrix_NTT[i].data()), n * sizeof(matrix_NTT[i][0]));
        }

        // Close the file after writing
        out.close();
    }
    return;

}

void Cryptor::GenNTTMatrixManual(MatrixData& matrix_NTT_manual) const
{
    std::cout << "Gen NTT matrix manually" << std::endl;
    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    Modulus mod = *vec_mod[0].data();
    // for (int i = 0; i<vec_mod.size(); i++){
    //     std::cout << i <<"-th modulus is: " << *vec_mod[i].data()  << std::endl;
    // }

    const auto context_data = rlwe_context_->first_context_data();
    // uint64_t root = context_data->plain_ntt_tables()->get_root();
    uint64_t root;
    seal::util::try_minimal_primitive_root(2*RLWEParams::poly_modulus_degree, mod, root);
    // std::cout << "root: " << root << std::endl;
    size_t n = RLWEParams::poly_modulus_degree;
    matrix_NTT_manual.resize(n, VecData(n)); 

    // Construct the file path
    // std::string file_path = "TransMatrix/";
    std::string file_path = "${workspaceFolder}/TransMatrix/";
    std::string file_name = std::to_string(RLWEParams::poly_modulus_degree) + "_"
                            + std::to_string(mod.value()) + "_"
                            + std::to_string(root) + "_matrix_NTT_manual.bin";
    file_path += file_name;


    // Check if file already exists
    // std::ifstream in(file_path);
    std::ifstream in(file_path, std::ios::binary);
    if (in.is_open()) // try to read
    {   

        for (size_t i = 0; i < n; ++i)
        {
            in.read(reinterpret_cast<char*>(matrix_NTT_manual[i].data()), n * sizeof(matrix_NTT_manual[i][0]));
        }

        in.close();
        // return; // Exit the function since we've loaded the matrix
    }
    else // then generate
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i=0; i<n; i++){
            uint64_t zeta_i = seal::util::exponentiate_uint_mod(root, (2*i+1), mod); 
            for (int j=0; j<n; j++){
                matrix_NTT_manual[i][j] = seal::util::exponentiate_uint_mod(zeta_i, j, mod);
            }
        }

        // Open file for writing
        // std::ofstream out(file_path);
        std::filesystem::path path(file_path);
        if (!std::filesystem::exists(path.parent_path()))
        {
            if (!std::filesystem::create_directories(path.parent_path()))
            {
                std::cerr << "Failed to create directories for path: " << path.parent_path() << std::endl;
                return;
            }
        }
        std::ofstream out(file_path, std::ios::binary);
        if (!out.is_open())
        {
            std::cerr << "Failed to open file for writing: " << file_path << std::endl;
            return;
        }

        for (size_t i = 0; i < n; ++i)
        {
            out.write(reinterpret_cast<const char*>(matrix_NTT_manual[i].data()), n * sizeof(matrix_NTT_manual[i][0]));
        }

        // Close the file after writing
        out.close();
    }
    return;
}

void Cryptor::GenNttRevMatrix(MatrixData& matrix_NTT) const
{

    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    for (int i = 0; i<vec_mod.size(); i++){
        std::cout << i <<"-th modulus is: " << *vec_mod[i].data()  << std::endl;
    }

    const auto context_data = rlwe_context_->first_context_data();
    // uint64_t root = context_data->plain_ntt_tables()->get_root();
    uint64_t root;
    seal::util::try_minimal_primitive_root(2*RLWEParams::poly_modulus_degree, *vec_mod[0].data(), root);
    std::cout << "root: " << root << std::endl;
    size_t n = RLWEParams::poly_modulus_degree;
    matrix_NTT.resize(n, VecData(n)); 

    // Construct the file path
    // std::string file_path = "TransMatrix/";
    std::string file_path = "${workspaceFolder}/TransMatrix/";
    std::string file_name = std::to_string(RLWEParams::poly_modulus_degree) + "_"
                            + std::to_string(*vec_mod[0].data()) + "_"
                            + std::to_string(root) + "_reverse_matrix_NTT.bin";
    file_path += file_name;


    // Check if file already exists
    // std::ifstream in(file_path);
    std::ifstream in(file_path, std::ios::binary);
    if (in.is_open()) // try to read
    {   

        for (size_t i = 0; i < n; ++i)
        {
            in.read(reinterpret_cast<char*>(matrix_NTT[i].data()), n * sizeof(matrix_NTT[i][0]));
        }

        in.close();
        // return; // Exit the function since we've loaded the matrix
    }
    else // then generate
    {
        // If code reaches here, it means file doesn't exist. We generate its content.
        // RLWECipher ctxt_extract, ctxt_ntt;
        VecData vec_extract(RLWEParams::poly_modulus_degree, 1ULL);
        
        #pragma omp parallel for num_threads(num_th)
        for (uint64_t i = 0; i < RLWEParams::poly_modulus_degree; i++)
        {   
            RLWECipher ctxt_extract, ctxt_ntt;
            encrypt(vec_extract, ctxt_extract);
            rlwe_evaluator_->mod_switch_to_inplace(ctxt_extract, rlwe_context_->last_parms_id());
            // Plaintext ptxt_ntt(RLWEParams::poly_modulus_degree);
            // Plaintext ptxt_extract(RLWEParams::poly_modulus_degree);
            
            for(int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                ctxt_extract.data()[j] = 0;
                // ptxt_ntt.data()[j] = 0;
            }
            // ptxt_extract.data()[i] = 1;
            int rev_i = seal::util::reverse_bits(i, RLWEParams::poly_logn+1);
            if (i==1){
                std::cout << "i: " << i << " rev_i: " << rev_i << std::endl;
            }
            ctxt_extract.data()[rev_i-1] = 1;
            rlwe_evaluator_->transform_to_ntt(ctxt_extract, ctxt_ntt);
            // rlwe_batch_encoder_->decode(ptxt_extract, vec_extract);
            for (int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                matrix_NTT[j][i] = ctxt_ntt.data()[j];
            }
        }

        // Open file for writing
        // std::ofstream out(file_path);
        std::filesystem::path path(file_path);
        if (!std::filesystem::exists(path.parent_path()))
        {
            if (!std::filesystem::create_directories(path.parent_path()))
            {
                std::cerr << "Failed to create directories for path: " << path.parent_path() << std::endl;
                return;
            }
        }
        std::ofstream out(file_path, std::ios::binary);
        if (!out.is_open())
        {
            std::cerr << "Failed to open file for writing: " << file_path << std::endl;
            return;
        }

        for (size_t i = 0; i < n; ++i)
        {
            out.write(reinterpret_cast<const char*>(matrix_NTT[i].data()), n * sizeof(matrix_NTT[i][0]));
        }

        // Close the file after writing
        out.close();
    }
    return;

}

void Cryptor::GeniNttMatrix(MatrixData& matrix_iNTT) const
{
    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    for (int i = 0; i<vec_mod.size(); i++){
        std::cout << i <<"-th modulus is: " << *vec_mod[i].data()  << std::endl;
    }

    const auto context_data = rlwe_context_->first_context_data();
    // uint64_t root = context_data->plain_ntt_tables()->get_root();
    uint64_t root;
    seal::util::try_minimal_primitive_root(2*RLWEParams::poly_modulus_degree, *vec_mod[0].data(), root);
    std::cout << "root: " << root << std::endl;
    size_t n = RLWEParams::poly_modulus_degree;
    matrix_iNTT.resize(n, VecData(n)); 

    

    // Construct the file path
    // std::string file_path = "TransMatrix/";
    std::string file_path = "${workspaceFolder}/TransMatrix/";
    std::string file_name = std::to_string(RLWEParams::poly_modulus_degree) + "_"
                            + std::to_string(*vec_mod[0].data()) + "_"
                            + std::to_string(root) + "_matrix_iNTT.bin";
    file_path += file_name;


    // Check if file already exists
    // std::ifstream in(file_path);
    std::ifstream in(file_path, std::ios::binary);
    if (in.is_open()) // try to read
    {   

        for (size_t i = 0; i < n; ++i)
        {
            in.read(reinterpret_cast<char*>(matrix_iNTT[i].data()), n * sizeof(matrix_iNTT[i][0]));
        }

        in.close();
        // return; // Exit the function since we've loaded the matrix
    }
    else // then generate
    {
        // If code reaches here, it means file doesn't exist. We generate its content.
        // #pragma omp parallel for num_threads(num_th)
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < RLWEParams::poly_modulus_degree; i++)
        {   
            // Plaintext ptxt_intt(RLWEParams::poly_modulus_degree);
            // // Plaintext ptxt_extract(RLWEParams::poly_modulus_degree);
            // for(int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            // {
            //     // ptxt_extract.data()[j] = 0;
            //     ptxt_intt.data()[j] = 1;
            // }
            VecData vec_intt(RLWEParams::poly_modulus_degree, 1ULL);
            RLWECipher ctxt_intt;
            encrypt(vec_intt, ctxt_intt);
            rlwe_evaluator_->mod_switch_to_inplace(ctxt_intt, rlwe_context_->last_parms_id());
            rlwe_evaluator_->transform_to_ntt_inplace(ctxt_intt);
            // rlwe_evaluator_->transform_from_ntt_inplace(ctxt_intt);
            for(int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                ctxt_intt.data()[j] = 0;
            }
            ctxt_intt.data()[i] = 1;
            // std::cout << "ctxt_intt.data()[" << i << "]: " << ctxt_intt.data()[i] << " "; 
            // std::cout << i << "-th ctxt: " << std::endl;
            // for (int t=0; t<RLWEParams::poly_modulus_degree; t=t+1){
            //     if(ctxt_intt.data()[t] != 0)
            //         std::cout << t << "ctxt[" << t << "]: " << ctxt_intt.data()[t] << " ";
            // }
            // std::cout << std::endl;
            rlwe_evaluator_->transform_from_ntt_inplace(ctxt_intt);
            // for (int t=0; t<RLWEParams::poly_modulus_degree; t=t+1){
            //     if(ctxt_intt.data()[t] != 0)
            //         std::cout << t << "ctxt[" << t << "]: " << ctxt_intt.data()[t] << " ";
            // }
            // std::cout << i << "-th ctxt intt nothing" << std::endl; 
            for (int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                matrix_iNTT[j][i] = ctxt_intt.data()[j];
            }
        }

        // Open file for writing
        // std::ofstream out(file_path);
        std::filesystem::path path(file_path);
        if (!std::filesystem::exists(path.parent_path()))
        {
            if (!std::filesystem::create_directories(path.parent_path()))
            {
                std::cerr << "Failed to create directories for path: " << path.parent_path() << std::endl;
                return;
            }
        }
        std::ofstream out(file_path, std::ios::binary);
        if (!out.is_open())
        {
            std::cerr << "Failed to open file for writing: " << file_path << std::endl;
            return;
        }

        for (size_t i = 0; i < n; ++i)
        {
            out.write(reinterpret_cast<const char*>(matrix_iNTT[i].data()), n * sizeof(matrix_iNTT[i][0]));
        }

        // Close the file after writing
        out.close();
    }

    return;
}

void Cryptor::GeniNTTMatrixManual(MatrixData& matrix_iNTT_manual) const
{
    std::cout << "Gen iNTT matrix manually" << std::endl;
    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    Modulus mod = *vec_mod[0].data();
    // for (int i = 0; i<vec_mod.size(); i++){
    //     std::cout << i <<"-th modulus is: " << *vec_mod[i].data()  << std::endl;
    // }

    const auto context_data = rlwe_context_->first_context_data();
    // uint64_t root = context_data->plain_ntt_tables()->get_root();
    uint64_t root;
    seal::util::try_minimal_primitive_root(2*RLWEParams::poly_modulus_degree, mod, root);
    // std::cout << "root: " << root << std::endl;
    size_t n = RLWEParams::poly_modulus_degree;
    matrix_iNTT_manual.resize(n, VecData(n)); 

    // Construct the file path
    // std::string file_path = "TransMatrix/";
    std::string file_path = "${workspaceFolder}/TransMatrix/";
    std::string file_name = std::to_string(RLWEParams::poly_modulus_degree) + "_"
                            + std::to_string(mod.value()) + "_"
                            + std::to_string(root) + "_matrix_iNTT_manual.bin";
    file_path += file_name;


    // Check if file already exists
    // std::ifstream in(file_path);
    std::ifstream in(file_path, std::ios::binary);
    if (in.is_open()) // try to read
    {   

        for (size_t i = 0; i < n; ++i)
        {
            in.read(reinterpret_cast<char*>(matrix_iNTT_manual[i].data()), n * sizeof(matrix_iNTT_manual[i][0]));
        }

        in.close();
        // return; // Exit the function since we've loaded the matrix
    }
    else // then generate
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i=0; i<n; i++){
            uint64_t zeta_i = seal::util::exponentiate_uint_mod(root, (2*i+1), mod); 
            for (int j=0; j<n; j++){
                // Attention: Here is transpose if consider the whole matix
                // Otherwise is component-wise inverse
                matrix_iNTT_manual[j][i] = seal::util::exponentiate_uint_mod(zeta_i, j, mod);
                seal::util::try_invert_uint_mod(matrix_iNTT_manual[j][i], mod, matrix_iNTT_manual[j][i]);
            }
        }

        // Open file for writing
        // std::ofstream out(file_path);
        std::filesystem::path path(file_path);
        if (!std::filesystem::exists(path.parent_path()))
        {
            if (!std::filesystem::create_directories(path.parent_path()))
            {
                std::cerr << "Failed to create directories for path: " << path.parent_path() << std::endl;
                return;
            }
        }
        std::ofstream out(file_path, std::ios::binary);
        if (!out.is_open())
        {
            std::cerr << "Failed to open file for writing: " << file_path << std::endl;
            return;
        }

        for (size_t i = 0; i < n; ++i)
        {
            out.write(reinterpret_cast<const char*>(matrix_iNTT_manual[i].data()), n * sizeof(matrix_iNTT_manual[i][0]));
        }

        // Close the file after writing
        out.close();
    }
    return;
}

void Cryptor::GeniNttRevMatrix(MatrixData& matrix_iNTT) const
{
    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    for (int i = 0; i<vec_mod.size(); i++){
        std::cout << i <<"-th modulus is: " << *vec_mod[i].data()  << std::endl;
    }

    const auto context_data = rlwe_context_->first_context_data();
    // uint64_t root = context_data->plain_ntt_tables()->get_root();
    uint64_t root;
    seal::util::try_minimal_primitive_root(2*RLWEParams::poly_modulus_degree, *vec_mod[0].data(), root);
    std::cout << "root: " << root << std::endl;
    size_t n = RLWEParams::poly_modulus_degree;
    matrix_iNTT.resize(n, VecData(n)); 

    

    // Construct the file path
    // std::string file_path = "TransMatrix/";
    std::string file_path = "${workspaceFolder}/TransMatrix/";
    std::string file_name = std::to_string(RLWEParams::poly_modulus_degree) + "_"
                            + std::to_string(*vec_mod[0].data()) + "_"
                            + std::to_string(root) + "_reverse_matrix_iNTT.bin";
    file_path += file_name;


    // Check if file already exists
    // std::ifstream in(file_path);
    std::ifstream in(file_path, std::ios::binary);
    if (in.is_open()) // try to read
    {   

        for (size_t i = 0; i < n; ++i)
        {
            in.read(reinterpret_cast<char*>(matrix_iNTT[i].data()), n * sizeof(matrix_iNTT[i][0]));
        }

        in.close();
        // return; // Exit the function since we've loaded the matrix
    }
    else // then generate
    {
        // If code reaches here, it means file doesn't exist. We generate its content.
        // #pragma omp parallel for num_threads(num_th)
        #pragma omp parallel for num_threads(num_th)
        for (uint64_t i = 0; i < RLWEParams::poly_modulus_degree; i++)
        {   
            // Plaintext ptxt_intt(RLWEParams::poly_modulus_degree);
            // // Plaintext ptxt_extract(RLWEParams::poly_modulus_degree);
            // for(int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            // {
            //     // ptxt_extract.data()[j] = 0;
            //     ptxt_intt.data()[j] = 1;
            // }
            VecData vec_intt(RLWEParams::poly_modulus_degree, 1ULL);
            RLWECipher ctxt_intt;
            encrypt(vec_intt, ctxt_intt);
            rlwe_evaluator_->mod_switch_to_inplace(ctxt_intt, rlwe_context_->last_parms_id());
            rlwe_evaluator_->transform_to_ntt_inplace(ctxt_intt);
            // rlwe_evaluator_->transform_from_ntt_inplace(ctxt_intt);
            for(int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                ctxt_intt.data()[j] = 0;
            }
            int rev_i = seal::util::reverse_bits(i, RLWEParams::poly_logn+1);
            ctxt_intt.data()[rev_i-1] = 1;
            // std::cout << "ctxt_intt.data()[" << i << "]: " << ctxt_intt.data()[i] << " "; 
            // std::cout << i << "-th ctxt: " << std::endl;
            // for (int t=0; t<RLWEParams::poly_modulus_degree; t=t+1){
            //     if(ctxt_intt.data()[t] != 0)
            //         std::cout << t << "ctxt[" << t << "]: " << ctxt_intt.data()[t] << " ";
            // }
            // std::cout << std::endl;
            rlwe_evaluator_->transform_from_ntt_inplace(ctxt_intt);
            // for (int t=0; t<RLWEParams::poly_modulus_degree; t=t+1){
            //     if(ctxt_intt.data()[t] != 0)
            //         std::cout << t << "ctxt[" << t << "]: " << ctxt_intt.data()[t] << " ";
            // }
            // std::cout << i << "-th ctxt intt nothing" << std::endl; 
            for (int j = 0; j < RLWEParams::poly_modulus_degree; j++)
            {
                matrix_iNTT[j][i] = ctxt_intt.data()[j];
            }
        }

        // Open file for writing
        // std::ofstream out(file_path);
        std::filesystem::path path(file_path);
        if (!std::filesystem::exists(path.parent_path()))
        {
            if (!std::filesystem::create_directories(path.parent_path()))
            {
                std::cerr << "Failed to create directories for path: " << path.parent_path() << std::endl;
                return;
            }
        }
        std::ofstream out(file_path, std::ios::binary);
        if (!out.is_open())
        {
            std::cerr << "Failed to open file for writing: " << file_path << std::endl;
            return;
        }

        for (size_t i = 0; i < n; ++i)
        {
            out.write(reinterpret_cast<const char*>(matrix_iNTT[i].data()), n * sizeof(matrix_iNTT[i][0]));
        }

        // Close the file after writing
        out.close();
    }

    return;
}

Modulus Cryptor::get_first_modulus() const
{
    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    return Modulus(*vec_mod[0].data());
}

void Cryptor::ModSwitchLWE(const LWECipher &ilwe, const uint64_t &dest_plain, const uint64_t &dest_mod, LWECipher &olwe) const
{
    // Warning: now restrict to LWE from RLWELittle -> Extract

    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    size_t lwe_n = seal::LWEParams::poly_modulus_degree;
    olwe.resize(lwe_n + 1);
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();    
    Modulus mod_coeff = *vec_mod[0].data();
    Modulus mod_dest_mod(dest_mod);
    Modulus mod_plain(seal::LWEParams::plain_modulus);
    Modulus mod_dest_plain(dest_plain);
    double scale = ( (double) mod_dest_mod.value() * (double) mod_plain.value() ) / ( (double) mod_coeff.value() * (double) mod_dest_plain.value() );
    // std::cout << "ModSwitch scale: " << scale << std::endl;
    // double scale = ( (double) mod_dest_mod.value() ) / ( (double) mod_coeff.value() );
    // uint64_t scale = std::round(scale_inner);
    // std::cout << "dest modulus: " << mod_dest_mod.value() << " dest plain: " << mod_dest_plain.value() << " scale: " << scale << std::endl;     
    // std::cout << "dest modulus: " << mod_dest_mod.value() << " scale: " << scale << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    // const uint64_t factor = 1e9;
    // #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<lwe_n+1; i++){
        // if(i<10) std::cout << i << "-th ilwe: " << ilwe[i] << " ";
        // olwe[i] = std::round(  (double) ilwe[i] / (double) scale );
        // olwe[i] = (2 * ilwe[i] + scale) / (2 * scale);
        // olwe[i] = static_cast<uint64_t>(round(static_cast<long double>(ilwe[i]) / scale));
        olwe[i] = static_cast<uint64_t>(round(static_cast<long double>(ilwe[i]) * scale));
        // if(i<10) std::cout << i << "-th olwe: " << olwe[i] << std::endl;
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    // std::cout << "ModSwitch Done [" << time_diff.count() << " microseconds]" << std::endl;


    // // find closest prime number
    // std::vector<Modulus> vec_mod_30;
    // size_t mod_number = 1;
    // vec_mod_30.resize(mod_number);
    // vec_mod_30 = util::get_primes(2*lwe_n, 21, mod_number);
    // for(int i=0; i<mod_number; i++){
    //     std::cout << i << "-th prime: " << *vec_mod_30[i].data() << std::endl;
    // }

    // find qulified prime number
    // int bit_size = 20;
    // uint64_t lower_bound = uint64_t(0x1) << (bit_size - 1);
    // std::cout << "lower bound: " << lower_bound << std::endl;
    // // uint64_t factor = 2 * RLWEParamsLittle::poly_modulus_degree;
    // uint64_t factor = 2 * 32768;
    // std::cout << "factor: " << factor << std::endl;
    // uint64_t value = ((uint64_t(0x1) << bit_size) - 1) / factor * factor + 1;
    // std::cout << "Initial value: " << value << std::endl; 
    // while (value > lower_bound)
    // {
    //     std::cout << "Now value: " << value << std::endl;
    //     Modulus new_mod(value);
    //     if (new_mod.is_prime())
    //     {
    //         std::cout << "Find value: " << value << std::endl;
    //     }
    //     value -= factor;
    // }
    


    return;
}

void Cryptor::NoiseAnal() const{

    size_t print_length = 16;

    std::cout << "================" << std::endl;

    size_t N = RLWEParamsLittle::poly_modulus_degree;
    VecData vec_test(N, 1ULL);
    RLWECipher rlwe_test;
    encrypt(vec_test, rlwe_test, ParamSet::RLWELittle);
    std::cout << "Encryption " << " ";
    print_noise(rlwe_test, ParamSet::RLWELittle);
    rlwe_evaluator_little_->square_inplace(rlwe_test);
    std::cout << "Square " << " ";
    print_noise(rlwe_test, ParamSet::RLWELittle);

    std::cout << "================" << std::endl;

    auto &context_data = *rlwe_context_little_->get_context_data(rlwe_test.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    auto &plain_modulus = parms.plain_modulus();
    std::cout << plain_modulus.value() << std::endl;
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.poly_modulus_degree();
    auto ntt_tables = context_data.small_ntt_tables();
    size_t encrypted_size = rlwe_pubkey_->data().size();
    scheme_type type = parms.scheme();

    auto prng = parms.random_generator()->create();

    // Generate u <-- R_3
    auto u(util::allocate_poly(coeff_count, coeff_modulus_size, *pool_));
    util::sample_poly_ternary(prng, parms, u.get());
    // std::cout << "print u <-- R_3" << std::endl;
    // for(int i=0; i<print_length; i++){
    //     std::cout << u[i] << std::endl;
    // }

    // Generate e_j <-- chi
    util::SEAL_NOISE_SAMPLER(prng, parms, u.get());
    util::RNSIter gaussian_iter(u.get(), coeff_count);
    // std::cout << "print u <-- chi" << std::endl;
    // for(int i=0; i<print_length; i++){
    //     std::cout << u[i] << std::endl;
    // }
    

    return;
}


// TFHE Part
void Cryptor::SampleExtract(const RLWECipher &rlwe, LWECipher &lwe, const size_t idx, const bool mod_switch, const ParamSet paramset) const
{

    if (paramset ==  ParamSet::LWE){
        auto poly_modulus_degree = LWEParams::poly_modulus_degree;
        auto coeff_modulus_size = LWEParams::coeff_modulus_size;
        
        RLWECipher temp(rlwe);
        if (mod_switch) {
            // TODO: modswitch to the LWEParams::coeff_modulus_size level
            rlwe_evaluator_->mod_switch_to_inplace(temp, rlwe_context_->last_parms_id());
            //  TODO: Keyswitch required
            // poly_modulus_degree = LWEParams::poly_modulus_degree;
            coeff_modulus_size = temp.coeff_modulus_size();
        }
        if (temp.is_ntt_form()) {
            if (mod_switch)
                rlwe_evaluator_->transform_from_ntt_inplace(temp);
            else
                util::inverse_ntt_negacyclic_harvey(temp, 2, lwe_context_->first_context_data()->small_ntt_tables());
        }
        lwe.resize(coeff_modulus_size * (poly_modulus_degree + 1));
        for (size_t i = 0; i < coeff_modulus_size; i++) {
            lwe[(poly_modulus_degree + 1) * i] = temp.data(0)[i * poly_modulus_degree + idx];
            for (size_t j = 0; j <= idx; j++)
                lwe[(poly_modulus_degree + 1) * i + 1 + j] = temp.data(1)[poly_modulus_degree * i + idx - j];
            for (size_t j = idx + 1; j < poly_modulus_degree; j++)
                lwe[(poly_modulus_degree + 1) * i + 1 + j] = rlwe_parms_->coeff_modulus()[i].value() - temp.data(1)[poly_modulus_degree * (i + 1) + idx - j];
        }

    }
    else if(paramset == ParamSet::RLWE){
        auto poly_modulus_degree = rlwe.poly_modulus_degree();
        auto coeff_modulus_size = rlwe.coeff_modulus_size();
        RLWECipher temp(rlwe);
        if (mod_switch) {
            // TODO: modswitch to the LWEParams::coeff_modulus_size level
            rlwe_evaluator_->mod_switch_to_inplace(temp, rlwe_context_->last_parms_id());
            //  TODO: Keyswitch required
            // poly_modulus_degree = LWEParams::poly_modulus_degree;
            coeff_modulus_size = temp.coeff_modulus_size();
        }
        if (temp.is_ntt_form()) {
            if (mod_switch)
                rlwe_evaluator_->transform_from_ntt_inplace(temp);
            else
                util::inverse_ntt_negacyclic_harvey(temp, 2, lwe_context_->first_context_data()->small_ntt_tables());
        }
        lwe.resize(coeff_modulus_size * (poly_modulus_degree + 1));
        for (size_t i = 0; i < coeff_modulus_size; i++) {
            lwe[(poly_modulus_degree + 1) * i] = temp.data(0)[i * poly_modulus_degree + idx];
            for (size_t j = 0; j <= idx; j++)
                lwe[(poly_modulus_degree + 1) * i + 1 + j] = temp.data(1)[poly_modulus_degree * i + idx - j];
            for (size_t j = idx + 1; j < poly_modulus_degree; j++)
                lwe[(poly_modulus_degree + 1) * i + 1 + j] = rlwe_parms_->coeff_modulus()[i].value() - temp.data(1)[poly_modulus_degree * (i + 1) + idx - j];
        }

    }
    else {
        std::cout << "Should be RLWE or LWE" << std::endl;
        return;
    }

    

    return;
}

void Cryptor::vecSampleExtract(const RLWECipher &rlwe, std::vector<LWECipher> &vec_lwe, const ParamSet paramset) const
{
    // extract all coefficient of rlwe
    vec_lwe.resize(rlwe.poly_modulus_degree());
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<rlwe.poly_modulus_degree(); i++){
        SampleExtract(rlwe, vec_lwe[i], i, false, paramset);
    }

    return;
}

void Cryptor::LWEtoRLWE(const LWECipher &lwe, RLWECipher &rlwe) const
{   
    // Debug
    // std::vector<Modulus> vec_lwe_mod = lwe_parms_->coeff_modulus();

    auto poly_modulus_degree = rlwe.poly_modulus_degree(); 
    auto coeff_modulus_size = rlwe.coeff_modulus_size();

    // std::cout << "poly_modulus_degree: " << poly_modulus_degree << std::endl;
    // std::cout << "coeff_modulus_size: " << coeff_modulus_size << std::endl;

    // Debug
    // std::cout << "LWE modulus:" << std::endl;
    // for (int i=0; i<coeff_modulus_size; i++){
    //     std::cout << *vec_lwe_mod[i].data() << " ";
    // }
    // std::cout << std::endl;

    rlwe.resize(2);
    // #pragma omp parallel for num_threads(num_th)
    for (size_t i = 0; i < coeff_modulus_size; i++) {
        rlwe.data(0)[poly_modulus_degree * i] = lwe[i * (poly_modulus_degree + 1)];
        // DEBUG
        // if(rlwe.data(0)[poly_modulus_degree * i]>=rlwe_parms_->coeff_modulus()[i].value()){
        //     std::cout << poly_modulus_degree * i << "-th: " << rlwe.data(0)[poly_modulus_degree * i] << std::endl;
        // }
        rlwe.data(1)[poly_modulus_degree * i] = lwe[i * (poly_modulus_degree + 1) + 1];
        // DEBUG
        // if(rlwe.data(1)[poly_modulus_degree * i]>=rlwe_parms_->coeff_modulus()[i].value()){
        //     std::cout << poly_modulus_degree * i << "-th: " << rlwe.data(1)[poly_modulus_degree * i] << std::endl;
        // }
        for (size_t j = 1; j < poly_modulus_degree; j++){
            if(lwe[(i + 1) * (poly_modulus_degree + 1) - j] != 0)
                rlwe.data(1)[poly_modulus_degree * i + j] = rlwe_parms_->coeff_modulus()[i].value() - lwe[(i + 1) * (poly_modulus_degree + 1) - j];
            // DEBUG
            // if(rlwe.data(1)[poly_modulus_degree * i + j]>=rlwe_parms_->coeff_modulus()[i].value()){
            //     std::cout << poly_modulus_degree * i + j << "-th: " << rlwe.data(1)[poly_modulus_degree * i + j] << std::endl;
            // }
        }
    }

    return;
}

void Cryptor::generate_lweswitchkeys(void) const
{
    SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey, RLWEParams::poly_modulus_degree, *pool_)
    std::copy_n(rlwe_seckey_->data().data(), RLWEParams::poly_modulus_degree, (uint64_t *)inv_seckey);
    util::inverse_ntt_negacyclic_harvey(inv_seckey, rlwe_context_->first_context_data()->small_ntt_tables()[0]);
    // Plaintext subkey(LWEParams::poly_modulus_degree);
    SecretKey new_key;
    new_key.data().resize(util::mul_safe(LWEParams::poly_modulus_degree, LWEParams::coeff_modulus_size));
    // SEAL_ALLOCATE_GET_RNS_ITER(new_key, LWEParams::poly_modulus_degree, LWEParams::coeff_modulus_size, *pool_)
    lweswitchkey_->reserve(LWEParams::npoly);
    auto &coeff_modulus = lwe_context_->first_context_data()->parms().coeff_modulus();
    for (size_t i = 0; i < LWEParams::npoly; i++) {
        RLevCipher temp_key;
        for (size_t j = 0; j < LWEParams::coeff_modulus_size; j++)
            std::copy_n(inv_seckey + LWEParams::poly_modulus_degree * i, LWEParams::poly_modulus_degree, new_key.data().data() + LWEParams::poly_modulus_degree * j);
        util::ntt_negacyclic_harvey(util::RNSIter(new_key.data().data(), LWEParams::poly_modulus_degree), LWEParams::coeff_modulus_size, lwe_context_->first_context_data()->small_ntt_tables());
        encrypt(util::RNSIter(new_key.data().data(), LWEParams::poly_modulus_degree), temp_key, ParamSet::LWE);
        lweswitchkey_->emplace_back(temp_key);
    }
}

void Cryptor::generate_rlwe_switchkeys_arbitary(void) const
{
    size_t print_length = 8;
    size_t npoly = RLWEParamsLittle::npoly;
    size_t poly_degree = RLWEParams::poly_modulus_degree;
    // size_t d_lev = RLWEParamsLittle::decompose_level;
    // std::cout << "decompose level: " << d_lev << std::endl;
    size_t l_poly_degree = RLWEParamsLittle::poly_modulus_degree;
    // size_t d_base = RLWEParamsLittle::decompose_log_base;
    // std::cout << "decompose base: " << d_base << std::endl;
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();
    std::vector<Modulus> long_vec_mod = rlwe_parms_->coeff_modulus();
    Modulus mod_coeff_first(*vec_mod[0].data());
    size_t mod_count = vec_mod.size()<3? 1:vec_mod.size() - 1;

    SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey,poly_degree, *pool_);
    std::copy_n(rlwe_seckey_->data().data(), poly_degree, (uint64_t *)inv_seckey);
    util::inverse_ntt_negacyclic_harvey(inv_seckey, rlwe_context_->first_context_data()->small_ntt_tables()[0]);

    //DEBUG
    // Print Original RLWE key
    // util::print_example_banner("Origianl rlwe key");
    // for(int x=0; x<poly_degree; x++){
    //     std::cout << "[" << x << "]" << inv_seckey[x] << " ";
    // }
    // std::cout << std::endl;
    
    rlweswitchkey_->reserve(npoly);
    
    for (int i=0; i<npoly; i++){
        RLevCipher temp_rlev;
        // temp_rlev.resize(d_lev);
        temp_rlev.resize(1); // we no more need to decompose
        // for (int j=0; j<(d_lev); j++){
        for (int j=0; j<(1); j++){
            // uint64_t B = ( (uint64_t) 1<<(d_base*j) );

            // we should handle in rns form, with differen modulus number
            // first we generate ciphertext encrypt zero plaintext
            RLWECipher temp_rlwe(*rlwe_context_little_);
            Plaintext zero_ptxt(l_poly_degree);
            VecData zero_vec(l_poly_degree, 0ULL);
            rlwe_batch_encoder_little_->encode(zero_vec, zero_ptxt);
            for (int t=0; t<l_poly_degree; t++){
                zero_ptxt.data()[t] = 0;
            }
            rlwe_encryptor_little_->encrypt(zero_ptxt, temp_rlwe);

            // DEBUG
            // We Mannually set zero?
            for(int x=0; x<l_poly_degree*mod_count; x++){
                temp_rlwe.data(0)[x] = 0;
                temp_rlwe.data(1)[x] = 0;
            }

            //DEBUG
            // we print the content of zero ciphertext
            // util::print_example_banner("Initialize Zero Ciphertext");
            // std::cout << "RLWE[0]: ";
            // for(int x=0; x<l_poly_degree*mod_count; x++){
            //     std::cout << "[" << x << "]" << temp_rlwe.data(0)[x] << " ";
            // }
            // std::cout << std::endl;

            // std::cout << "RLWE[1]: ";
            // for(int x=0; x<l_poly_degree*mod_count; x++){
            //     std::cout << "[" << x << "]" << temp_rlwe.data(1)[x] << " ";
            // }
            // std::cout << std::endl;

            for (int k=0; k<mod_count; k++){
                
                Modulus mod_coeff_now(*vec_mod[k].data());

                // copy s_t with t-th prime modulus
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_key, l_poly_degree, *pool_);
                for (int t=0; t<l_poly_degree; t++){
                    if(inv_seckey[t*npoly+i] == (mod_coeff_first.value()-1)){
                        temp_key[t] = mod_coeff_now.value() - 1; // -1 element
                    }
                    else{
                        temp_key[t] = inv_seckey[t*npoly+i]; // 1,0 element
                    }
                }

                // DEBUG
                // util::print_example_banner(std::to_string(k) + "-th Extract Key");
                // std::cout << "Now mod: " << vec_mod[k].value() << std::endl;
                // std::cout << k << "-th Extract key: ";
                // for(int x=0; x<poly_degree; x++){
                //     std::cout << "[" << x << "]" << temp_key[x] << " ";
                // }
                // std::cout << std::endl;

                // compute scaled s_t
                // for (int t=0; t<l_poly_degree; t++){
                //     temp_key[t] = util::multiply_uint_mod(temp_key[t], B, mod_coeff_now);
                // }

                // add scaled s_t to zero-ciphertext
                for (int t=0; t<l_poly_degree; t++){
                    temp_rlwe.data(0)[t+k*l_poly_degree] =  util::add_uint_mod(temp_rlwe.data(0)[t+k*l_poly_degree], temp_key[t], mod_coeff_now);
                }

                //DEBUG
                // util::print_example_banner("Add " + std::to_string(k) + " -th key to Zero Ciphertext");
                // std::cout << "RLWE[0]: ";
                // for(int x=0; x<poly_degree*mod_count; x++){
                //     std::cout << "[" << x << "]" << temp_rlwe.data(0)[x] << " ";
                // }
                // std::cout << std::endl;

                // std::cout << "RLWE[1]: ";
                // for(int x=0; x<poly_degree*mod_count; x++){
                //     std::cout << "[" << x << "]" << temp_rlwe.data(1)[x] << " ";
                // }
                // std::cout << std::endl;

            }

        //     // we done all rns operation
            temp_rlev[j] = temp_rlwe;

        }
        rlweswitchkey_->emplace_back(temp_rlev);
    }
    return;
}

void Cryptor::generate_rlwe_switchkeys_arbitary_trash(void) const
{
    size_t print_length = 8;
    size_t npoly = RLWEParamsLittle::npoly;
    size_t poly_degree = RLWEParams::poly_modulus_degree;
    size_t d_lev = RLWEParamsLittle::decompose_level;
    std::cout << "decompose level: " << d_lev << std::endl;
    size_t l_poly_degree = RLWEParamsLittle::poly_modulus_degree;
    size_t d_base = RLWEParamsLittle::decompose_log_base;
    std::cout << "decompose base: " << d_base << std::endl;
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();
    std::vector<Modulus> long_vec_mod = rlwe_parms_->coeff_modulus();
    Modulus mod_coeff_first(*vec_mod[0].data());
    size_t mod_count = vec_mod.size()<3? 1:vec_mod.size() - 1;

    SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey,poly_degree, *pool_);
    std::copy_n(rlwe_seckey_->data().data(), poly_degree, (uint64_t *)inv_seckey);
    util::inverse_ntt_negacyclic_harvey(inv_seckey, rlwe_context_->first_context_data()->small_ntt_tables()[0]);
    

    rlweswitchkey_->reserve(npoly);
    
    for (int i=0; i<npoly; i++){
        RLevCipher temp_rlev;
        temp_rlev.resize(d_lev);
        for (int j=0; j<(d_lev); j++){
            uint64_t B = ( (uint64_t) 1<<(d_base*j) );

            // we should handle in rns form, with differen modulus number
            // first we generate ciphertext encrypt zero plaintext
            RLWECipher temp_rlwe(*rlwe_context_little_);
            Plaintext zero_ptxt(l_poly_degree);
            VecData zero_vec(l_poly_degree, 0ULL);
            rlwe_batch_encoder_little_->encode(zero_vec, zero_ptxt);
            for (int t=0; t<l_poly_degree; t++){
                zero_ptxt.data()[t] = 0;
            }
            rlwe_encryptor_little_->encrypt(zero_ptxt, temp_rlwe);

            for (int k=0; k<mod_count; k++){
                
                Modulus mod_coeff_now(*vec_mod[k].data());

                // copy s_t with t-th prime modulus
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_key, l_poly_degree, *pool_);
                for (int t=0; t<l_poly_degree; t++){
                    if(inv_seckey[t*npoly+i] == (mod_coeff_first.value()-1)){
                        temp_key[t] = mod_coeff_now.value() - 1; // -1 element
                    }
                    else{
                        temp_key[t] = inv_seckey[t*npoly+i]; // 1,0 element
                    }
                }

                // compute scaled s_t
                for (int t=0; t<l_poly_degree; t++){
                    temp_key[t] = util::multiply_uint_mod(temp_key[t], B, mod_coeff_now);
                }

                // add scaled s_t to zero-ciphertext
                for (int t=0; t<l_poly_degree; t++){
                    temp_rlwe.data(0)[t+k*l_poly_degree] =  util::add_uint_mod(temp_rlwe.data(0)[t+k*l_poly_degree], temp_key[t], mod_coeff_now);
                }

            }

            // we done all rns operation
            temp_rlev[j] = temp_rlwe;

        }
        rlweswitchkey_->emplace_back(temp_rlev);
    }
    return;
}

void Cryptor::rns_add_test(void) const
{   
    size_t print_length = 8;
    size_t N = RLWEParamsLittle::poly_modulus_degree;
    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    size_t mod_count = RLWEParamsLittle::coeff_modulus_size<3?1:RLWEParamsLittle::coeff_modulus_size-1;
    Plaintext ptxt_test(N);
    for(int i=0; i<N; i++){
        ptxt_test.data()[i] = 0;
    }
    std::cout << "original data: ";
    for(int i=0; i<print_length; i++){
        std::cout << ptxt_test.data()[i] << " ";
    }
    std::cout << std::endl;

    RLWECipher ctxt_test(*rlwe_context_);
    encrypt(ptxt_test, ctxt_test, ParamSet::RLWELittle);
    Modulus mod_plain(RLWEParamsLittle::plain_modulus);

    for(int i=0; i<1; i++){
        Modulus mod_now(*vec_mod[i].data());
        std::cout << i << "-th modulus " << mod_now.value() << " with " << std::log2(mod_now.value()) << " bits" << std::endl;
        uint64_t scale = mod_now.value() / mod_plain.value();
        std::cout << "scale is " << scale << std::endl;
        uint64_t bias = util::multiply_uint_mod(1, scale, mod_now);
        for(int j=0; j<N; j++){
            ctxt_test.data(0)[j + i * N] = util::add_uint_mod(ctxt_test.data(0)[j + i * N], bias, mod_now);
        }
    }

    Plaintext ptxt_result(N);
    decrypt(ctxt_test, ptxt_result, ParamSet::RLWELittle);
    std::cout << "decryption result: ";
    for(int i=0; i<print_length; i++){
        std::cout << ptxt_result.data()[i] << " ";
    }
    std::cout << std::endl;

    return;
}

void Cryptor::generate_rlwe_switchkeys(void) const
{
    size_t npoly = RLWEParamsLittle::npoly;
    size_t poly_degree = RLWEParams::poly_modulus_degree;
    Modulus mod_plain(RLWEParamsLittle::plain_modulus);
    size_t d_lev = RLWEParamsLittle::decompose_level;
    size_t l_poly_degree = RLWEParamsLittle::poly_modulus_degree;
    size_t d_base = RLWEParamsLittle::decompose_log_base;
    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    Modulus mod_coeff(*vec_mod[0].data());
    std::vector<Modulus> vec_mod_little = rlwe_parms_little_->coeff_modulus();
    Modulus mod_coeff_little(*vec_mod[0].data());
    // std::cout << "Coeff Mod: " << mod_coeff.value() << std::endl;
    uint64_t scale = mod_coeff.value() / mod_plain.value();
    uint64_t scale_little = mod_coeff_little.value() / mod_plain.value();
    // std::cout << "Scale little: " << scale_little << std::endl;

    SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey,poly_degree, *pool_);
    std::copy_n(rlwe_seckey_->data().data(), poly_degree, (uint64_t *)inv_seckey);
    util::inverse_ntt_negacyclic_harvey(inv_seckey, rlwe_context_->first_context_data()->small_ntt_tables()[0]);

    size_t print_length = 8;

    rlweswitchkey_->reserve(npoly);
    
    for (int i=0; i<npoly; i++){
        RLevCipher temp_rlev;
        temp_rlev.resize(d_lev);
        for (int j=0; j<(d_lev); j++){
            uint64_t B = ( (uint64_t) 1<<(d_base*j) );
            
            // std::cout << "    Current base is: " << B << std::endl;

            SEAL_ALLOCATE_GET_COEFF_ITER(temp_key, l_poly_degree, *pool_);
            for (int t=0; t<l_poly_degree; t++){
                temp_key[t] = inv_seckey[t*npoly+i];
            }

            // std::cout << "    " << i << "-th extract key is: ";
            // for(int t=0; t<print_length; t++){
            //     std::cout << temp_key[t] <<" ";
            // }
            // std::cout << std::endl;

            for (int t=0; t<l_poly_degree; t++){
                temp_key[t] = util::multiply_uint_mod(temp_key[t], B, mod_coeff_little);
            }

            // std::cout << "    " << i << "-th  scaled key is: ";
            // for(int t=0; t<print_length; t++){
            //     std::cout << temp_key[t] <<" ";
            // }
            // std::cout << std::endl;

            RLWECipher temp_rlwe(*rlwe_context_little_);
            Plaintext zero_ptxt(l_poly_degree);
            VecData zero_vec(l_poly_degree, 0ULL);
            rlwe_batch_encoder_little_->encode(zero_vec, zero_ptxt);
            for (int t=0; t<l_poly_degree; t++){
                zero_ptxt.data()[t] = 0;
            }
            // std::cout << "zero ptxt: ";
            // for (int t=0; t<print_length; t++){
            //     std::cout << zero_ptxt[t] << " ";
            // }
            // std::cout << std::endl;
            
            rlwe_encryptor_little_->encrypt(zero_ptxt, temp_rlwe);

            for (int t=0; t<l_poly_degree; t++){
                temp_rlwe.data(0)[t] =  util::add_uint_mod(temp_rlwe.data(0)[t], temp_key[t], mod_coeff_little);
            }

            temp_rlev[j] = temp_rlwe;
        }
        rlweswitchkey_->emplace_back(temp_rlev);
    }
    return;
}

void Cryptor::generate_lweseckey(void) const
{
    // Extract encryption parameters.
    auto &context_data = *lwe_context_->key_context_data();
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    lwe_seckey_->data().resize(util::mul_safe(coeff_count, coeff_modulus_size));
    lwe_seckey_intt_->data().resize(util::mul_safe(coeff_count, coeff_modulus_size));
    // Generate secret key
    util::RNSIter secret_key(lwe_seckey_->data().data(), coeff_count);
    util::RNSIter secret_key_intt(lwe_seckey_intt_->data().data(), coeff_count);
    util::sample_poly_binary(parms.random_generator()->create(), parms, secret_key);
    std::copy_n(lwe_seckey_->data().data(), util::mul_safe(coeff_count, coeff_modulus_size), lwe_seckey_intt_->data().data());

    // Transform the secret s into NTT representation.
    auto ntt_tables = context_data.small_ntt_tables();
    util::ntt_negacyclic_harvey(secret_key, coeff_modulus_size, ntt_tables);
    // Set the parms_id for secret key
    lwe_seckey_->parms_id() = context_data.parms_id();
    lwe_seckey_intt_->parms_id() = context_data.parms_id();
}

void Cryptor::lwekeyswitch(const LWECipher &ilwe, LWECipher &olwe) const
{
    RLWECipher rlwe(*lwe_context_), prod(*lwe_context_), result(*lwe_context_);
    rlwe.resize(2);
    prod.resize(2);
    result.resize(2);
    olwe.resize(LWEParams::poly_modulus_degree + 1);
    Plaintext plain(LWEParams::poly_modulus_degree);
    for (size_t i = 0; i < LWEParams::decompose_level; i++) {
        util::dyadic_product_coeffmod(util::ConstRNSIter(lwe_seckey_->data().data(), LWEParams::poly_modulus_degree), util::ConstRNSIter(lweswitchkey_->at(0).data()[i].data(1), LWEParams::poly_modulus_degree), 1, lwe_context_->first_context_data()->parms().coeff_modulus(), util::RNSIter(plain.data(), LWEParams::poly_modulus_degree));
        util::add_poly_coeffmod(util::ConstRNSIter(plain.data(), LWEParams::poly_modulus_degree), util::ConstRNSIter(lweswitchkey_->at(0).data()[i].data(0), LWEParams::poly_modulus_degree), 1, lwe_context_->first_context_data()->parms().coeff_modulus(), util::RNSIter(plain.data(), LWEParams::poly_modulus_degree));
        util::inverse_ntt_negacyclic_harvey(util::RNSIter(plain.data(), LWEParams::poly_modulus_degree), 1, lwe_context_->first_context_data()->small_ntt_tables());
    }
    for (size_t i = 0; i < LWEParams::npoly; i++) {
        std::copy_n(ilwe.begin() + 1 + LWEParams::poly_modulus_degree * i, LWEParams::poly_modulus_degree, olwe.begin() + 1);
        LWEtoRLWE(olwe, rlwe);
        keyswitch(util::RNSIter(rlwe.data(1), LWEParams::poly_modulus_degree), lweswitchkey_->at(i), prod, ParamSet::LWE);
        // rlwe_evaluator_->add_inplace(result, prod);
        util::add_poly_coeffmod(result, prod, 2, lwe_context_->first_context_data()->parms().coeff_modulus(), result);
    }
    result.is_ntt_form() = true;
    SampleExtract(result, olwe, 0, false, ParamSet::LWE);
    std::vector<Modulus> vec_mod = lwe_parms_->coeff_modulus();
    olwe[0] = util::add_uint_mod(ilwe[0], olwe[0], *vec_mod[0].data()); ilwe[0]; // should be mod add?
}

void Cryptor::veclwekeyswtich(const std::vector<LWECipher> &ilwe_vec, const size_t &number, std::vector<LWECipher> &olwe_vec) const 
{
    // do lwe keyswitch for vector of lwe
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<number; i++){
        lwekeyswitch(ilwe_vec[i], olwe_vec[i]);
    }
    return;
}

void Cryptor::rlwekeyswitch(const RLWECipher &ilwe, std::vector<RLWECipher> &vec_olwe) const
{

    RLWECipher ilwe_copy = ilwe;
    // TODO: cancel mod switch to last!
    rlwe_evaluator_->mod_switch_to_inplace(ilwe_copy, rlwe_context_->last_parms_id());
    
    uint64_t npoly = RLWEParamsLittle::npoly;
    uint64_t poly_degree = RLWEParamsLittle::poly_modulus_degree;
    uint64_t dec_base = RLWEParamsLittle::decompose_log_base;
    uint64_t dec_lev = RLWEParamsLittle::decompose_level;
    Modulus mod_base((uint64_t) 1 <<dec_base);
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();
    Modulus mod_coeff(*vec_mod[0].data());

    Plaintext Debug_Data(poly_degree);
    
    vec_olwe.resize(npoly);
    const RGSWCipher temp_rgsw = *rlweswitchkey_;
    // #pragma omp parallel for num_threads(num_th)
    for(int k=0; k<npoly; k++){
        RLWECipher trivial_rlwe(*rlwe_context_little_);
        trivial_rlwe.resize(2);

        for(int i=0; i<poly_degree;i++){
            trivial_rlwe.data(0)[i] = ilwe_copy.data(0)[i*npoly+k];
            trivial_rlwe.data(1)[i] = 0;
        }

        // DEBUG
        try {
            decrypt(trivial_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
        }
        catch (const std::logic_error& e) {
            // Check if the exception message is the one you expect
            if (std::string(e.what()) == "encrypted is not valid for encryption parameters") {
                std::cout << k << "-th org trivial rlwe: ";
            } else {
                // If it's a different logic_error, might want to rethrow or handle differently
                throw;
            }
        }

        // DEBUG
        // std::cout << k << "-th org trivial rlwe: ";
        // for(int x=0; x<16; x++){
        //     std::cout << Debug_Data.data()[x] << " ";
        // }
        // std::cout << std::endl;

        for (int i=0; i<(k+1); i++){
            size_t idx = k - i;
            RLevCipher temp_rlev = temp_rgsw[i];

            // generate a
            SEAL_ALLOCATE_GET_COEFF_ITER(temp_a, poly_degree, *pool_);
            for(int l=0; l<poly_degree; l++){
                temp_a[l] = ilwe_copy.data(1)[l*npoly+idx];
            }
        
            for (int j=0; j<(dec_lev); j++){
                // generate aj
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_a_j, poly_degree, *pool_);
                for(int l=0; l<poly_degree; l++){
                    temp_a_j[l] = temp_a[l] >> (dec_base*j);
                    // TODO: may change to & operation to further speed up
                    util::modulo_uint_inplace(&temp_a_j[l], 1, mod_base);
                }
                RLWECipher temp_rlwe = temp_rlev[j];
                
                // copy aj
                // VecData vec_temp_a(poly_degree, 0ULL);
                // for (int l=0; l<poly_degree; l++){
                //     vec_temp_a[l] = temp_a_j[l];
                // }
                SEAL_ALLOCATE_GET_COEFF_ITER(vec_temp_a, poly_degree, *pool_);
                for (int l=0; l<poly_degree; l++){
                    vec_temp_a[l] = temp_a_j[l];
                }
                util::ntt_negacyclic_harvey(vec_temp_a, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);

                // copy c1
                // VecData temp_rlwe_a(poly_degree, 0ULL);
                // for (int l=0; l<poly_degree; l++){
                //     temp_rlwe_a[l] = temp_rlwe.data(1)[l];
                // }
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a, poly_degree, *pool_);
                for (int l=0; l<poly_degree; l++){
                    temp_rlwe_a[l] = temp_rlwe.data(1)[l];
                }
                util::ntt_negacyclic_harvey(temp_rlwe_a, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);

                // do c1*aj
                // VecData temp_rlwe_a_scaled(poly_degree, 0ULL);
                // util::NWC_Manual(temp_rlwe_a, vec_temp_a, poly_degree, mod_coeff, temp_rlwe_a_scaled);
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a_scaled, poly_degree, *pool_);
                util::dyadic_product_coeffmod(temp_rlwe_a, vec_temp_a, poly_degree,mod_coeff,temp_rlwe_a_scaled);
                util::inverse_ntt_negacyclic_harvey(temp_rlwe_a_scaled, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);

                // copy c0
                // VecData temp_rlwe_b(poly_degree, 0ULL);
                // for (int l=0; l<poly_degree; l++){
                //     temp_rlwe_b[l] = temp_rlwe.data(0)[l];
                // }
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b, poly_degree, *pool_);
                for (int l=0; l<poly_degree; l++){
                    temp_rlwe_b[l] = temp_rlwe.data(0)[l];
                }
                util::ntt_negacyclic_harvey(temp_rlwe_b, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);

                // do c0*aj
                // VecData temp_rlwe_b_scaled(poly_degree, 0ULL);
                // util::NWC_Manual(temp_rlwe_b, vec_temp_a, poly_degree, mod_coeff, temp_rlwe_b_scaled);
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b_scaled, poly_degree, *pool_);
                util::dyadic_product_coeffmod(temp_rlwe_b, vec_temp_a, poly_degree,mod_coeff,temp_rlwe_b_scaled);
                util::inverse_ntt_negacyclic_harvey(temp_rlwe_b_scaled, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
                

                // copy new c0 c1 to rlwe
                for (int l=0; l<poly_degree; l++){
                    temp_rlwe.data(1)[l] = temp_rlwe_a_scaled[l];
                    temp_rlwe.data(0)[l] = temp_rlwe_b_scaled[l];
                }

                rlwe_evaluator_little_->add_inplace(trivial_rlwe, temp_rlwe);
                // DEBUG
                try {
                    decrypt(trivial_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
                }
                catch (const std::logic_error& e) {
                    // Check if the exception message is the one you expect
                    if (std::string(e.what()) == "encrypted is not valid for encryption parameters") {
                        std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                    } else {
                        // If it's a different logic_error, might want to rethrow or handle differently
                        throw;
                    }
                }

                // DEBUG
                // std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                // for(int x=0; x<16; x++){
                //     std::cout << Debug_Data.data()[x] << " ";
                // }
                // std::cout << std::endl;
                
            }
        }
        
        for (int i=k+1; i<npoly; i++){
            size_t idx = k + npoly - i;
            RLevCipher temp_rlev = temp_rgsw[i];

            // generate a
            SEAL_ALLOCATE_GET_COEFF_ITER(temp_a, RLWEParamsLittle::poly_modulus_degree, *pool_);
            for(int l=0; l<poly_degree; l++){
                temp_a[l] = ilwe_copy.data(1)[l*npoly+idx];
            }

            // DEBUG
            // std::cout << k << "-th " << i << "-th round copy a: ";
            // for(int x=0; x<16; x++){
            //     std::cout << temp_a[x] << " ";
            // }
            // std::cout << std::endl;


            for (int j=0; j<(dec_lev); j++){
                RLWECipher temp_rlwe = temp_rlev[j];

                // generate aj and do bias to aj
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_a_j, RLWEParamsLittle::poly_modulus_degree, *pool_);
                temp_a_j[0] = temp_a[poly_degree-1] >> (dec_base*j);
                util::modulo_uint_inplace(&temp_a_j[0], 1, mod_base);
                temp_a_j[0] = util::negate_uint_mod(temp_a_j[0],mod_coeff);
                for(int l=1; l<poly_degree; l++){
                    temp_a_j[l] = temp_a[l-1] >> (dec_base*j);
                    // DEBUG
                    // if(l==1){
                    //     std::cout << "mod base: " << mod_base.value() << std::endl;
                    //     std::cout << "temp_a_j[l]: " << temp_a_j[l]  << std::endl;
                    // }
                    util::modulo_uint_inplace(&temp_a_j[l], 1, mod_base);
                    // DEBUG
                    // if(l==1)
                    //     std::cout << "temp_a_j[l]: " << temp_a_j[l]  << std::endl;
                }

                // DEBUG
                // std::cout << k << "-th " << i << "-th round " << j << "-th level biased temp a: ";
                // for(int x=0; x<16; x++){
                //     std::cout << temp_a_j[x] << " ";
                // }
                // std::cout << std::endl;

                util::ntt_negacyclic_harvey(temp_a_j, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
                // do bias to aj (we fuse it in aj generation)
                
                // do bias to aj
                // std::cout << "Before bias temp a is: ";
                // for (int l=0; l<4; l++){
                //     std::cout << temp_a[l] << " ";
                // }
                // std::cout << std::endl;
                // VecData bias(poly_degree, 0ULL);
                // bias[1] = 1;
                // VecData vec_temp_a(poly_degree, 0ULL);
                // for (int l=0; l<poly_degree; l++){
                //     vec_temp_a[l] = temp_a[l];
                // }
                // VecData bias_temp_a(poly_degree, 0ULL);
                // util::NWC_Manual(vec_temp_a, bias, poly_degree, mod_coeff, bias_temp_a);
                // std::cout << "After bias temp a is: ";
                // for (int l=0; l<4; l++){
                //     std::cout << bias_temp_a[l] << " ";
                // }
                // std::cout << std::endl;

                // copy c1
                // VecData temp_rlwe_a(poly_degree, 0ULL);
                // for (int l=0; l<poly_degree; l++){
                //     temp_rlwe_a[l] = temp_rlwe.data(1)[l];
                // }
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a, RLWEParamsLittle::poly_modulus_degree, *pool_);
                for (int l=0; l<poly_degree; l++){
                    temp_rlwe_a[l] = temp_rlwe.data(1)[l];
                }
                util::ntt_negacyclic_harvey(temp_rlwe_a, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);

                // do aj * c1
                // VecData temp_rlwe_a_scaled(poly_degree, 0ULL);
                // util::NWC_Manual(temp_rlwe_a, bias_temp_a, poly_degree, mod_coeff, temp_rlwe_a_scaled);
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a_scaled, RLWEParamsLittle::poly_modulus_degree, *pool_);
                util::dyadic_product_coeffmod(temp_rlwe_a, temp_a_j, poly_degree, mod_coeff, temp_rlwe_a_scaled);
                util::inverse_ntt_negacyclic_harvey(temp_rlwe_a_scaled, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);

                // copy c0
                // VecData temp_rlwe_b(poly_degree, 0ULL);
                // for (int l=0; l<poly_degree; l++){
                //     temp_rlwe_b[l] = temp_rlwe.data(0)[l];
                // }
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b, RLWEParamsLittle::poly_modulus_degree, *pool_);
                for (int l=0; l<poly_degree; l++){
                    temp_rlwe_b[l] = temp_rlwe.data(0)[l];
                }
                util::ntt_negacyclic_harvey(temp_rlwe_b, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);

                // do aj * c0
                // VecData temp_rlwe_b_scaled(poly_degree, 0ULL);
                // util::NWC_Manual(temp_rlwe_b, bias_temp_a, poly_degree, mod_coeff, temp_rlwe_b_scaled);
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b_scaled, RLWEParamsLittle::poly_modulus_degree, *pool_);
                util::dyadic_product_coeffmod(temp_rlwe_b, temp_a_j, poly_degree, mod_coeff, temp_rlwe_b_scaled);
                util::inverse_ntt_negacyclic_harvey(temp_rlwe_b_scaled, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);



                for (int l=0; l<poly_degree; l++){
                    temp_rlwe.data(1)[l] = temp_rlwe_a_scaled[l];
                    temp_rlwe.data(0)[l] = temp_rlwe_b_scaled[l];
                }

                rlwe_evaluator_little_->add_inplace(trivial_rlwe, temp_rlwe);
                // DEBUG
                try {
                    decrypt(trivial_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
                }
                catch (const std::logic_error& e) {
                    // Check if the exception message is the one you expect
                    if (std::string(e.what()) == "encrypted is not valid for encryption parameters") {
                        std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                    } else {
                        // If it's a different logic_error, might want to rethrow or handle differently
                        throw;
                    }
                }

                // DEBUG
                // std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                // for(int x=0; x<16; x++){
                //     std::cout << Debug_Data.data()[x] << " ";
                // }
                // std::cout << std::endl;

            }
            
        }
        
        vec_olwe[k] = trivial_rlwe;
    }
    std::cout <<"noise budget after switch: " << rlwe_decryptor_little_->invariant_noise_budget(vec_olwe[npoly-1]) << " bits" << std::endl;
    
    // Plaintext ptxt_noise_mul(poly_degree);
    // for(int i=0; i<poly_degree; i++){
    //     ptxt_noise_mul.data()[npoly-1] = i;
    // }
    // rlwe_evaluator_little_->multiply_plain_inplace(vec_olwe[npoly-1],ptxt_noise_mul);
    // std::cout <<"noise budget after further multiplication: " << rlwe_decryptor_little_->invariant_noise_budget(vec_olwe[npoly-1]) << " bits" << std::endl;

    return;
}

void Cryptor::rlwekeyswitch_arbitary(const RLWECipher &ilwe, std::vector<RLWECipher> &vec_olwe) const
{

    size_t print_length = RLWEParamsLittle::poly_modulus_degree;

    RLWECipher ilwe_copy = ilwe;

    
    
    // rlwe_evaluator_->mod_switch_to_inplace(ilwe_copy, rlwe_context_->last_parms_id());
    // Let long rlwe mod switch to short rlwe
    size_t long_mod_size = ilwe.coeff_modulus_size();
    std::cout << "long rlwe modulus size: " << long_mod_size << std::endl;

    // DEBUG
    auto context = rlwe_context_->get_context_data(ilwe.parms_id());
    std::cout << "Input RLWE Chain now: " << context->chain_index() << std::endl;

    size_t short_mod_size = (RLWEParamsLittle::coeff_modulus_size<3)?1:RLWEParamsLittle::coeff_modulus_size - 1;  // here should minus 1
    std::cout << "short rlwe modulus size: " << short_mod_size << std::endl;
    size_t mod_diff = long_mod_size - short_mod_size;
    std::cout << "modulus size difference: " << mod_diff << std::endl;
    for(int i=0; i<mod_diff; i++){
        rlwe_evaluator_->mod_switch_to_next_inplace(ilwe_copy);
    }
    std::cout << "long rlwe modulus size after switch: " << ilwe_copy.coeff_modulus_size() << " it should be: " << short_mod_size << std::endl;


    uint64_t npoly = RLWEParamsLittle::npoly;
    uint64_t poly_degree = RLWEParamsLittle::poly_modulus_degree;
    uint64_t long_poly_degree = RLWEParams::poly_modulus_degree;
    // uint64_t dec_base = RLWEParamsLittle::decompose_log_base; // we no more need decompose
    // uint64_t dec_lev = RLWEParamsLittle::decompose_level; // we no more need decompose
    // Modulus mod_base((uint64_t) 1 <<dec_base);
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();
    vec_olwe.resize(npoly);

    // DEBUG
    // util::print_example_banner("Parameter");
    // for(int i=0; i<short_mod_size; i++){
    //     std::cout << "mod[" << i << "]:" << vec_mod[i].value() << " ";
    // }
    // std::cout << std::endl;
    // std::cout << "decompose base: " << mod_base.value() << std::endl;
    

    const RGSWCipher temp_rgsw = *rlweswitchkey_;

    Plaintext Debug_Data(poly_degree);

    // DEBUG
    // we print input rlwe first
    // util::print_example_banner("Input RLWE");
    // std::cout << "long rlwe[0]: ";
    // for(int i=0; i<long_poly_degree*short_mod_size; i++){
    //     std::cout << "[" << i << "]" << ilwe.data(0)[i] <<" "; 
    // }
    // std::cout << std::endl;
    // std::cout << "long rlwe[1]: ";
    // for(int i=0; i<long_poly_degree*short_mod_size; i++){
    //     std::cout << "[" << i << "]" << ilwe.data(1)[i] <<" "; 
    // }
    // std::cout << std::endl;

    // DEBUG
    // we then print rlwe key
    // util::print_example_banner("Input RLWE Key");
    // SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey,long_poly_degree, *pool_);
    // std::copy_n(rlwe_seckey_->data().data(), long_poly_degree, (uint64_t *)inv_seckey);
    // util::inverse_ntt_negacyclic_harvey(inv_seckey, rlwe_context_->first_context_data()->small_ntt_tables()[0]);
    // std::cout << "RLWE key: ";
    // for(int i=0; i<long_poly_degree; i++){
    //     std::cout << "[" << i << "]" << inv_seckey[i] <<" "; 
    // }
    // std::cout << std::endl;


    #pragma omp parallel for num_threads(num_th)
    for(int k=0; k<npoly; k++){
        // initialize trivial rlwe
        RLWECipher trivial_rlwe(*rlwe_context_little_);
        trivial_rlwe.resize(2);

        // copy c0 to generate trivial rlwe in rns edition
        for (int l=0; l<short_mod_size; l++){
            for(int i=0; i<poly_degree;i++){
                trivial_rlwe.data(0)[i+l*poly_degree] = ilwe_copy.data(0)[i*npoly+k+l*long_poly_degree];
                trivial_rlwe.data(1)[i+l*poly_degree] = 0;
            }
        }

        // DEBUG
        // we print trivial rlwe
        // util::print_example_banner("Gnerate Trivial RLWE(b_k,0)");
        // std::cout << k << "-th trivial short rlwe[0]: ";
        // for(int i=0; i<poly_degree*short_mod_size; i++){
        //     std::cout << "[" << i << "]" << trivial_rlwe.data(0)[i] <<" "; 
        // }
        // std::cout << std::endl;
        // std::cout << k << "-th trivial short rlwe[1]: ";
        // for(int i=0; i<poly_degree*short_mod_size; i++){
        //     std::cout << "[" << i << "]" << trivial_rlwe.data(1)[i] <<" "; 
        // }
        // std::cout << std::endl;

        // DEBUG
        // util::print_example_banner("Decrypt Trivial RLWE Now");
        // try {
        //     decrypt(trivial_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
        // }
        // catch (const std::logic_error& e) {
        //     // Check if the exception message is the one you expect
        //     if (std::string(e.what()) == "encrypted is not valid for encryption parameters") {
        //         std::cout << k << "-th org trivial rlwe: ";
        //     } else {
        //         // If it's a different logic_error, might want to rethrow or handle differently
        //         throw;
        //     }
        // }
        // std::cout << k << "-th org trivial rlwe: ";
        // for(int x=0; x<print_length; x++){
        //     std::cout << Debug_Data.data()[x] << " ";
        // }
        // std::cout << std::endl;

        for (int i=0; i<(k+1); i++){
            size_t idx = k - i;
            RLevCipher temp_rlev = temp_rgsw[i];

            // generate a(c1)
            SEAL_ALLOCATE_GET_COEFF_ITER(temp_a, short_mod_size*poly_degree, *pool_);
            for (int j=0; j<short_mod_size; j++){
                for(int l=0; l<poly_degree; l++){
                    temp_a[l+j*poly_degree] = ilwe_copy.data(1)[l*npoly+idx+j*long_poly_degree];
                }
            }

            // DEBUG
            // util::print_example_banner("Extract temp a");
            // std::cout << i << "-th a: ";
            // for(int x=0; x<short_mod_size*poly_degree; x++){
            //     std::cout << "[" << x << "]" << temp_a[x] << " ";
            // }
            // std::cout << std::endl;
            
            // for (int j=0; j<(dec_lev); j++){
            for (int j=0; j<(1); j++){

                // generate aj
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_a_j, short_mod_size*poly_degree, *pool_);
                for (int t=0; t<short_mod_size; t++){
                    for(int l=0; l<poly_degree; l++){
                        // temp_a_j[l+t*poly_degree] = temp_a[l+t*poly_degree] >> (dec_base*j);
                        // util::modulo_uint_inplace(&temp_a_j[l+t*poly_degree], 1, mod_base);
                        temp_a_j[l+t*poly_degree] = temp_a[l+t*poly_degree];
                    }
                }

                // DEBUG
                // util::print_example_banner("Decompose temp a");
                // std::cout << i << "-th a in " << j << "-th dec level: ";
                // for(int x=0; x<short_mod_size*poly_degree; x++){
                //     std::cout << "[" << x << "]" << temp_a_j[x] << " ";
                // }
                // std::cout << std::endl;

                RLWECipher temp_rlwe = temp_rlev[j];

                //DEBUG
                // print switch key
                // util::print_example_banner("Decrypt Switch Key");
                // decrypt(temp_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
                // std::cout << "[" << i << "," << j << "] key decryption is: ";
                // for(int x=0; x<poly_degree; x++){
                //     std::cout << "[" << x << "]" << Debug_Data.data()[x] << " ";
                // }
                // std::cout << std::endl;

                // generate ntt table
                auto ntt_table = rlwe_context_little_->first_context_data()->small_ntt_tables();
       
                for (int t=0; t<short_mod_size; t++){

                    // Bug May appears here
                    uint64_t mod_coeff_now = *vec_mod[t].data();

                    // copy aj in t-th prime modulus 
                    SEAL_ALLOCATE_GET_COEFF_ITER(vec_temp_a, poly_degree, *pool_);
                    for (int l=0; l<poly_degree; l++){
                        vec_temp_a[l] = temp_a_j[l+t*poly_degree];
                    }

                    // DEBUG
                    // Do RNS multiplication
                    // util::print_example_banner("Decomposed a * Key in RNS");
                    // std::cout << t << "-th rns decompose a: ";
                    // for(int x=0; x<poly_degree; x++){
                    //     std::cout << "[" << x << "]" << vec_temp_a[x] << " ";
                    // }
                    // std::cout << std::endl;

                    util::ntt_negacyclic_harvey(vec_temp_a, ntt_table[t]);

                    // DEBUG
                    // Do RNS NTT
                    // util::print_example_banner("Decomposed a do NTT");
                    // std::cout << "Mod: " << vec_mod[t].value() << std::endl;
                    // std::cout << t << "-th rns decompose a in NTT: ";
                    // for(int x=0; x<poly_degree; x++){
                    //     std::cout << "[" << x << "]" << vec_temp_a[x] << " ";
                    // }
                    // std::cout << std::endl;

                    // copy c1
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a, poly_degree, *pool_);
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe_a[l] = temp_rlwe.data(1)[l+t*poly_degree];
                    }

                    // DEBUG
                    // Extract a of key
                    // util::print_example_banner("Extract a of Key");
                    // std::cout << "Mod: " << vec_mod[t].value() << std::endl;
                    // std::cout << "[" << i << "," << j << "] key in " << t << "-th rns: ";
                    // for(int x=0; x<poly_degree; x++){
                    //     std::cout << "[" << x << "]" << temp_rlwe_a[x] << " ";
                    // }
                    // std::cout << std::endl;

                    util::ntt_negacyclic_harvey(temp_rlwe_a, ntt_table[t]);

                    // DEBUG
                    // Do RNS NTT
                    // util::print_example_banner("a of Key do NTT");
                    // std::cout << "Mod: " << vec_mod[t].value() << std::endl;
                    // std::cout << "[" << i << "," << j << "] key in " << t << "-th rns: ";
                    // for(int x=0; x<poly_degree; x++){
                    //     std::cout << "[" << x << "]" << temp_rlwe_a[x] << " ";
                    // }
                    // std::cout << std::endl;

                    // do c1*aj
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a_scaled, poly_degree, *pool_);
                    util::dyadic_product_coeffmod(temp_rlwe_a, vec_temp_a, poly_degree,mod_coeff_now,temp_rlwe_a_scaled);

                    // DEBUG
                    // Do Dynamic Mul
                    // util::print_example_banner("decompose a * key's a in NTT");
                    // std::cout << "Mod: " << vec_mod[t].value() << std::endl;
                    // std::cout << "[" << i << "," << j << "] key in " << t << "-th rns: ";
                    // for(int x=0; x<poly_degree; x++){
                    //     std::cout << "[" << x << "]" << temp_rlwe_a_scaled[x] << " ";
                    // }
                    // std::cout << std::endl;

                    util::inverse_ntt_negacyclic_harvey(temp_rlwe_a_scaled, ntt_table[t]);

                    // DEBUG
                    // Do Dynamic Mul
                    // util::print_example_banner("Result do iNTT");
                    // std::cout << "Mod: " << vec_mod[t].value() << std::endl;
                    // std::cout << "[" << i << "," << j << "] key in " << t << "-th rns: ";
                    // for(int x=0; x<poly_degree; x++){
                    //     std::cout << "[" << x << "]" << temp_rlwe_a_scaled[x] << " ";
                    // }
                    // std::cout << std::endl;

                    

                    // copy c0
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b, poly_degree, *pool_);
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe_b[l] = temp_rlwe.data(0)[l+t*poly_degree];
                    }
                    util::ntt_negacyclic_harvey(temp_rlwe_b, ntt_table[t]);

                    // do c0*aj
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b_scaled, poly_degree, *pool_);
                    util::dyadic_product_coeffmod(temp_rlwe_b, vec_temp_a, poly_degree,mod_coeff_now,temp_rlwe_b_scaled);
                    util::inverse_ntt_negacyclic_harvey(temp_rlwe_b_scaled, ntt_table[t]);

                    // copy new c0 c1 to rlwe
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe.data(1)[l+t*poly_degree] = temp_rlwe_a_scaled[l];
                        temp_rlwe.data(0)[l+t*poly_degree] = temp_rlwe_b_scaled[l];
                    }
                }

                rlwe_evaluator_little_->add_inplace(trivial_rlwe, temp_rlwe);

                // DEBUG
                // try {
                //     decrypt(trivial_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
                // }
                // catch (const std::logic_error& e) {
                //     // Check if the exception message is the one you expect
                //     if (std::string(e.what()) == "encrypted is not valid for encryption parameters") {
                //         std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                //     } else {
                //         // If it's a different logic_error, might want to rethrow or handle differently
                //         throw;
                //     }
                // }
                // std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                // for(int x=0; x<print_length; x++){
                //     std::cout << Debug_Data.data()[x] << " ";
                // }
                // std::cout << std::endl;

            }
        }
        
        for (int i=k+1; i<npoly; i++){
            size_t idx = k + npoly - i;
            RLevCipher temp_rlev = temp_rgsw[i];

            // generate a(c1)
            SEAL_ALLOCATE_GET_COEFF_ITER(temp_a, poly_degree*short_mod_size, *pool_);
            for (int j=0; j<short_mod_size; j++){
                for(int l=0; l<poly_degree; l++){
                    temp_a[l+j*poly_degree] = ilwe_copy.data(1)[l*npoly+idx+j*long_poly_degree];
                }
            }

            // DEBUG
            // std::cout << k << "-th " << i << "-th round copy a: ";
            // for(int x=0; x<print_length; x++){
            //     std::cout << temp_a[x] << " ";
            // }
            // std::cout << std::endl;


            // for (int j=0; j<(dec_lev); j++){
            for (int j=0; j<(1); j++){

                // generate aj
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_a_j, short_mod_size*poly_degree, *pool_);
                for (int t=0; t<short_mod_size; t++){
                    for(int l=0; l<poly_degree; l++){
                        // temp_a_j[l+t*poly_degree] = temp_a[l+t*poly_degree] >> (dec_base*j);
                        // util::modulo_uint_inplace(&temp_a_j[l+t*poly_degree], 1, mod_base);
                        temp_a_j[l+t*poly_degree] = temp_a[l+t*poly_degree];
                    }
                }

                // DEBUG
                // std::cout << k << "-th " << i << "-th round " << j << "-th level temp a: ";
                // for(int x=0; x<print_length; x++){
                //     std::cout << temp_a_j[x] << " ";
                // }
                // std::cout << std::endl;


                RLWECipher temp_rlwe = temp_rlev[j];

                // generate ntt table
                auto ntt_table = rlwe_context_little_->first_context_data()->small_ntt_tables();
                

                for (int t=0; t<short_mod_size; t++){

                    // Bug May appears here
                    uint64_t mod_coeff_now = *vec_mod[t].data();

                    // generate biased aj in rns form
                    SEAL_ALLOCATE_GET_COEFF_ITER(biased_temp_a_j, poly_degree, *pool_);  
                    biased_temp_a_j[0] = temp_a_j[t*poly_degree+poly_degree-1];
                    biased_temp_a_j[0] = util::negate_uint_mod(biased_temp_a_j[0],mod_coeff_now);
                    for(int l=1; l<poly_degree; l++){
                        biased_temp_a_j[l] = temp_a_j[l+t*poly_degree-1];
                    }

                    // DEBUG
                    // std::cout << k << "-th " << i << "-th round " << j << "-th level " << t << "-th RNS biased temp a: ";
                    // for(int x=0; x<print_length; x++){
                    //     std::cout << biased_temp_a_j[x] << " ";
                    // }
                    // std::cout << std::endl;


                    util::ntt_negacyclic_harvey(biased_temp_a_j, ntt_table[t]);

                    // copy c1
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a, poly_degree, *pool_);
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe_a[l] = temp_rlwe.data(1)[l+t*poly_degree];
                    }
                    util::ntt_negacyclic_harvey(temp_rlwe_a, ntt_table[t]);

                    // do c1*biased aj
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a_scaled, poly_degree, *pool_);
                    util::dyadic_product_coeffmod(temp_rlwe_a, biased_temp_a_j, poly_degree,mod_coeff_now,temp_rlwe_a_scaled);
                    util::inverse_ntt_negacyclic_harvey(temp_rlwe_a_scaled, ntt_table[t]);

                    // copy c0
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b, poly_degree, *pool_);
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe_b[l] = temp_rlwe.data(0)[l+t*poly_degree];
                    }
                    util::ntt_negacyclic_harvey(temp_rlwe_b, ntt_table[t]);

                    // do c0* biased aj
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b_scaled, poly_degree, *pool_);
                    util::dyadic_product_coeffmod(temp_rlwe_b, biased_temp_a_j, poly_degree,mod_coeff_now,temp_rlwe_b_scaled);
                    util::inverse_ntt_negacyclic_harvey(temp_rlwe_b_scaled, ntt_table[t]);

                    // copy new c0 c1 to rlwe
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe.data(1)[l+t*poly_degree] = temp_rlwe_a_scaled[l];
                        temp_rlwe.data(0)[l+t*poly_degree] = temp_rlwe_b_scaled[l];
                    }

                }

                rlwe_evaluator_little_->add_inplace(trivial_rlwe, temp_rlwe);
                // DEBUG
                // try {
                //     decrypt(trivial_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
                // }
                // catch (const std::logic_error& e) {
                //     // Check if the exception message is the one you expect
                //     if (std::string(e.what()) == "encrypted is not valid for encryption parameters") {
                //         std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                //     } else {
                //         // If it's a different logic_error, might want to rethrow or handle differently
                //         throw;
                //     }
                // }
                // std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                // for(int x=0; x<print_length; x++){
                //     std::cout << Debug_Data.data()[x] << " ";
                // }
                // std::cout << std::endl;


            }
            
        }
        
        vec_olwe[k] = trivial_rlwe;

        // DEBUG
        // we print output rlwe
        // if(k==0){
        //     util::print_example_banner("Output RLWE");
        //     std::cout << "short rlwe[0]: ";
        //     for(int i=0; i<poly_degree*short_mod_size; i=i+poly_degree/2){
        //         std::cout << "[" << i << "]" << ilwe.data(0)[i] <<" "; 
        //     }
        //     std::cout << std::endl;
        //     std::cout << "short rlwe[1]: ";
        //     for(int i=0; i<poly_degree*short_mod_size; i=i+poly_degree/2){
        //         std::cout << "[" << i << "]" << ilwe.data(1)[i] <<" "; 
        //     }
        //     std::cout << std::endl;
        // }
        
    }
    std::cout <<"noise budget after switch: " << rlwe_decryptor_little_->invariant_noise_budget(vec_olwe[npoly-1]) << " bits" << std::endl;
    Plaintext ptxt_noise_mul(poly_degree);
    for(int i=0; i<poly_degree; i++){
        ptxt_noise_mul.data()[i] = i;
    }
    RLWECipher rlwe_temp = vec_olwe[npoly-1];
    context = rlwe_context_little_->get_context_data(rlwe_temp.parms_id());
    std::cout << "output RLWE Chain now: " << context->chain_index() << std::endl;
    rlwe_evaluator_little_->multiply_plain_inplace(rlwe_temp,ptxt_noise_mul);
    std::cout <<"noise budget after further multiplication: " << rlwe_decryptor_little_->invariant_noise_budget(rlwe_temp) << " bits" << std::endl;

    

    return;
}

void Cryptor::rlwekeyswitch_arbitary_trash(const RLWECipher &ilwe, std::vector<RLWECipher> &vec_olwe) const
{

    size_t print_length = RLWEParamsLittle::poly_modulus_degree;

    RLWECipher ilwe_copy = ilwe;

    
    
    // rlwe_evaluator_->mod_switch_to_inplace(ilwe_copy, rlwe_context_->last_parms_id());
    // Let long rlwe mod switch to short rlwe
    size_t long_mod_size = ilwe.coeff_modulus_size();
    std::cout << "long rlwe modulus size: " << long_mod_size << std::endl;

    // DEBUG
    auto context = rlwe_context_->get_context_data(ilwe.parms_id());
    std::cout << "Input RLWE Chain now: " << context->chain_index() << std::endl;

    size_t short_mod_size = (RLWEParamsLittle::coeff_modulus_size<3)?1:RLWEParamsLittle::coeff_modulus_size - 1;  // here should minus 1
    std::cout << "short rlwe modulus size: " << short_mod_size << std::endl;
    size_t mod_diff = long_mod_size - short_mod_size;
    std::cout << "modulus size difference: " << mod_diff << std::endl;
    for(int i=0; i<mod_diff; i++){
        rlwe_evaluator_->mod_switch_to_next_inplace(ilwe_copy);
    }
    std::cout << "long rlwe modulus size after switch: " << ilwe_copy.coeff_modulus_size() << " it should be: " << short_mod_size << std::endl;


    uint64_t npoly = RLWEParamsLittle::npoly;
    uint64_t poly_degree = RLWEParamsLittle::poly_modulus_degree;
    uint64_t long_poly_degree = RLWEParams::poly_modulus_degree;
    uint64_t dec_base = RLWEParamsLittle::decompose_log_base;
    uint64_t dec_lev = RLWEParamsLittle::decompose_level;
    Modulus mod_base((uint64_t) 1 <<dec_base);
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();
    vec_olwe.resize(npoly);

    // DEBUG
    util::print_example_banner("Parameter");
    for(int i=0; i<short_mod_size; i++){
        std::cout << "mod[" << i << "]:" << vec_mod[i].value() << " ";
    }
    std::cout << std::endl;
    std::cout << "decompose base: " << mod_base.value() << std::endl;
    

    const RGSWCipher temp_rgsw = *rlweswitchkey_;

    Plaintext Debug_Data(poly_degree);

    // DEBUG
    // we print input rlwe first
    util::print_example_banner("Input RLWE");
    std::cout << "long rlwe[0]: ";
    for(int i=0; i<long_poly_degree*short_mod_size; i++){
        std::cout << "[" << i << "]" << ilwe.data(0)[i] <<" "; 
    }
    std::cout << std::endl;
    std::cout << "long rlwe[1]: ";
    for(int i=0; i<long_poly_degree*short_mod_size; i++){
        std::cout << "[" << i << "]" << ilwe.data(1)[i] <<" "; 
    }
    std::cout << std::endl;

    // DEBUG
    // we then print rlwe key
    util::print_example_banner("Input RLWE Key");
    SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey,long_poly_degree, *pool_);
    std::copy_n(rlwe_seckey_->data().data(), long_poly_degree, (uint64_t *)inv_seckey);
    util::inverse_ntt_negacyclic_harvey(inv_seckey, rlwe_context_->first_context_data()->small_ntt_tables()[0]);
    std::cout << "RLWE key: ";
    for(int i=0; i<long_poly_degree; i++){
        std::cout << "[" << i << "]" << inv_seckey[i] <<" "; 
    }
    std::cout << std::endl;


    // #pragma omp parallel for num_threads(num_th)
    for(int k=0; k<npoly; k++){
        // initialize trivial rlwe
        RLWECipher trivial_rlwe(*rlwe_context_little_);
        trivial_rlwe.resize(2);

        // copy c0 to generate trivial rlwe in rns edition
        for (int l=0; l<short_mod_size; l++){
            for(int i=0; i<poly_degree;i++){
                trivial_rlwe.data(0)[i+l*poly_degree] = ilwe_copy.data(0)[i*npoly+k+l*long_poly_degree];
                trivial_rlwe.data(1)[i+l*poly_degree] = 0;
            }
        }

        // DEBUG
        // we print trivial rlwe
        util::print_example_banner("Gnerate Trivial RLWE(b_k,0)");
        std::cout << k << "-th trivial short rlwe[0]: ";
        for(int i=0; i<poly_degree*short_mod_size; i++){
            std::cout << "[" << i << "]" << trivial_rlwe.data(0)[i] <<" "; 
        }
        std::cout << std::endl;
        std::cout << k << "-th trivial short rlwe[1]: ";
        for(int i=0; i<poly_degree*short_mod_size; i++){
            std::cout << "[" << i << "]" << trivial_rlwe.data(1)[i] <<" "; 
        }
        std::cout << std::endl;

        // DEBUG
        util::print_example_banner("Decrypt Trivial RLWE Now");
        try {
            decrypt(trivial_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
        }
        catch (const std::logic_error& e) {
            // Check if the exception message is the one you expect
            if (std::string(e.what()) == "encrypted is not valid for encryption parameters") {
                std::cout << k << "-th org trivial rlwe: ";
            } else {
                // If it's a different logic_error, might want to rethrow or handle differently
                throw;
            }
        }

        // DEBUG
        // std::cout << k << "-th org trivial rlwe: ";
        // for(int x=0; x<print_length; x++){
        //     std::cout << Debug_Data.data()[x] << " ";
        // }
        // std::cout << std::endl;

        for (int i=0; i<(k+1); i++){
            size_t idx = k - i;
            RLevCipher temp_rlev = temp_rgsw[i];

            // generate a(c1)
            SEAL_ALLOCATE_GET_COEFF_ITER(temp_a, short_mod_size*poly_degree, *pool_);
            for (int j=0; j<short_mod_size; j++){
                for(int l=0; l<poly_degree; l++){
                    temp_a[l+j*poly_degree] = ilwe_copy.data(1)[l*npoly+idx+j*long_poly_degree];
                }
            }

            // DEBUG
            util::print_example_banner("Extract temp a");
            std::cout << i << "-th a: ";
            for(int x=0; x<short_mod_size*poly_degree; x++){
                std::cout << "[" << x << "]" << temp_a[x] << " ";
            }
            std::cout << std::endl;
            
            for (int j=0; j<(dec_lev); j++){

                // generate aj
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_a_j, short_mod_size*poly_degree, *pool_);
                for (int t=0; t<short_mod_size; t++){
                    for(int l=0; l<poly_degree; l++){
                        temp_a_j[l+t*poly_degree] = temp_a[l+t*poly_degree] >> (dec_base*j);
                        util::modulo_uint_inplace(&temp_a_j[l+t*poly_degree], 1, mod_base);
                    }
                }

                // DEBUG
                util::print_example_banner("Decompose temp a");
                std::cout << i << "-th a in " << j << "-th dec level: ";
                for(int x=0; x<short_mod_size*poly_degree; x++){
                    std::cout << "[" << x << "]" << temp_a_j[x] << " ";
                }
                std::cout << std::endl;

                RLWECipher temp_rlwe = temp_rlev[j];

                //DEBUG
                // print switch key
                util::print_example_banner("Decrypt Switch Key");
                decrypt(temp_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
                std::cout << "[" << i << "," << j << "] key decryption is: ";
                for(int x=0; x<poly_degree; x++){
                    std::cout << "[" << x << "]" << Debug_Data.data()[x] << " ";
                }
                std::cout << std::endl;

                // generate ntt table
                auto ntt_table = rlwe_context_little_->first_context_data()->small_ntt_tables();
       
                for (int t=0; t<short_mod_size; t++){

                    // Bug May appears here
                    uint64_t mod_coeff_now = *vec_mod[t].data();

                    // copy aj in t-th prime modulus 
                    SEAL_ALLOCATE_GET_COEFF_ITER(vec_temp_a, poly_degree, *pool_);
                    for (int l=0; l<poly_degree; l++){
                        vec_temp_a[l] = temp_a_j[l+t*poly_degree];
                    }

                    // DEBUG
                    // Do RNS multiplication
                    util::print_example_banner("Decomposed a * Key in RNS");
                    std::cout << t << "-th rns decompose a: ";
                    for(int x=0; x<poly_degree; x++){
                        std::cout << "[" << x << "]" << vec_temp_a[x] << " ";
                    }
                    std::cout << std::endl;

                    util::ntt_negacyclic_harvey(vec_temp_a, ntt_table[t]);

                    // DEBUG
                    // Do RNS NTT
                    util::print_example_banner("Decomposed a do NTT");
                    std::cout << "Mod: " << vec_mod[t].value() << std::endl;
                    std::cout << t << "-th rns decompose a in NTT: ";
                    for(int x=0; x<poly_degree; x++){
                        std::cout << "[" << x << "]" << vec_temp_a[x] << " ";
                    }
                    std::cout << std::endl;

                    // copy c1
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a, poly_degree, *pool_);
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe_a[l] = temp_rlwe.data(1)[l+t*poly_degree];
                    }

                    // DEBUG
                    // Extract a of key
                    util::print_example_banner("Extract a of Key");
                    std::cout << "Mod: " << vec_mod[t].value() << std::endl;
                    std::cout << "[" << i << "," << j << "] key in " << t << "-th rns: ";
                    for(int x=0; x<poly_degree; x++){
                        std::cout << "[" << x << "]" << temp_rlwe_a[x] << " ";
                    }
                    std::cout << std::endl;

                    util::ntt_negacyclic_harvey(temp_rlwe_a, ntt_table[t]);

                    // DEBUG
                    // Do RNS NTT
                    util::print_example_banner("a of Key do NTT");
                    std::cout << "Mod: " << vec_mod[t].value() << std::endl;
                    std::cout << "[" << i << "," << j << "] key in " << t << "-th rns: ";
                    for(int x=0; x<poly_degree; x++){
                        std::cout << "[" << x << "]" << temp_rlwe_a[x] << " ";
                    }
                    std::cout << std::endl;

                    // do c1*aj
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a_scaled, poly_degree, *pool_);
                    util::dyadic_product_coeffmod(temp_rlwe_a, vec_temp_a, poly_degree,mod_coeff_now,temp_rlwe_a_scaled);

                    // DEBUG
                    // Do Dynamic Mul
                    util::print_example_banner("decompose a * key's a in NTT");
                    std::cout << "Mod: " << vec_mod[t].value() << std::endl;
                    std::cout << "[" << i << "," << j << "] key in " << t << "-th rns: ";
                    for(int x=0; x<poly_degree; x++){
                        std::cout << "[" << x << "]" << temp_rlwe_a_scaled[x] << " ";
                    }
                    std::cout << std::endl;

                    util::inverse_ntt_negacyclic_harvey(temp_rlwe_a_scaled, ntt_table[t]);

                    // DEBUG
                    // Do Dynamic Mul
                    util::print_example_banner("Result do iNTT");
                    std::cout << "Mod: " << vec_mod[t].value() << std::endl;
                    std::cout << "[" << i << "," << j << "] key in " << t << "-th rns: ";
                    for(int x=0; x<poly_degree; x++){
                        std::cout << "[" << x << "]" << temp_rlwe_a_scaled[x] << " ";
                    }
                    std::cout << std::endl;

                    

                    // copy c0
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b, poly_degree, *pool_);
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe_b[l] = temp_rlwe.data(0)[l+t*poly_degree];
                    }
                    util::ntt_negacyclic_harvey(temp_rlwe_b, ntt_table[t]);

                    // do c0*aj
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b_scaled, poly_degree, *pool_);
                    util::dyadic_product_coeffmod(temp_rlwe_b, vec_temp_a, poly_degree,mod_coeff_now,temp_rlwe_b_scaled);
                    util::inverse_ntt_negacyclic_harvey(temp_rlwe_b_scaled, ntt_table[t]);

                    // copy new c0 c1 to rlwe
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe.data(1)[l+t*poly_degree] = temp_rlwe_a_scaled[l];
                        temp_rlwe.data(0)[l+t*poly_degree] = temp_rlwe_b_scaled[l];
                    }
                }

                rlwe_evaluator_little_->add_inplace(trivial_rlwe, temp_rlwe);

                // DEBUG
                try {
                    decrypt(trivial_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
                }
                catch (const std::logic_error& e) {
                    // Check if the exception message is the one you expect
                    if (std::string(e.what()) == "encrypted is not valid for encryption parameters") {
                        std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                    } else {
                        // If it's a different logic_error, might want to rethrow or handle differently
                        throw;
                    }
                }
                // std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                for(int x=0; x<print_length; x++){
                    std::cout << Debug_Data.data()[x] << " ";
                }
                std::cout << std::endl;

            }
        }
        
        for (int i=k+1; i<npoly; i++){
            size_t idx = k + npoly - i;
            RLevCipher temp_rlev = temp_rgsw[i];

            // generate a(c1)
            SEAL_ALLOCATE_GET_COEFF_ITER(temp_a, poly_degree*short_mod_size, *pool_);
            for (int j=0; j<short_mod_size; j++){
                for(int l=0; l<poly_degree; l++){
                    temp_a[l+j*poly_degree] = ilwe_copy.data(1)[l*npoly+idx+j*long_poly_degree];
                }
            }

            // DEBUG
            // std::cout << k << "-th " << i << "-th round copy a: ";
            // for(int x=0; x<print_length; x++){
            //     std::cout << temp_a[x] << " ";
            // }
            // std::cout << std::endl;


            for (int j=0; j<(dec_lev); j++){

                // generate aj
                SEAL_ALLOCATE_GET_COEFF_ITER(temp_a_j, short_mod_size*poly_degree, *pool_);
                for (int t=0; t<short_mod_size; t++){
                    for(int l=0; l<poly_degree; l++){
                        temp_a_j[l+t*poly_degree] = temp_a[l+t*poly_degree] >> (dec_base*j);
                        util::modulo_uint_inplace(&temp_a_j[l+t*poly_degree], 1, mod_base);
                    }
                }

                // DEBUG
                std::cout << k << "-th " << i << "-th round " << j << "-th level temp a: ";
                for(int x=0; x<print_length; x++){
                    std::cout << temp_a_j[x] << " ";
                }
                std::cout << std::endl;


                RLWECipher temp_rlwe = temp_rlev[j];

                // generate ntt table
                auto ntt_table = rlwe_context_little_->first_context_data()->small_ntt_tables();
                

                for (int t=0; t<short_mod_size; t++){

                    // Bug May appears here
                    uint64_t mod_coeff_now = *vec_mod[t].data();

                    // generate biased aj in rns form
                    SEAL_ALLOCATE_GET_COEFF_ITER(biased_temp_a_j, poly_degree, *pool_);  
                    biased_temp_a_j[0] = temp_a_j[t*poly_degree+poly_degree-1];
                    biased_temp_a_j[0] = util::negate_uint_mod(biased_temp_a_j[0],mod_coeff_now);
                    for(int l=1; l<poly_degree; l++){
                        biased_temp_a_j[l] = temp_a_j[l+t*poly_degree-1];
                    }

                    // DEBUG
                    std::cout << k << "-th " << i << "-th round " << j << "-th level " << t << "-th RNS biased temp a: ";
                    for(int x=0; x<print_length; x++){
                        std::cout << biased_temp_a_j[x] << " ";
                    }
                    std::cout << std::endl;


                    util::ntt_negacyclic_harvey(biased_temp_a_j, ntt_table[t]);

                    // copy c1
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a, poly_degree, *pool_);
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe_a[l] = temp_rlwe.data(1)[l+t*poly_degree];
                    }
                    util::ntt_negacyclic_harvey(temp_rlwe_a, ntt_table[t]);

                    // do c1*biased aj
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_a_scaled, poly_degree, *pool_);
                    util::dyadic_product_coeffmod(temp_rlwe_a, biased_temp_a_j, poly_degree,mod_coeff_now,temp_rlwe_a_scaled);
                    util::inverse_ntt_negacyclic_harvey(temp_rlwe_a_scaled, ntt_table[t]);

                    // copy c0
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b, poly_degree, *pool_);
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe_b[l] = temp_rlwe.data(0)[l+t*poly_degree];
                    }
                    util::ntt_negacyclic_harvey(temp_rlwe_b, ntt_table[t]);

                    // do c0* biased aj
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp_rlwe_b_scaled, poly_degree, *pool_);
                    util::dyadic_product_coeffmod(temp_rlwe_b, biased_temp_a_j, poly_degree,mod_coeff_now,temp_rlwe_b_scaled);
                    util::inverse_ntt_negacyclic_harvey(temp_rlwe_b_scaled, ntt_table[t]);

                    // copy new c0 c1 to rlwe
                    for (int l=0; l<poly_degree; l++){
                        temp_rlwe.data(1)[l+t*poly_degree] = temp_rlwe_a_scaled[l];
                        temp_rlwe.data(0)[l+t*poly_degree] = temp_rlwe_b_scaled[l];
                    }

                }

                rlwe_evaluator_little_->add_inplace(trivial_rlwe, temp_rlwe);
                // DEBUG
                try {
                    decrypt(trivial_rlwe, Debug_Data, seal::ParamSet::RLWELittle);
                }
                catch (const std::logic_error& e) {
                    // Check if the exception message is the one you expect
                    if (std::string(e.what()) == "encrypted is not valid for encryption parameters") {
                        std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                    } else {
                        // If it's a different logic_error, might want to rethrow or handle differently
                        throw;
                    }
                }
                // std::cout << k << "-th " << i << "-th round " << j << "-th level trivial rlwe: ";
                for(int x=0; x<print_length; x++){
                    std::cout << Debug_Data.data()[x] << " ";
                }
                std::cout << std::endl;


            }
            
        }
        
        vec_olwe[k] = trivial_rlwe;
    }
    std::cout <<"noise budget after switch: " << rlwe_decryptor_little_->invariant_noise_budget(vec_olwe[npoly-1]) << " bits" << std::endl;
    Plaintext ptxt_noise_mul(poly_degree);
    for(int i=0; i<poly_degree; i++){
        ptxt_noise_mul.data()[i] = i;
    }
    // RLWECipher rlwe_temp = vec_olwe[npoly-1];
    // auto context = rlwe_context_little_->get_context_data(rlwe_temp.parms_id());
    // std::cout << "Chain now: " << context->chain_index() << std::endl;
    // rlwe_evaluator_little_->multiply_plain_inplace(rlwe_temp,ptxt_noise_mul);
    // std::cout <<"noise budget after further multiplication: " << rlwe_decryptor_little_->invariant_noise_budget(rlwe_temp) << " bits" << std::endl;

    

    return;
}

void Cryptor::rlwe_context_mod_check()
{
    size_t long_n = RLWEParams::poly_modulus_degree;
    VecData vec_mod_check(long_n, 0ULL);
    size_t print_length = 4;

    RLWECipher ctxt_mod_check(*rlwe_context_);
    encrypt(vec_mod_check, ctxt_mod_check, ParamSet::RLWE);

    std::vector<Modulus> vec_mod = rlwe_parms_->coeff_modulus();
    size_t mod_size = vec_mod.size();
    std::cout << "mod size set as: " << RLWEParams::coeff_modulus_size << std::endl;
    std::cout << "print mod size as: " << mod_size << std::endl;
    std::cout << "cipher mod size as: " << ctxt_mod_check.coeff_modulus_size() << std::endl;
    for (int i=0; i<mod_size; i++){
        std::cout << i << "-th mod is " << *vec_mod[i].data() << " with "<< std::log2(*vec_mod[i].data()) << " bits" << std::endl;
    }

    // generally speaking, [54,60,40] corresponds to 54->0, 60->1, 40->2
    // and ctxt is at [54,60]

    // Next, we try to figure out ntt tables

    auto ntt_tables = rlwe_context_->first_context_data()->small_ntt_tables();
    for (int i=0; i<ctxt_mod_check.coeff_modulus_size(); i++){
        SEAL_ALLOCATE_GET_COEFF_ITER(ntt_test, long_n, *pool_);
        for(int j=0; j<long_n; j++){
            ntt_test[j] = 1;
        }
        util::ntt_negacyclic_harvey(ntt_test, ntt_tables[i]);
        std::cout << i << "-th mod: " << *vec_mod[i].data() << std::endl;
        std::cout << i << "-th ntt result" << std::endl;
        for (int j=0; j<print_length; j++){
            std::cout << ntt_test[j] << " ";
        }
        std::cout << std::endl;
    }

    // as we expected, ntt_table[i] corresponds to i-th prime number NTT transform

    // last question is, what about sec_key? which prime it is in??
    SEAL_ALLOCATE_GET_COEFF_ITER(inv_seckey, RLWEParams::poly_modulus_degree, *pool_)
    std::copy_n(rlwe_seckey_->data().data(), RLWEParams::poly_modulus_degree, (uint64_t *)inv_seckey);
    for(int j=0; j<ctxt_mod_check.coeff_modulus_size(); j++){
        std::cout << j << "-th prim mod: " << *vec_mod[j].data() << std::endl;
        util::inverse_ntt_negacyclic_harvey(inv_seckey, rlwe_context_->first_context_data()->small_ntt_tables()[0]);
        std::cout << j << "-th secret key: ";
        for(int i=0; i<print_length; i++){
            std::cout << inv_seckey[i] << " ";
        }
        std::cout << std::endl;
    }

    // as we expected, sec key is in 0-th prim modulus!

    // when we generate keyswitching key, api automatically generate rns key
    // but we should make it to correct prime number
    // when we do keyswitch, we should do corresponding rns ntt polynomial multiplication

    // next we check the polynomial form of a ciphertext
    for (int i=0; i<ctxt_mod_check.coeff_modulus_size(); i++){
        std::cout << i << "-th prime number " << *vec_mod[i].data() << " with " << std::log2(*vec_mod[i].data()) << " bits" << std::endl;
        std::cout << "c0: ";
        for(int j=0; j<print_length; j++){
            std::cout << ctxt_mod_check.data(0)[j+i*long_n] << " ";
        }
        std::cout << std::endl;
        std::cout << "c1: ";
        for(int j=0; j<print_length; j++){
            std::cout << ctxt_mod_check.data(1)[j+i*long_n] << " ";
        }
        std::cout << std::endl;
    }


    
    return;
}

void Cryptor::keyswitch(const util::ConstRNSIter &poly, const RLevCipher &rlev, RLWECipher &rlwe, const ParamSet paramset) const
{
    auto &rnstool = (paramset == ParamSet::LWE) ? lwe_rnstool_ : rgsw_rnstool_;
    auto &context = (paramset == ParamSet::LWE) ? lwe_context_ : rgsw_context_;
    auto decomposed_level = (paramset == ParamSet::LWE) ? LWEParams::decompose_level : RGSWParams::decompose_level;
    std::vector<std::vector<uint64_t>> crtdecpoly;
    rnstool->CRTDecPoly((const uint64_t *)(poly), crtdecpoly);
    auto coeff_modulus_size = context->first_context_data()->parms().coeff_modulus().size();
    auto poly_modulus_degree = context->first_context_data()->parms().poly_modulus_degree();
    auto ntt_tables = context->first_context_data()->small_ntt_tables();
    std::fill_n(rlwe.data(0), coeff_modulus_size * poly_modulus_degree, 0);
    std::fill_n(rlwe.data(1), coeff_modulus_size * poly_modulus_degree, 0);
    SEAL_ALLOCATE_GET_RNS_ITER(temp, poly_modulus_degree, coeff_modulus_size, *pool_)
    SEAL_ALLOCATE_GET_RNS_ITER(buf0, poly_modulus_degree, coeff_modulus_size, *pool_)
    SEAL_ALLOCATE_GET_RNS_ITER(buf1, poly_modulus_degree, coeff_modulus_size, *pool_)
    util::RNSIter buff[2] = {buf0, buf1};
    for (size_t i = 0; i < decomposed_level; i++) {
        for (size_t j = 0; j < coeff_modulus_size; j++)
            std::copy_n(crtdecpoly[i].begin(), poly_modulus_degree, ((uint64_t *)temp) + j * poly_modulus_degree);
        util::ntt_negacyclic_harvey(temp, coeff_modulus_size, ntt_tables);
        for (size_t k = 0; k < 2; k++) {
            util::dyadic_product_coeffmod(temp, util::ConstRNSIter(rlev[i].data(k), poly_modulus_degree), coeff_modulus_size, context->first_context_data()->parms().coeff_modulus(), buff[k]);
            util::add_poly_coeffmod(buff[k], util::RNSIter(rlwe.data(k), poly_modulus_degree), coeff_modulus_size, context->first_context_data()->parms().coeff_modulus(), util::RNSIter(rlwe.data(k), poly_modulus_degree));
        }
    }
}

const Plaintext &Cryptor::get_lwe_seckey(void) const
{
    return lwe_seckey_->data();
}

void Cryptor::construct_lwe_element(MatrixData &matrix_lwe_A, VecData &vec_lwe_b)
{
    matrix_lwe_A.resize(RLWEParams::poly_modulus_degree, VecData(LWEParams::poly_modulus_degree));
    vec_lwe_b.resize(RLWEParams::poly_modulus_degree);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<RLWEParams::poly_modulus_degree; i++){
        Plaintext ptxt_lwe(RLWEParams::poly_modulus_degree);
        ptxt_lwe.data()[0] = 1; 
        RLWECipher rlwe_ctxt_test;
        encrypt(ptxt_lwe, rlwe_ctxt_test);
        LWECipher lwe_ctxt_extract;
        SampleExtract(rlwe_ctxt_test, lwe_ctxt_extract, 0, 0, seal::ParamSet::RLWE);
        LWECipher lwe_keyswitch;
        lwekeyswitch(lwe_ctxt_extract, lwe_keyswitch);
        vec_lwe_b[i] = lwe_keyswitch.data()[0];
        for (int j=0; j<LWEParams::poly_modulus_degree; j++){
            matrix_lwe_A[i][j] = lwe_keyswitch.data()[j];
        }
        if(i==0){
            uint64_t uint_keyswitch = decrypt(lwe_keyswitch, seal::ParamSet::LWE);
            // lwe encrypt the index-th coefficient of plaintext, we can see here
            std::cout << "golden: " << ptxt_lwe.data()[0]  
                    << " keyswitch decrypt result: " << uint_keyswitch << std::endl;
        }
    }
}

void Cryptor::NWC_NTT_Compare()
{
    uint64_t npoly = RLWEParamsLittle::npoly;
    uint64_t poly_degree = RLWEParamsLittle::poly_modulus_degree;
    std::cout << "polynomial degree: " << poly_degree << std::endl;
    std::vector<Modulus> vec_mod = rlwe_parms_little_->coeff_modulus();
    Modulus mod_coeff(*vec_mod[0].data());
    std::cout << "coefficient mudulus: " << mod_coeff.value() << std::endl;
    auto ntt_tables = rlwe_context_little_->first_context_data()->plain_ntt_tables();
    uint64_t prim_root = rlwe_context_little_->first_context_data()->small_ntt_tables()->get_root();
    std::cout << "primitive root: " << prim_root << std::endl;
    uint64_t inv_prim_root = 0;
    util::try_invert_uint_mod(prim_root, mod_coeff, inv_prim_root);
    std::cout << "invert primitive root: " << inv_prim_root << std::endl;
    uint64_t inv_n = 0;
    util::try_invert_uint_mod(poly_degree, mod_coeff, inv_n);
    std::cout << "invert n is: " << inv_n << std::endl;
    size_t print_length = 8;
    size_t bit_count = util::get_power_of_two(poly_degree) + 1;
    std::cout << "bit count of degree is: " << bit_count << std::endl;
    
    MatrixData ntt_matrix(poly_degree, VecData(poly_degree));
    SEAL_ALLOCATE_GET_COEFF_ITER(ntt_test, poly_degree, *pool_);
    for (int i=0; i<poly_degree; i++){
        for(int j=0; j<poly_degree; j++){
            ntt_test[j] = 0;
        }
        ntt_test[i]=1;
        util::ntt_negacyclic_harvey(ntt_test, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
        for (int j=0; j<poly_degree; j++){
            ntt_matrix[j][i] = ntt_test[j];
        }
    }

    std::cout << "small table NTT matrix is: " << std::endl;
    for(int i=0; i<print_length; i++){
        for(int j=0; j<print_length; j++){
            std::cout << ntt_matrix[i][j] << " ";
        }
        std::cout << std::endl;
    }

    MatrixData ntt_matrix_index(print_length, VecData(print_length));
    for (int i=0; i<print_length; i++){
        for (int j=0; j<print_length; j++){
            for (int t=0; t<2*poly_degree; t++){
                uint64_t temp = util::exponentiate_uint_mod(prim_root, t, mod_coeff);
                if(temp == ntt_matrix[i][j]){
                    ntt_matrix_index[i][j] = t;
                    break;
                }
            }
        }
    }

    std::cout << "small table NTT index is: " << std::endl;
    for(int i=0; i<print_length; i++){
        for(int j=0; j<print_length; j++){
            std::cout << ntt_matrix_index[i][j] << " ";
        }
        std::cout << std::endl;
    }

    MatrixData manual_construct_index_ntt_matrix(poly_degree, VecData(poly_degree));
    for(uint64_t i=0; i<print_length; i++){
        for(int j=0; j<print_length; j++){
            manual_construct_index_ntt_matrix[i][j] = util::reverse_bits(i, bit_count) * j + j;
            manual_construct_index_ntt_matrix[i][j] = manual_construct_index_ntt_matrix[i][j] % (2*poly_degree);
        }
    }

    std::cout << "mannual construct NTT index matrix is: " << std::endl;
    for(int i=0; i<print_length; i++){
        for(int j=0; j<print_length; j++){
            std::cout << manual_construct_index_ntt_matrix[i][j] << " ";
        }
        std::cout << std::endl;
    }

    // util::dyadic_product_coeffmod(temp_rlwe_b, vec_temp_a, poly_degree,mod_coeff,temp_rlwe_b_scaled);
    // util::inverse_ntt_negacyclic_harvey(temp_rlwe_b_scaled, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
    // util::inverse_ntt_negacyclic_harvey(temp_rlwe_a_scaled, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);

    // Now we know that ntt matrix of seal is bitreversed order (remember bitcount + 1!!)
    // Next we try to find intt matrix order!

    MatrixData inverse_ntt_matrix(poly_degree, VecData(poly_degree));
    SEAL_ALLOCATE_GET_COEFF_ITER(inverse_ntt_test, poly_degree, *pool_);
    for (int i=0; i<poly_degree; i++){
        for(int j=0; j<poly_degree; j++){
            inverse_ntt_test[j] = 0;
        }
        inverse_ntt_test[i]=1;
        util::inverse_ntt_negacyclic_harvey(inverse_ntt_test, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
        for (int j=0; j<poly_degree; j++){
            inverse_ntt_matrix[j][i] = inverse_ntt_test[j];
        }
    }

    std::cout << "small table invert NTT matrix is: " << std::endl;
    for(int i=0; i<print_length; i++){
        for(int j=0; j<print_length; j++){
            std::cout << inverse_ntt_matrix[i][j] << " ";
        }
        std::cout << std::endl;
    }

    std::cout << "N * inverte NTT matrix is: " << std::endl;
    for(int i=0; i<print_length; i++){
        for(int j=0; j<print_length; j++){
            std::cout << util::multiply_uint_mod(inverse_ntt_matrix[i][j], poly_degree, mod_coeff) << " ";
        }
        std::cout << std::endl;
    }

    MatrixData inverse_ntt_matrix_index(print_length, VecData(print_length));
    for (int i=0; i<print_length; i++){
        for (int j=0; j<print_length; j++){
            for (int t=0; t<2*poly_degree; t++){
                uint64_t temp = util::exponentiate_uint_mod(inv_prim_root, t, mod_coeff);
                if(temp == util::multiply_uint_mod(inverse_ntt_matrix[i][j],poly_degree, mod_coeff)){
                    inverse_ntt_matrix_index[i][j] = t;
                    break;
                }
            }
        }
    }

    std::cout << "small table invert NTT index is: " << std::endl;
    for(int i=0; i<print_length; i++){
        for(int j=0; j<print_length; j++){
            std::cout << inverse_ntt_matrix_index[i][j] << " ";
        }
        std::cout << std::endl;
    }

    MatrixData manual_construct_index_invert_ntt_matrix(poly_degree, VecData(poly_degree));
    for(uint64_t i=0; i<print_length; i++){
        for(int j=0; j<print_length; j++){
            manual_construct_index_invert_ntt_matrix[i][j] = util::reverse_bits(i, bit_count) * j + j;
            manual_construct_index_invert_ntt_matrix[i][j] = manual_construct_index_invert_ntt_matrix[i][j] % (2*poly_degree);
        }
    }

    std::cout << "mannual construct invert NTT index matrix is: " << std::endl;
    for(int i=0; i<print_length; i++){
        for(int j=0; j<print_length; j++){
            std::cout << manual_construct_index_invert_ntt_matrix[i][j] << " ";
        }
        std::cout << std::endl;
    }

    // Now we know that INTT matrix is also in reversed order

    // Next let's try polynomial multiplication!
    SEAL_ALLOCATE_GET_COEFF_ITER(poly1, poly_degree, *pool_);
    SEAL_ALLOCATE_GET_COEFF_ITER(poly2, poly_degree, *pool_);
    SEAL_ALLOCATE_GET_COEFF_ITER(poly3, poly_degree, *pool_);
    for(int i=0; i<poly_degree; i++){
        poly1[i] = i;
        poly2[i] = 1;
    }
    util::ntt_negacyclic_harvey(poly1, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
    util::ntt_negacyclic_harvey(poly2, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
    util::dyadic_product_coeffmod(poly1, poly2, poly_degree, mod_coeff, poly3);
    util::inverse_ntt_negacyclic_harvey(poly3, rlwe_context_little_->first_context_data()->small_ntt_tables()[0]);
    std::cout << "ntt poly result: ";
    for (int i=0; i<print_length; i++){
        std::cout << poly3[i] << " ";
    }
    std::cout << std::endl;

    // we set golden firstly
    VecData vec_1(poly_degree, 0ULL);
    VecData vec_2(poly_degree, 0ULL);
    for(int i=0; i<poly_degree; i++){
        vec_1[i] = i;
        vec_2[i] = 1;
    }
    VecData vec_3(poly_degree, 0ULL);
    util::NWC_Manual(vec_1, vec_2, poly_degree, 1, mod_coeff, {mod_coeff}, vec_3);
    
    std::cout << "golden poly result: ";
    for (int i=0; i<print_length; i++){
        std::cout << vec_3[i] << " ";
    }
    std::cout << std::endl;

    // really strange! they are same?? so problem comes from coding?


    return;
}

// NTT test part
void Cryptor::show_encode_step() const{

    // uint64_t slot = seal::RLWEParams::poly_modulus_degree;
    uint64_t slot = 4;
    seal::Modulus mod_plain(17);
    seal::Modulus mod_degree(2*slot);
    uint64_t degree_inv;
    seal::util::try_invert_uint_mod(slot, mod_plain, degree_inv);
    uint64_t root = 0;
    seal::util::try_minimal_primitive_root(2*slot, mod_plain, root);
    std::cout << "degree: " << slot << " plain: " << *mod_plain.data() << " root: " << root << std::endl;

    std::vector<uint64_t> values_matrix(slot, 1ULL);
    for (int i=0; i<slot; i++){
        values_matrix[i] = i;
    }

    std::cout << "intput vector: ";
    for(int i=0; i<slot; i++){
        std::cout << values_matrix[i] << " ";
    }
    std::cout << std::endl;

    // std::vector<uint64_t> encode_api(slot, 0ULL);
    uint64_t *encode_api = new uint64_t[slot]();


    size_t values_matrix_size = values_matrix.size();
    // size_t values_matrix_size = slot;


    util::Pointer<std::size_t> matrix_reps_index_map_;
    MemoryPoolHandle pool_ = MemoryManager::GetPool();

    int logn = seal::util::get_power_of_two(slot);
    matrix_reps_index_map_ = seal::util::allocate<size_t>(slot, pool_);
    // seal::VecData matrix_reps_index_map_(slot, 0ULL);

    // Copy from the matrix to the value vectors
    size_t row_size = slot >> 1;
    size_t m = slot << 1;
    uint64_t gen = 3;
    uint64_t pos = 1;
    for (size_t i = 0; i < row_size; i++)
    {
        // Position in normal bit order
        uint64_t index1 = (pos - 1) >> 1;
        uint64_t index2 = (m - pos - 1) >> 1;

        // Set the bit-reversed locations
        matrix_reps_index_map_[i] = util::safe_cast<size_t>(util::reverse_bits(index1, logn));
        matrix_reps_index_map_[row_size | i] = util::safe_cast<size_t>(util::reverse_bits(index2, logn));

        // Next primitive root
        pos *= gen;
        pos &= (m - 1);
    }

    std::cout << "index map is: " << std::endl;
    for (int i=0; i<slot; i++){
        std::cout << matrix_reps_index_map_[i] << " ";
    }
    std::cout << std::endl;

    for (int i=0; i<slot; i++){
        for (int j = logn - 1; j >= 0; --j) {
            size_t temp = matrix_reps_index_map_[i];
            std::cout << ((temp >> j) & 1);
        }
        std::cout << " ";
    }
    std::cout << std::endl;

    // First write the values to destination coefficients.
    // Read in top row, then bottom row.
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        *(encode_api + matrix_reps_index_map_[i]) = values_matrix[i];
    }
    for (size_t i = values_matrix_size; i < slot; i++)
    {
        *(encode_api + matrix_reps_index_map_[i]) = 0;
    }

    std::cout << "encode_api after map is: ";
    for (int i=0; i<slot; i++){
        std::cout << encode_api[i] << " ";
    }
    std::cout << std::endl;

    // seal::util::Pointer<util::NTTTables> plain_ntt_tables_;
    // seal::util::CreateNTTTables(logn, { mod_plain }, plain_ntt_tables_, pool_);

    // seal::util::inverse_ntt_negacyclic_harvey(encode_api, *plain_ntt_tables_.get());
    // which equals to
    // seal::util::inverse_ntt_negacyclic_harvey_lazy(encode_api, *plain_ntt_tables_.get());
    // which also equals to
    // seal::util::MultiplyUIntModOperand inv_degree_modulo = plain_ntt_tables_->inv_degree_modulo();
    // plain_ntt_tables_->ntt_handler().transform_from_rev(
    //     encode_api, plain_ntt_tables_->coeff_count_power(), plain_ntt_tables_->get_from_inv_root_powers(), &inv_degree_modulo);
    // which finally equals to
    uint64_t *api_head = encode_api;
    uint64_t *values = encode_api;
    // const seal::util::MultiplyUIntModOperand *roots = plain_ntt_tables_->get_from_inv_root_powers();
    // std::cout << "Size of roots: " << sizeof(roots) << std::endl;
    seal::util::MultiplyUIntModOperand *roots = new seal::util::MultiplyUIntModOperand[slot];
    seal::util::MultiplyUIntModOperand *roots_head = roots;
    roots[0].operand = 1;
    uint64_t root_inv = 0;
    seal::util::try_invert_uint_mod(root, mod_plain, root_inv);
    uint64_t power = root_inv;
    uint64_t degree_power = seal::util::get_power_of_two(slot);
    for(size_t i=1; i<slot; i++){
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i-1, mod_degree);
        // exp = seal::util::sub_uint_mod(2*slot, exp, mod_degree);
        // roots[i].operand = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
        int idx = seal::util::reverse_bits(i - 1, degree_power) + 1;
        // std::cout << "idx: " << idx << std::endl;
        roots[idx].operand = power;
        power = seal::util::multiply_uint_mod(power, root_inv, mod_plain);
    }
    std::cout << "roots: ";
    for (int i=0; i<slot; i++){
        std::cout << roots[i].operand << " ";
    }
    std::cout << std::endl;
    // find out index of roots
    std::vector<int> roots_idx(slot, 0ULL);
    roots_idx[0] = 0;
    for(int i=1; i<slot; i++){
        for(int j=0; j<2*slot; j++){
            if(seal::util::exponentiate_uint_mod(root, j, mod_plain) == roots[i].operand){
                roots_idx[i] = -(2*slot - j);
                continue;
            }
        }
    }
    std::cout << "roots index: ";
    for (int i=0; i<slot; i++){
        std::cout << roots_idx[i] << " ";
    }
    std::cout << std::endl;
    std::cout << "roots: ";
    for (int i=0; i<slot; i++){
        std::cout << roots[i].operand << " ";
    }
    std::cout << std::endl;
    // const seal::util::MultiplyUIntModOperand *scalar = &plain_ntt_tables_->inv_degree_modulo();
    seal::util::MultiplyUIntModOperand *scalar = new seal::util::MultiplyUIntModOperand[1];
    seal::util::MultiplyUIntModOperand *scalar_head = scalar;
    seal::util::try_invert_uint_mod(slot, mod_plain, scalar->operand);
    std::cout << "inv_degree_modulo: " << scalar->operand << std::endl;
    
    // seal::util::Arithmetic<uint64_t, seal::util::MultiplyUIntModOperand, seal::util::MultiplyUIntModOperand> arithmetic_;
    // constant transform size
    size_t n = size_t(1) << logn;
    // registers to hold temporary values
    seal::util::MultiplyUIntModOperand r;
    uint64_t u;
    uint64_t v;
    // pointers for faster indexing
    uint64_t *x = nullptr;
    uint64_t *y = nullptr;
    // variables for indexing
    std::size_t gap = 1;
    std::size_t m_2 = n >> 1;
    // DEBUG
    std::cout << "m_2: " << m_2 << std::endl;

    // some variable just for debug
    int x_index = 0;
    int y_index = 0;
    int u_index = 0;
    int v_index = 0;
    int root_index = 0;
    int value_index = 0;

    std::cout << "vlaues: " << std::endl;
    for (int i=0; i<slot; i++){
        std::cout << values[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "Start Encode INTT: " << std::endl;

    for (; m_2 > 1; m_2 >>= 1)
    {
        // DEBUG
        std::cout << "m_2: " << m_2 << std::endl;
        std::cout << "gap: " << gap << std::endl;

        std::size_t offset = 0;
        if (gap < 4)
        {
            for (std::size_t i = 0; i < m_2; i++)
            {
                std::cout << "gap < 4" << std::endl;
                std::cout << "i: " << i << std::endl;
                r = *++roots;                                       root_index++; std::cout << "root_index: " << root_index << std::endl;
                std::cout << "r: " << r.operand << std::endl;
                std::cout << "roots: ";
                for (int i=0; i<slot; i++){
                    std::cout << roots[i].operand << " ";
                }
                std::cout << std::endl;
                x = values + offset;                                x_index = value_index + offset; std::cout << "x_index: " << x_index << std::endl;
                std::cout << "x: " << *x << std::endl;
                y = x + gap;                                        y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
                std::cout << "y: " << *y << std::endl;
                for (std::size_t j = 0; j < gap; j++)
                {
                    u = *x;                                         u_index = x_index;
                    std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++;
                    std::cout << "vlaues: " << std::endl;
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;
                }
                offset += gap << 1;                                 std::cout << "off set: " << offset << std::endl;
            }
        }
        else
        {
            for (std::size_t i = 0; i < m_2; i++)
            {
                std::cout << "gap !< 4" << std::endl;
                std::cout << "i: " << i << std::endl;
                r = *++roots;                                       root_index++; std::cout << "root_index: " << root_index << std::endl;
                std::cout << "r: " << r.operand << std::endl;
                std::cout << "roots: ";
                for (int i=0; i<slot; i++){
                    std::cout << roots[i].operand << " ";
                }
                std::cout << std::endl;
                x = values + offset;                                x_index = value_index + offset; std::cout << "x_index: " << x_index << std::endl;
                std::cout << "x: " << *x << std::endl;
                y = x + gap;                                        y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
                std::cout << "y: " << *y << std::endl;
                for (std::size_t j = 0; j < gap; j += 4)
                {
                    u = *x;                                         u_index = x_index;
                    std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    std::cout << "vlaues: " << std::endl;
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;

                    u = *x;                                         u_index = x_index;
                    std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    std::cout << "vlaues: " << std::endl;
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;

                    u = *x;                                         u_index = x_index;
                    std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;
                    
                    u = *x;                                         u_index = x_index;
                    std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;
                    
                }
                offset += gap << 1;
            }
        }
        gap <<= 1;
    }
    std::cout << "for loop done" << std::endl;
    std::cout << std::endl;
    std::cout << "roots: ";
    for (int i=0; i<slot; i++){
        std::cout << roots[i].operand << " ";
    }
    std::cout << std::endl;

    x_index = 0;
    y_index = 0;
    u_index = 0;
    v_index = 0;
    // root_index = 0;
    if (scalar != nullptr)
    {
        r = *++roots;                                       root_index++; std::cout << "root_index: " << root_index << std::endl;
        std::cout << "r: " << r.operand << std::endl;
        std::cout << "roots: ";
        for (int i=0; i<slot; i++){
            std::cout << roots[i].operand << " ";
        }
        std::cout << std::endl;
        const uint64_t scaled_r = util::multiply_uint_mod(r.operand, scalar->operand, mod_plain);
        std::cout << "scaled_r: " << scaled_r << std::endl;
        x = values;                                         x_index = x_index; std::cout << "x_index: " << x_index << std::endl;
        std::cout << "x: " << *x << std::endl;
        y = x + gap;                                        y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
        std::cout << "y: " << *y << std::endl;
        if (gap < 4)
        {
            for (size_t j = 0; j < gap; j++)
            {
                std::cout << "gap < 4" << std::endl;
                std::cout << "j: " << j << std::endl;
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                                                                v_index = y_index;   
                std::cout << "v: " << v << std::endl;                                                            
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * scalar"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                     
            }
        }
        else
        {
            for (std::size_t j = 0; j < gap; j += 4)
            {
                std::cout << "gap !< 4" << std::endl;
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
            }
        }
    }
    else
    {
        r = *++roots;                                       root_index++; std::cout << "root_index: " << root_index << std::endl;
        std::cout << "r: " << r.operand << std::endl;
        std::cout << "roots: ";
        for (int i=0; i<slot; i++){
            std::cout << roots[i].operand << " ";
        }
        std::cout << std::endl;
        x = values;                                         x_index = value_index; std::cout << "x_index: " << x_index << std::endl;
        std::cout << "x: " << *x << std::endl;
        y = x + gap;                                        y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
        std::cout << "y: " << *y << std::endl;
        if (gap < 4)
        {
            for (std::size_t j = 0; j < gap; j++)
            {
                std::cout << "j: " << j << std::endl;
                u = *x;                                         u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
            }
        }
        else
        {
            for (std::size_t j = 0; j < gap; j += 4)
            {
                std::cout << "j: " << j << std::endl;
                u = *x;                                         u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = *x;                                         u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = *x;                                         u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = *x;                                         u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
            }
        }
    }
    std::cout << std::endl;
    std::cout << "roots: ";
    for (int i=0; i<slot; i++){
        std::cout << roots[i].operand << " ";
    }
    std::cout << std::endl;


    // Final adjustments; compute a[j] = a[j] * n^{-1} mod q.
    // We incorporated the final adjustment in the butterfly. Only need to reduce here.
    for(int i=0; i<slot; i++){
        if(encode_api[i] >= *mod_plain.data()){
            encode_api[i] -= *mod_plain.data();
        }
    }

    std::cout << "Encode result is: ";
    for (int i=0; i<slot; i++){
        std::cout << encode_api[i] << " ";
    }
    std::cout << std::endl;

    // gen encode matrix
    seal::MatrixData matrix_encode;
    matrix_encode.resize(slot, seal::VecData(slot));
    for (int i=slot/2; i<slot; i++)
    {   
        uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
        for (int j=0; j<slot; j++){
            matrix_encode[j][i] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            matrix_encode[j][i] = seal::util::multiply_uint_mod(matrix_encode[j][i], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }
    for (int i=0; i<slot/2; i++)
    {   
        uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
        seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        for (int j=0; j<slot; j++){
            matrix_encode[j][i] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            matrix_encode[j][i] = seal::util::multiply_uint_mod(matrix_encode[j][i], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }

    // std::cout << "Encode Matrix: " << std::endl;
    // for (int i=0; i<slot; i++){
    //     for (int j=0; j<slot; j++){
    //         std::cout << matrix_encode[i][j] << " ";
    //     }
    //     std::cout << std::endl;
    // }

    // encode to plaintext
    seal::VecData ptxt_encode(slot, 0);
    for(int i=0; i<slot; i++){
        for(int j=0; j<slot; j++){
            ptxt_encode[i] = seal::util::add_uint_mod(ptxt_encode[i], seal::util::multiply_uint_mod(matrix_encode[i][j], values_matrix[j], mod_plain), mod_plain);
        }
    }

    std::cout << "Manual encode result is: ";
    for (int i=0; i<slot; i++){
        std::cout << ptxt_encode[i] << " ";
    }
    std::cout << std::endl;
    std::cout << "Done" << std::endl;

    // seal::VecData decode_api(slot, 0ULL);

    // // Do decode
    // auto temp_dest(seal::util::allocate_uint(slot, pool_));
    // // make a copy of poly
    // seal::util::set_uint(encode_api, slot, temp_dest.get());
    // // Transform destination using negacyclic NTT.
    // seal::util::ntt_negacyclic_harvey(temp_dest.get(), *plain_ntt_tables_.get());
    // // Read top row, then bottom row
    // for (size_t i = 0; i < slot; i++)
    // {
    //     decode_api[i] = temp_dest[matrix_reps_index_map_[i]];
    // }
    // // std::cout << "Decode result is: ";
    // // for (int i=0; i<slot; i++){
    // //     std::cout << decode_api[i] << " ";
    // // }
    // // std::cout << std::endl;

    // seal::MatrixData matrix_decode;
    // matrix_decode.resize(slot, seal::VecData(slot));
    // // gen decode matrix
    // for (int i=0; i<slot/2; i++)
    // {   
    //     uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
    //     uint64_t zeta = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
    //     for (int j=0; j<slot; j++){
    //         matrix_decode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
    //     }
    // }
    // for (int i=slot/2; i<slot; i++)
    // {   
    //     uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
    //     uint64_t zeta = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
    //     seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
    //     for (int j=0; j<slot; j++){
    //         matrix_decode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
    //     }
    // }

    // std::cout << "Decode Matrix: " << std::endl;
    // for (int i=0; i<slot; i++){
    //     for (int j=0; j<slot; j++){
    //         std::cout << matrix_decode[i][j] << " ";
    //     }
    //     std::cout << std::endl;
    // }

    // seal::VecData vec_decode(slot, 0);
    // for(int i=0; i<slot; i++){
    //     for(int j=0; j<slot; j++){
    //         vec_decode[i] = seal::util::add_uint_mod(vec_decode[i], seal::util::multiply_uint_mod(matrix_decode[i][j], ptxt_encode[j], mod_plain), mod_plain);
    //     }
    // }

    // std::cout << "Manual decode result is: ";
    // for (int i=0; i<slot; i++){
    //     std::cout << vec_decode[i] << " ";
    // }
    // std::cout << std::endl;
    

    // Memory mangement
    // delete []scalar_head;
    // delete []roots_head;
    // delete []api_head;

    // Cryptor cryptor;
    // // vec construct in way 1
    // seal::VecData vec_s2c_test(seal::RLWEParams::poly_modulus_degree, 0ULL);
    // for (int i = 0; i < seal::RLWEParams::poly_modulus_degree; i++)
    // {
    //     vec_s2c_test.data()[i] = i;
    //     // vec_s2c_test.data()[i + RLWEParams::poly_modulus_degree/2] = 2;
    // }
    // // vec_s2c_test.data()[2] = 1;
    // seal::Plaintext ptxt_s2c_test;
    // cryptor.encode_manual(vec_s2c_test, ptxt_s2c_test);
    // cryptor.decode_manual(ptxt_s2c_test,vec_s2c_test);
    return;
}

void Cryptor::intt_extract_matrix_compare() const
{

    // uint64_t slot = seal::RLWEParams::poly_modulus_degree;
    uint64_t slot = 8;
    seal::Modulus mod_plain(17);
    seal::Modulus mod_degree(2*slot);
    uint64_t degree_inv;
    seal::util::try_invert_uint_mod(slot, mod_plain, degree_inv);
    uint64_t root = 0;
    seal::util::try_minimal_primitive_root(2*slot, mod_plain, root);
    std::cout << "degree: " << slot << " plain: " << *mod_plain.data() << " root: " << root << std::endl;

    std::vector<uint64_t> values_matrix(slot, 1ULL);
    for (int i=0; i<slot; i++){
        values_matrix[i] = i;
    }

    std::cout << "intput vector: ";
    for(int i=0; i<slot; i++){
        std::cout << values_matrix[i] << " ";
    }
    std::cout << std::endl;

    // std::vector<uint64_t> encode_api(slot, 0ULL);
    uint64_t *encode_api = new uint64_t[slot]();


    size_t values_matrix_size = values_matrix.size();
    // size_t values_matrix_size = slot;


    util::Pointer<std::size_t> matrix_reps_index_map_;
    MemoryPoolHandle pool_ = MemoryManager::GetPool();

    int logn = seal::util::get_power_of_two(slot);
    matrix_reps_index_map_ = seal::util::allocate<size_t>(slot, pool_);
    // seal::VecData matrix_reps_index_map_(slot, 0ULL);

    // Copy from the matrix to the value vectors
    // we don't need this for pure INTT
    size_t row_size = slot >> 1;
    size_t m = slot << 1;
    uint64_t gen = 3;
    uint64_t pos = 1;
    for (size_t i = 0; i < slot; i++)
    {   

        // // Position in normal bit order
        // uint64_t index1 = (pos - 1) >> 1;
        // uint64_t index2 = (m - pos - 1) >> 1;

        // // Set the bit-reversed locations
        // matrix_reps_index_map_[i] = util::safe_cast<size_t>(util::reverse_bits(index1, logn));
        // matrix_reps_index_map_[row_size | i] = util::safe_cast<size_t>(util::reverse_bits(index2, logn));

        // // Next primitive root
        // pos *= gen;
        // pos &= (m - 1);

        matrix_reps_index_map_[i] = seal::util::reverse_bits(i, logn);
    }

    // INTT should be in bit reversed order!
    // matrix_reps_index_map_[0] = 0;
    // matrix_reps_index_map_[1] = 2;
    // matrix_reps_index_map_[2] = 1;
    // matrix_reps_index_map_[3] = 3;

    std::cout << "index map is: " << std::endl;
    for (int i=0; i<slot; i++){
        std::cout << matrix_reps_index_map_[i] << " ";
    }
    std::cout << std::endl;

    for (int i=0; i<slot; i++){
        for (int j = logn - 1; j >= 0; --j) {
            size_t temp = matrix_reps_index_map_[i];
            std::cout << ((temp >> j) & 1);
        }
        std::cout << " ";
    }
    std::cout << std::endl;

    // First write the values to destination coefficients.
    // Read in top row, then bottom row.
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        *(encode_api + matrix_reps_index_map_[i]) = values_matrix[i];
    }
    for (size_t i = values_matrix_size; i < slot; i++)
    {
        *(encode_api + matrix_reps_index_map_[i]) = 0;
    }

    std::cout << "encode_api after map is: ";
    for (int i=0; i<slot; i++){
        std::cout << encode_api[i] << " ";
    }
    std::cout << std::endl;

    // seal::util::Pointer<util::NTTTables> plain_ntt_tables_;
    // seal::util::CreateNTTTables(logn, { mod_plain }, plain_ntt_tables_, pool_);

    // seal::util::inverse_ntt_negacyclic_harvey(encode_api, *plain_ntt_tables_.get());
    // which equals to
    // seal::util::inverse_ntt_negacyclic_harvey_lazy(encode_api, *plain_ntt_tables_.get());
    // which also equals to
    // seal::util::MultiplyUIntModOperand inv_degree_modulo = plain_ntt_tables_->inv_degree_modulo();
    // plain_ntt_tables_->ntt_handler().transform_from_rev(
    //     encode_api, plain_ntt_tables_->coeff_count_power(), plain_ntt_tables_->get_from_inv_root_powers(), &inv_degree_modulo);
    // which finally equals to
    uint64_t *api_head = encode_api;
    uint64_t *values = encode_api;
    // const seal::util::MultiplyUIntModOperand *roots = plain_ntt_tables_->get_from_inv_root_powers();
    // std::cout << "Size of roots: " << sizeof(roots) << std::endl;
    seal::util::MultiplyUIntModOperand *roots = new seal::util::MultiplyUIntModOperand[slot];
    seal::util::MultiplyUIntModOperand *roots_head = roots;
    roots[0].operand = 1;
    uint64_t root_inv = 0;
    seal::util::try_invert_uint_mod(root, mod_plain, root_inv);
    std::cout << "root_inv: " << root_inv << std::endl; 
    uint64_t power = root_inv;
    uint64_t degree_power = seal::util::get_power_of_two(slot);
    for(size_t i=1; i<slot; i++){
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i-1, mod_degree);
        // exp = seal::util::sub_uint_mod(2*slot, exp, mod_degree);
        // roots[i].operand = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
        int idx = seal::util::reverse_bits(i - 1, degree_power) + 1;
        // std::cout << "idx: " << idx << std::endl;
        roots[idx].operand = power;
        power = seal::util::multiply_uint_mod(power, root_inv, mod_plain);
    }
    std::cout << "roots: ";
    for (int i=0; i<slot; i++){
        std::cout << roots[i].operand << " ";
    }
    std::cout << std::endl;
    // find out index of roots
    std::vector<int> roots_idx(slot, 0ULL);
    roots_idx[0] = 0;
    for(int i=1; i<slot; i++){
        for(int j=0; j<2*slot; j++){
            if(seal::util::exponentiate_uint_mod(root, j, mod_plain) == roots[i].operand){
                roots_idx[i] = -(2*slot - j);
                continue;
            }
        }
    }
    std::cout << "roots index: ";
    for (int i=0; i<slot; i++){
        std::cout << roots_idx[i] << " ";
    }
    std::cout << std::endl;
    std::cout << "roots: ";
    for (int i=0; i<slot; i++){
        std::cout << roots[i].operand << " ";
    }
    std::cout << std::endl;
    // const seal::util::MultiplyUIntModOperand *scalar = &plain_ntt_tables_->inv_degree_modulo();
    seal::util::MultiplyUIntModOperand *scalar = new seal::util::MultiplyUIntModOperand[1];
    seal::util::MultiplyUIntModOperand *scalar_head = scalar;
    seal::util::try_invert_uint_mod(slot, mod_plain, scalar->operand);
    std::cout << "inv_degree_modulo: " << scalar->operand << std::endl;
    
    // seal::util::Arithmetic<uint64_t, seal::util::MultiplyUIntModOperand, seal::util::MultiplyUIntModOperand> arithmetic_;
    // constant transform size
    size_t n = size_t(1) << logn;
    // registers to hold temporary values
    seal::util::MultiplyUIntModOperand r;
    uint64_t u;
    uint64_t v;
    // pointers for faster indexing
    uint64_t *x = nullptr;
    uint64_t *y = nullptr;
    // variables for indexing
    std::size_t gap = 1;
    std::size_t m_2 = n >> 1;
    // DEBUG
    std::cout << "m_2: " << m_2 << std::endl;

    // some variable just for debug
    int x_index = 0;
    int y_index = 0;
    int u_index = 0;
    int v_index = 0;
    int root_index = 0;
    int value_index = 0;

    std::cout << "vlaues: " << std::endl;
    for (int i=0; i<slot; i++){
        std::cout << values[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "Start Encode INTT: " << std::endl;

    for (; m_2 > 1; m_2 >>= 1)
    {
        // DEBUG
        std::cout << "m_2: " << m_2 << std::endl;
        std::cout << "gap: " << gap << std::endl;

        std::size_t offset = 0;
        if (gap < 4)
        {
            for (std::size_t i = 0; i < m_2; i++)
            {
                std::cout << "gap < 4" << std::endl;
                std::cout << "i: " << i << std::endl;
                r = *++roots;                                       root_index++; std::cout << "root_index: " << root_index << std::endl;
                std::cout << "r: " << r.operand << std::endl;
                std::cout << "roots: ";
                for (int i=0; i<slot; i++){
                    std::cout << roots[i].operand << " ";
                }
                std::cout << std::endl;
                x = values + offset;                                x_index = value_index + offset; std::cout << "x_index: " << x_index << std::endl;
                std::cout << "x: " << *x << std::endl;
                y = x + gap;                                        y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
                std::cout << "y: " << *y << std::endl;
                for (std::size_t j = 0; j < gap; j++)
                {
                    u = *x;                                         u_index = x_index;
                    std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++;
                    std::cout << "vlaues: " << std::endl;
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;
                }
                offset += gap << 1;                                 std::cout << "off set: " << offset << std::endl;
            }
        }
        else
        {
            for (std::size_t i = 0; i < m_2; i++)
            {
                std::cout << "gap !< 4" << std::endl;
                std::cout << "i: " << i << std::endl;
                r = *++roots;                                       root_index++; std::cout << "root_index: " << root_index << std::endl;
                std::cout << "r: " << r.operand << std::endl;
                std::cout << "roots: ";
                for (int i=0; i<slot; i++){
                    std::cout << roots[i].operand << " ";
                }
                std::cout << std::endl;
                x = values + offset;                                x_index = value_index + offset; std::cout << "x_index: " << x_index << std::endl;
                std::cout << "x: " << *x << std::endl;
                y = x + gap;                                        y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
                std::cout << "y: " << *y << std::endl;
                for (std::size_t j = 0; j < gap; j += 4)
                {
                    u = *x;                                         u_index = x_index;
                    std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    std::cout << "vlaues: " << std::endl;
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;

                    u = *x;                                         u_index = x_index;
                    std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    std::cout << "vlaues: " << std::endl;
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;

                    u = *x;                                         u_index = x_index;
                    std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;
                    
                    u = *x;                                         u_index = x_index;
                    std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;
                    
                }
                offset += gap << 1;
            }
        }
        gap <<= 1;
    }
    std::cout << "for loop done" << std::endl;
    std::cout << std::endl;
    std::cout << "roots: ";
    for (int i=0; i<slot; i++){
        std::cout << roots[i].operand << " ";
    }
    std::cout << std::endl;

    x_index = 0;
    y_index = 0;
    u_index = 0;
    v_index = 0;
    // root_index = 0;
    if (scalar != nullptr)
    {
        r = *++roots;                                       root_index++; std::cout << "root_index: " << root_index << std::endl;
        std::cout << "r: " << r.operand << std::endl;
        std::cout << "roots: ";
        for (int i=0; i<slot; i++){
            std::cout << roots[i].operand << " ";
        }
        std::cout << std::endl;
        const uint64_t scaled_r = util::multiply_uint_mod(r.operand, scalar->operand, mod_plain);
        std::cout << "scaled_r: " << scaled_r << std::endl;
        x = values;                                         x_index = x_index; std::cout << "x_index: " << x_index << std::endl;
        std::cout << "x: " << *x << std::endl;
        y = x + gap;                                        y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
        std::cout << "y: " << *y << std::endl;
        if (gap < 4)
        {
            for (size_t j = 0; j < gap; j++)
            {
                std::cout << "gap < 4" << std::endl;
                std::cout << "j: " << j << std::endl;
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                                                                v_index = y_index;   
                std::cout << "v: " << v << std::endl;                                                            
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * scalar"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                     
            }
        }
        else
        {
            for (std::size_t j = 0; j < gap; j += 4)
            {
                std::cout << "gap !< 4" << std::endl;
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
            }
        }
    }
    else
    {
        r = *++roots;                                       root_index++; std::cout << "root_index: " << root_index << std::endl;
        std::cout << "r: " << r.operand << std::endl;
        std::cout << "roots: ";
        for (int i=0; i<slot; i++){
            std::cout << roots[i].operand << " ";
        }
        std::cout << std::endl;
        x = values;                                         x_index = value_index; std::cout << "x_index: " << x_index << std::endl;
        std::cout << "x: " << *x << std::endl;
        y = x + gap;                                        y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
        std::cout << "y: " << *y << std::endl;
        if (gap < 4)
        {
            for (std::size_t j = 0; j < gap; j++)
            {
                std::cout << "j: " << j << std::endl;
                u = *x;                                         u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
            }
        }
        else
        {
            for (std::size_t j = 0; j < gap; j += 4)
            {
                std::cout << "j: " << j << std::endl;
                u = *x;                                         u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = *x;                                         u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = *x;                                         u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
                u = *x;                                         u_index = x_index;
                std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                for (int i=0; i<slot; i++){
                    std::cout << values[i] << " ";
                }
                std::cout << std::endl;
                    
            }
        }
    }
    std::cout << std::endl;
    std::cout << "roots: ";
    for (int i=0; i<slot; i++){
        std::cout << roots[i].operand << " ";
    }
    std::cout << std::endl;


    // Final adjustments; compute a[j] = a[j] * n^{-1} mod q.
    // We incorporated the final adjustment in the butterfly. Only need to reduce here.
    for(int i=0; i<slot; i++){
        if(encode_api[i] >= *mod_plain.data()){
            encode_api[i] -= *mod_plain.data();
        }
    }

    std::cout << "Encode result is: ";
    for (int i=0; i<slot; i++){
        std::cout << encode_api[i] << " ";
    }
    std::cout << std::endl;

    // gen INTT matrix
    seal::MatrixData matrix_encode;
    matrix_encode.resize(slot, seal::VecData(slot));
    for (int i=slot/2; i<slot; i++)
    {   
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t exp = i;
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, 2*exp, mod_plain);
        seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        std::cout << "zeta: " << zeta << std::endl;
        for (int j=0; j<slot; j++){
            matrix_encode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            matrix_encode[i][j] = seal::util::multiply_uint_mod(matrix_encode[i][j], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }
    for (int i=0; i<slot/2; i++)
    {   
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t exp = i;
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, 2*exp, mod_plain);
        seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        std::cout << "zeta: " << zeta << std::endl;
        for (int j=0; j<slot; j++){
            matrix_encode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            matrix_encode[i][j] = seal::util::multiply_uint_mod(matrix_encode[i][j], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }

    std::cout << "INTT Matrix: " << std::endl;
    for (int i=0; i<slot; i++){
        for (int j=0; j<slot; j++){
            std::cout << matrix_encode[i][j] << " ";
        }
        std::cout << std::endl;
    }
  

    // INTT execution
    seal::VecData ptxt_encode(slot, 0);
    for(int i=0; i<slot; i++){
        for(int j=0; j<slot; j++){
            ptxt_encode[i] = seal::util::add_uint_mod(ptxt_encode[i], seal::util::multiply_uint_mod(matrix_encode[i][j], values_matrix[j], mod_plain), mod_plain);
        }
    }

    std::vector<uint64_t> ptxt_encode_scale(slot, 0ULL);
    for (int i=0; i<slot; i++){
        uint64_t scale = 0;
        scale = seal::util::exponentiate_uint_mod(root, i, mod_plain);
        seal::util::try_invert_uint_mod(scale, mod_plain, scale);
        // std::cout << "scale: " << scale << std::endl;
        ptxt_encode_scale[i] = seal::util::multiply_uint_mod(ptxt_encode[i], scale ,mod_plain);
    } 

    std::cout << "Manual encode result is: ";
    for (int i=0; i<slot; i++){
        std::cout << ptxt_encode[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "Scaled manual encode result is: ";
    for (int i=0; i<slot; i++){
        std::cout << ptxt_encode_scale[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "Done" << std::endl;
    return;

}

void Cryptor::intt_extract(std::vector<uint64_t> values_matrix, uint64_t slot, seal::Modulus mod_plain, std::vector<uint64_t> &ptxt_encode_scale) const 
{
    // uint64_t slot = seal::RLWEParams::poly_modulus_degree;
    // uint64_t slot = 8;
    // seal::Modulus mod_plain(17);
    seal::Modulus mod_degree(2*slot);
    uint64_t degree_inv;
    seal::util::try_invert_uint_mod(slot, mod_plain, degree_inv);
    uint64_t root = 0;
    seal::util::try_minimal_primitive_root(2*slot, mod_plain, root);
    std::cout << "degree: " << slot << " plain: " << *mod_plain.data() << " root: " << root << std::endl;

    // std::vector<uint64_t> values_matrix(slot, 1ULL);
    // for (int i=0; i<slot; i++){
    //     values_matrix[i] = i;
    // }

    std::cout << "intput vector: ";
    for(int i=0; i<slot; i++){
        std::cout << values_matrix[i] << " ";
    }
    std::cout << std::endl;

    // std::vector<uint64_t> encode_api(slot, 0ULL);
    uint64_t *encode_api = new uint64_t[slot]();


    size_t values_matrix_size = values_matrix.size();
    // size_t values_matrix_size = slot;


    util::Pointer<std::size_t> matrix_reps_index_map_;
    MemoryPoolHandle pool_ = MemoryManager::GetPool();

    int logn = seal::util::get_power_of_two(slot);
    matrix_reps_index_map_ = seal::util::allocate<size_t>(slot, pool_);
    // seal::VecData matrix_reps_index_map_(slot, 0ULL);

    // Copy from the matrix to the value vectors
    // we don't need this for pure INTT
    size_t row_size = slot >> 1;
    size_t m = slot << 1;
    uint64_t gen = 3;
    uint64_t pos = 1;
    for (size_t i = 0; i < slot; i++)
    {   

        // // Position in normal bit order
        // uint64_t index1 = (pos - 1) >> 1;
        // uint64_t index2 = (m - pos - 1) >> 1;

        // // Set the bit-reversed locations
        // matrix_reps_index_map_[i] = util::safe_cast<size_t>(util::reverse_bits(index1, logn));
        // matrix_reps_index_map_[row_size | i] = util::safe_cast<size_t>(util::reverse_bits(index2, logn));

        // // Next primitive root
        // pos *= gen;
        // pos &= (m - 1);

        matrix_reps_index_map_[i] = seal::util::reverse_bits(i, logn);
    }

    // INTT should be in bit reversed order!
    // matrix_reps_index_map_[0] = 0;
    // matrix_reps_index_map_[1] = 2;
    // matrix_reps_index_map_[2] = 1;
    // matrix_reps_index_map_[3] = 3;

    std::cout << "index map is: " << std::endl;
    for (int i=0; i<slot; i++){
        std::cout << matrix_reps_index_map_[i] << " ";
    }
    std::cout << std::endl;

    for (int i=0; i<slot; i++){
        for (int j = logn - 1; j >= 0; --j) {
            size_t temp = matrix_reps_index_map_[i];
            std::cout << ((temp >> j) & 1);
        }
        std::cout << " ";
    }
    std::cout << std::endl;

    // First write the values to destination coefficients.
    // Read in top row, then bottom row.
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        *(encode_api + matrix_reps_index_map_[i]) = values_matrix[i];
    }
    for (size_t i = values_matrix_size; i < slot; i++)
    {
        *(encode_api + matrix_reps_index_map_[i]) = 0;
    }

    std::cout << "encode_api after map is: ";
    for (int i=0; i<slot; i++){
        std::cout << encode_api[i] << " ";
    }
    std::cout << std::endl;

    // seal::util::Pointer<util::NTTTables> plain_ntt_tables_;
    // seal::util::CreateNTTTables(logn, { mod_plain }, plain_ntt_tables_, pool_);

    // seal::util::inverse_ntt_negacyclic_harvey(encode_api, *plain_ntt_tables_.get());
    // which equals to
    // seal::util::inverse_ntt_negacyclic_harvey_lazy(encode_api, *plain_ntt_tables_.get());
    // which also equals to
    // seal::util::MultiplyUIntModOperand inv_degree_modulo = plain_ntt_tables_->inv_degree_modulo();
    // plain_ntt_tables_->ntt_handler().transform_from_rev(
    //     encode_api, plain_ntt_tables_->coeff_count_power(), plain_ntt_tables_->get_from_inv_root_powers(), &inv_degree_modulo);
    // which finally equals to
    uint64_t *api_head = encode_api;
    uint64_t *values = encode_api;
    // const seal::util::MultiplyUIntModOperand *roots = plain_ntt_tables_->get_from_inv_root_powers();
    // std::cout << "Size of roots: " << sizeof(roots) << std::endl;
    seal::util::MultiplyUIntModOperand *roots = new seal::util::MultiplyUIntModOperand[slot];
    seal::util::MultiplyUIntModOperand *roots_head = roots;
    roots[0].operand = 1;
    uint64_t root_inv = 0;
    seal::util::try_invert_uint_mod(root, mod_plain, root_inv);
    std::cout << "root_inv: " << root_inv << std::endl; 
    uint64_t power = root_inv;
    uint64_t degree_power = seal::util::get_power_of_two(slot);
    for(size_t i=1; i<slot; i++){
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i-1, mod_degree);
        // exp = seal::util::sub_uint_mod(2*slot, exp, mod_degree);
        // roots[i].operand = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
        int idx = seal::util::reverse_bits(i - 1, degree_power) + 1;
        // std::cout << "idx: " << idx << std::endl;
        roots[idx].operand = power;
        power = seal::util::multiply_uint_mod(power, root_inv, mod_plain);
    }
    std::cout << "roots: ";
    for (int i=0; i<slot; i++){
        std::cout << roots[i].operand << " ";
    }
    std::cout << std::endl;
    // find out index of roots
    std::vector<int> roots_idx(slot, 0ULL);
    roots_idx[0] = 0;
    for(int i=1; i<slot; i++){
        for(int j=0; j<2*slot; j++){
            if(seal::util::exponentiate_uint_mod(root, j, mod_plain) == roots[i].operand){
                roots_idx[i] = -(2*slot - j);
                continue;
            }
        }
    }
    std::cout << "roots index: ";
    for (int i=0; i<slot; i++){
        std::cout << roots_idx[i] << " ";
    }
    std::cout << std::endl;
    // std::cout << "roots: ";
    // for (int i=0; i<slot; i++){
    //     std::cout << roots[i].operand << " ";
    // }
    // std::cout << std::endl;
    // const seal::util::MultiplyUIntModOperand *scalar = &plain_ntt_tables_->inv_degree_modulo();
    seal::util::MultiplyUIntModOperand *scalar = new seal::util::MultiplyUIntModOperand[1];
    seal::util::MultiplyUIntModOperand *scalar_head = scalar;
    seal::util::try_invert_uint_mod(slot, mod_plain, scalar->operand);
    std::cout << "inv_degree_modulo: " << scalar->operand << std::endl;
    
    // seal::util::Arithmetic<uint64_t, seal::util::MultiplyUIntModOperand, seal::util::MultiplyUIntModOperand> arithmetic_;
    // constant transform size
    size_t n = size_t(1) << logn;
    // registers to hold temporary values
    seal::util::MultiplyUIntModOperand r;
    uint64_t u;
    uint64_t v;
    // pointers for faster indexing
    uint64_t *x = nullptr;
    uint64_t *y = nullptr;
    // variables for indexing
    std::size_t gap = 1;
    std::size_t m_2 = n >> 1;
    // DEBUG
    // std::cout << "m_2: " << m_2 << std::endl;

    // some variable just for debug
    int x_index = 0;
    int y_index = 0;
    int u_index = 0;
    int v_index = 0;
    int root_index = 0;
    int value_index = 0;

    // std::cout << "vlaues: " << std::endl;
    // for (int i=0; i<slot; i++){
    //     std::cout << values[i] << " ";
    // }
    // std::cout << std::endl;

    std::cout << "Start Encode INTT: " << std::endl;

    for (; m_2 > 1; m_2 >>= 1)
    {
        // DEBUG
        // std::cout << "m_2: " << m_2 << std::endl;
        // std::cout << "gap: " << gap << std::endl;

        std::size_t offset = 0;
        if (gap < 4)
        {
            for (std::size_t i = 0; i < m_2; i++)
            {
                // std::cout << "gap < 4" << std::endl;
                // std::cout << "i: " << i << std::endl;
                r = *++roots;                                       //root_index++; std::cout << "root_index: " << root_index << std::endl;
                // std::cout << "r: " << r.operand << std::endl;
                // std::cout << "roots: ";
                // for (int i=0; i<slot; i++){
                //     std::cout << roots[i].operand << " ";
                // }
                // std::cout << std::endl;
                x = values + offset;                                //x_index = value_index + offset; std::cout << "x_index: " << x_index << std::endl;
                // std::cout << "x: " << *x << std::endl;
                y = x + gap;                                        //y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
                // std::cout << "y: " << *y << std::endl;
                for (std::size_t j = 0; j < gap; j++)
                {
                    u = *x;                                         //u_index = x_index;
                    // std::cout << "u: " << u << std::endl;
                    v = *y;                                        //v_index = y_index;
                    // std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); ///* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); ///*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++;
                    // std::cout << "vlaues: " << std::endl;
                    // for (int i=0; i<slot; i++){
                    //     std::cout << values[i] << " ";
                    // }
                    // std::cout << std::endl;
                }
                offset += gap << 1;                                 //std::cout << "off set: " << offset << std::endl;
            }
        }
        else
        {
            for (std::size_t i = 0; i < m_2; i++)
            {
                // std::cout << "gap !< 4" << std::endl;
                // std::cout << "i: " << i << std::endl;
                r = *++roots;                                       //root_index++; std::cout << "root_index: " << root_index << std::endl;
                // std::cout << "r: " << r.operand << std::endl;
                // std::cout << "roots: ";
                // for (int i=0; i<slot; i++){
                //     std::cout << roots[i].operand << " ";
                // }
                // std::cout << std::endl;
                x = values + offset;                                //x_index = value_index + offset; std::cout << "x_index: " << x_index << std::endl;
                // std::cout << "x: " << *x << std::endl;
                y = x + gap;                                        //y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
                // std::cout << "y: " << *y << std::endl;
                for (std::size_t j = 0; j < gap; j += 4)
                {
                    u = *x;                                         u_index = x_index;
                    // std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    // std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); // /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); // /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    // std::cout << "vlaues: " << std::endl;
                    // for (int i=0; i<slot; i++){
                    //     std::cout << values[i] << " ";
                    // }
                    // std::cout << std::endl;

                    u = *x;                                         u_index = x_index;
                    // std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    // std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); // /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); // /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    // std::cout << "vlaues: " << std::endl;
                    // for (int i=0; i<slot; i++){
                    //     std::cout << values[i] << " ";
                    // }
                    // std::cout << std::endl;

                    u = *x;                                         u_index = x_index;
                    // std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    // std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain);//  /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); // /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;
                    
                    u = *x;                                         u_index = x_index;
                    // std::cout << "u: " << u << std::endl;
                    v = *y;                                         v_index = y_index;
                    // std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain);// /* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); // /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    // for (int i=0; i<slot; i++){
                    //     std::cout << values[i] << " ";
                    // }
                    // std::cout << std::endl;
                    
                }
                offset += gap << 1;
            }
        }
        gap <<= 1;
    }
    // std::cout << "for loop done" << std::endl;
    // std::cout << std::endl;
    // std::cout << "roots: ";
    // for (int i=0; i<slot; i++){
    //     std::cout << roots[i].operand << " ";
    // }
    // std::cout << std::endl;

    x_index = 0;
    y_index = 0;
    u_index = 0;
    v_index = 0;
    // root_index = 0;
    if (scalar != nullptr)
    {
        r = *++roots;                                       //root_index++; std::cout << "root_index: " << root_index << std::endl;
        // std::cout << "r: " << r.operand << std::endl;
        // std::cout << "roots: ";
        // for (int i=0; i<slot; i++){
        //     std::cout << roots[i].operand << " ";
        // }
        // std::cout << std::endl;
        const uint64_t scaled_r = util::multiply_uint_mod(r.operand, scalar->operand, mod_plain);
        // std::cout << "scaled_r: " << scaled_r << std::endl;
        x = values;                                         //x_index = x_index; std::cout << "x_index: " << x_index << std::endl;
        // std::cout << "x: " << *x << std::endl;
        y = x + gap;                                       // y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
        // std::cout << "y: " << *y << std::endl;
        if (gap < 4)
        {
            for (size_t j = 0; j < gap; j++)
            {
                // std::cout << "gap < 4" << std::endl;
                // std::cout << "j: " << j << std::endl;
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                // std::cout << "u: " << u << std::endl;
                v = *y;                                                                                v_index = y_index;   
                // std::cout << "v: " << v << std::endl;                                                            
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); // /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * scalar"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); // /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                // for (int i=0; i<slot; i++){
                //     std::cout << values[i] << " ";
                // }
                // std::cout << std::endl;
                     
            }
        }
        else
        {
            for (std::size_t j = 0; j < gap; j += 4)
            {
                // std::cout << "gap !< 4" << std::endl;
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); ///* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); ///*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                // for (int i=0; i<slot; i++){
                //     std::cout << values[i] << " ";
                // }
                // std::cout << std::endl;
                    
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); ///* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); ///*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                // for (int i=0; i<slot; i++){
                //     std::cout << values[i] << " ";
                // }
                // std::cout << std::endl;
                    
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); ///* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); ///*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                // for (int i=0; i<slot; i++){
                //     std::cout << values[i] << " ";
                // }
                // std::cout << std::endl;
                    
                u = seal::util::modulo_uint(x, 1, mod_plain); /* arithmetic_.guard(*x); */             u_index = x_index;
                v = *y;                                                                                v_index = y_index;                                                               
                *x++ = seal::util::multiply_uint_mod(seal::util::add_uint_mod(u, v, mod_plain), scalar->operand, mod_plain); ///* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << "( " << u_index << " + " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), scaled_r, mod_plain); ///*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * scaled root[" << root_index << "]"  <<  std::endl; y_index++; 
                // for (int i=0; i<slot; i++){
                //     std::cout << values[i] << " ";
                // }
                // std::cout << std::endl;
                    
            }
        }
    }
    else
    {
        r = *++roots;                                       //root_index++; std::cout << "root_index: " << root_index << std::endl;
        // std::cout << "r: " << r.operand << std::endl;
        // std::cout << "roots: ";
        // for (int i=0; i<slot; i++){
        //     std::cout << roots[i].operand << " ";
        // }
        std::cout << std::endl;
        x = values;                                         // x_index = value_index; std::cout << "x_index: " << x_index << std::endl;
        // std::cout << "x: " << *x << std::endl;
        y = x + gap;                                        // y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
        // std::cout << "y: " << *y << std::endl;
        if (gap < 4)
        {
            for (std::size_t j = 0; j < gap; j++)
            {
                // std::cout << "j: " << j << std::endl;
                u = *x;                                         u_index = x_index;
                // std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                // std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); // /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); // /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                // for (int i=0; i<slot; i++){
                //     std::cout << values[i] << " ";
                // }
                // std::cout << std::endl;
                    
            }
        }
        else
        {
            for (std::size_t j = 0; j < gap; j += 4)
            {
                // std::cout << "j: " << j << std::endl;
                u = *x;                                         u_index = x_index;
                // std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                // std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); // /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); // /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                // for (int i=0; i<slot; i++){
                //     std::cout << values[i] << " ";
                // }
                // std::cout << std::endl;
                    
                u = *x;                                         u_index = x_index;
                // std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                // std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); // /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); // /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                // for (int i=0; i<slot; i++){
                //     std::cout << values[i] << " ";
                // }
                // std::cout << std::endl;
                    
                u = *x;                                         u_index = x_index;
                // std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                // std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); // /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); // /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                // for (int i=0; i<slot; i++){
                //     std::cout << values[i] << " ";
                // }
                // std::cout << std::endl;
                    
                u = *x;                                         u_index = x_index;
                // std::cout << "u: " << u << std::endl;
                v = *y;                                         v_index = y_index;
                // std::cout << "v: " << v << std::endl;
                *x++ = seal::util::add_uint_mod(u, v, mod_plain); // /* arithmetic_.guard(arithmetic_.add(u, v));*/ std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++; 
                *y++ = seal::util::multiply_uint_mod(seal::util::sub_uint_mod(u,v,mod_plain), r.operand, mod_plain); // /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                // for (int i=0; i<slot; i++){
                //     std::cout << values[i] << " ";
                // }
                // std::cout << std::endl;
                    
            }
        }
    }
    // std::cout << std::endl;
    // std::cout << "roots: ";
    // for (int i=0; i<slot; i++){
    //     std::cout << roots[i].operand << " ";
    // }
    // std::cout << std::endl;


    // Final adjustments; compute a[j] = a[j] * n^{-1} mod q.
    // We incorporated the final adjustment in the butterfly. Only need to reduce here.
    for(int i=0; i<slot; i++){
        if(encode_api[i] >= *mod_plain.data()){
            encode_api[i] -= *mod_plain.data();
        }
    }

    std::cout << "Encode result is: ";
    for (int i=0; i<slot; i++){
        std::cout << encode_api[i] << " ";
    }
    std::cout << std::endl;

    // gen INTT matrix
    seal::MatrixData matrix_encode;
    matrix_encode.resize(slot, seal::VecData(slot));
    for (int i=slot/2; i<slot; i++)
    {   
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t exp = i;
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, 2*exp, mod_plain);
        seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        // std::cout << "zeta: " << zeta << std::endl;
        for (int j=0; j<slot; j++){
            matrix_encode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            matrix_encode[i][j] = seal::util::multiply_uint_mod(matrix_encode[i][j], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }
    for (int i=0; i<slot/2; i++)
    {   
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t exp = i;
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, 2*exp, mod_plain);
        seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        // std::cout << "zeta: " << zeta << std::endl;
        for (int j=0; j<slot; j++){
            matrix_encode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            matrix_encode[i][j] = seal::util::multiply_uint_mod(matrix_encode[i][j], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }

    std::cout << "INTT Matrix: " << std::endl;
    for (int i=0; i<slot; i++){
        for (int j=0; j<slot; j++){
            std::cout << matrix_encode[i][j] << " ";
        }
        std::cout << std::endl;
    }
  

    // INTT execution
    seal::VecData ptxt_encode(slot, 0);
    for(int i=0; i<slot; i++){
        for(int j=0; j<slot; j++){
            ptxt_encode[i] = seal::util::add_uint_mod(ptxt_encode[i], seal::util::multiply_uint_mod(matrix_encode[i][j], values_matrix[j], mod_plain), mod_plain);
        }
    }

    // std::vector<uint64_t> ptxt_encode_scale(slot, 0ULL);
    ptxt_encode_scale.resize(slot);
    for (int i=0; i<slot; i++){
        uint64_t scale = 0;
        scale = seal::util::exponentiate_uint_mod(root, i, mod_plain);
        seal::util::try_invert_uint_mod(scale, mod_plain, scale);
        // std::cout << "scale: " << scale << std::endl;
        ptxt_encode_scale[i] = seal::util::multiply_uint_mod(ptxt_encode[i], scale ,mod_plain);
    } 

    std::cout << "Manual encode result is: ";
    for (int i=0; i<slot; i++){
        std::cout << ptxt_encode[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "Scaled manual encode result is: ";
    for (int i=0; i<slot; i++){
        std::cout << ptxt_encode_scale[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "Done" << std::endl;
    return;
}

void Cryptor::ntt_extract(std::vector<uint64_t> values_matrix, uint64_t slot, seal::Modulus mod_plain, std::vector<uint64_t> &ptxt_encode_scale) const
{
    // uint64_t slot = seal::RLWEParams::poly_modulus_degree;
    // uint64_t slot = 8;
    // seal::Modulus mod_plain(17);
    seal::Modulus mod_degree(2*slot);
    uint64_t degree_inv;
    seal::util::try_invert_uint_mod(slot, mod_plain, degree_inv);
    uint64_t root = 0;
    seal::util::try_minimal_primitive_root(2*slot, mod_plain, root);
    std::cout << "degree: " << slot << " plain: " << *mod_plain.data() << " root: " << root << std::endl;

    // std::vector<uint64_t> values_matrix(slot, 1ULL);
    // for (int i=0; i<slot; i++){
    //     values_matrix[i] = i;
    // }

    std::cout << "intput vector: ";
    for(int i=0; i<slot; i++){
        std::cout << values_matrix[i] << " ";
    }
    std::cout << std::endl;

    // std::vector<uint64_t> encode_api(slot, 0ULL);
    uint64_t *encode_api = new uint64_t[slot]();


    size_t values_matrix_size = values_matrix.size();
    // size_t values_matrix_size = slot;


    util::Pointer<std::size_t> matrix_reps_index_map_;
    MemoryPoolHandle pool_ = MemoryManager::GetPool();

    int logn = seal::util::get_power_of_two(slot);
    matrix_reps_index_map_ = seal::util::allocate<size_t>(slot, pool_);
    // seal::VecData matrix_reps_index_map_(slot, 0ULL);

    // Copy from the matrix to the value vectors
    // we don't need this for pure INTT
    size_t row_size = slot >> 1;
    size_t m = slot << 1;
    uint64_t gen = 3;
    uint64_t pos = 1;
    for (size_t i = 0; i < slot; i++)
    {   

        // // Position in normal bit order
        // uint64_t index1 = (pos - 1) >> 1;
        // uint64_t index2 = (m - pos - 1) >> 1;

        // // Set the bit-reversed locations
        // matrix_reps_index_map_[i] = util::safe_cast<size_t>(util::reverse_bits(index1, logn));
        // matrix_reps_index_map_[row_size | i] = util::safe_cast<size_t>(util::reverse_bits(index2, logn));

        // // Next primitive root
        // pos *= gen;
        // pos &= (m - 1);

        // matrix_reps_index_map_[i] = seal::util::reverse_bits(i, logn);

        matrix_reps_index_map_[i] = i;
    }

    // INTT should be in bit reversed order!
    // matrix_reps_index_map_[0] = 0;
    // matrix_reps_index_map_[1] = 2;
    // matrix_reps_index_map_[2] = 1;
    // matrix_reps_index_map_[3] = 3;

    std::cout << "index map is: " << std::endl;
    for (int i=0; i<slot; i++){
        std::cout << matrix_reps_index_map_[i] << " ";
    }
    std::cout << std::endl;

    for (int i=0; i<slot; i++){
        for (int j = logn - 1; j >= 0; --j) {
            size_t temp = matrix_reps_index_map_[i];
            std::cout << ((temp >> j) & 1);
        }
        std::cout << " ";
    }
    std::cout << std::endl;

    // First write the values to destination coefficients.
    // Read in top row, then bottom row.
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        *(encode_api + matrix_reps_index_map_[i]) = values_matrix[i];
    }
    for (size_t i = values_matrix_size; i < slot; i++)
    {
        *(encode_api + matrix_reps_index_map_[i]) = 0;
    }

    std::cout << "encode_api after map is: ";
    for (int i=0; i<slot; i++){
        std::cout << encode_api[i] << " ";
    }
    std::cout << std::endl;

    // seal::util::Pointer<util::NTTTables> plain_ntt_tables_;
    // seal::util::CreateNTTTables(logn, { mod_plain }, plain_ntt_tables_, pool_);

    // seal::util::inverse_ntt_negacyclic_harvey(encode_api, *plain_ntt_tables_.get());
    // which equals to
    // seal::util::inverse_ntt_negacyclic_harvey_lazy(encode_api, *plain_ntt_tables_.get());
    // which also equals to
    // seal::util::MultiplyUIntModOperand inv_degree_modulo = plain_ntt_tables_->inv_degree_modulo();
    // plain_ntt_tables_->ntt_handler().transform_from_rev(
    //     encode_api, plain_ntt_tables_->coeff_count_power(), plain_ntt_tables_->get_from_inv_root_powers(), &inv_degree_modulo);
    // which finally equals to
    uint64_t *api_head = encode_api;
    uint64_t *values = encode_api;
    // const seal::util::MultiplyUIntModOperand *roots = plain_ntt_tables_->get_from_inv_root_powers();
    // std::cout << "Size of roots: " << sizeof(roots) << std::endl;
    seal::util::MultiplyUIntModOperand *roots = new seal::util::MultiplyUIntModOperand[slot];
    seal::util::MultiplyUIntModOperand *roots_head = roots;
    roots[0].operand = 1;
    uint64_t root_inv = 0;
    seal::util::try_invert_uint_mod(root, mod_plain, root_inv);
    std::cout << "root_inv: " << root_inv << std::endl; 
    // uint64_t power = root_inv;
    uint64_t power = root;
    uint64_t degree_power = seal::util::get_power_of_two(slot);
    for(size_t i=1; i<slot; i++){
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i-1, mod_degree);
        // exp = seal::util::sub_uint_mod(2*slot, exp, mod_degree);
        // roots[i].operand = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
        int idx = seal::util::reverse_bits(i, degree_power); //Difference between NTT and INTT
        // std::cout << "idx: " << idx << std::endl;
        roots[idx].operand = power;
        // power = seal::util::multiply_uint_mod(power, root_inv, mod_plain);
        power = seal::util::multiply_uint_mod(power, root, mod_plain);
    }
    std::cout << "roots: ";
    for (int i=0; i<slot; i++){
        std::cout << roots[i].operand << " ";
    }
    std::cout << std::endl;
    // find out index of roots
    std::vector<int> roots_idx(slot, 0ULL);
    roots_idx[0] = 0;
    for(int i=1; i<slot; i++){
        for(int j=0; j<2*slot; j++){
            if(seal::util::exponentiate_uint_mod(root, j, mod_plain) == roots[i].operand){
                // roots_idx[i] = -(2*slot - j);
                roots_idx[i] = j;
                continue;
            }
        }
    }
    std::cout << "roots index: ";
    for (int i=0; i<slot; i++){
        std::cout << roots_idx[i] << " ";
    }
    std::cout << std::endl;
    // std::cout << "roots: ";
    // for (int i=0; i<slot; i++){
    //     std::cout << roots[i].operand << " ";
    // }
    // std::cout << std::endl;
    // const seal::util::MultiplyUIntModOperand *scalar = &plain_ntt_tables_->inv_degree_modulo();
    seal::util::MultiplyUIntModOperand *scalar = nullptr;
    // seal::util::MultiplyUIntModOperand *scalar = new seal::util::MultiplyUIntModOperand[1];
    // seal::util::MultiplyUIntModOperand *scalar_head = scalar;
    // seal::util::try_invert_uint_mod(slot, mod_plain, scalar->operand);
    // std::cout << "inv_degree_modulo: " << scalar->operand << std::endl;
    
    // seal::util::Arithmetic<uint64_t, seal::util::MultiplyUIntModOperand, seal::util::MultiplyUIntModOperand> arithmetic_;
    // constant transform size
    size_t n = size_t(1) << logn;
    // registers to hold temporary values
    seal::util::MultiplyUIntModOperand r;
    uint64_t u;
    uint64_t v;
    // pointers for faster indexing
    uint64_t *x = nullptr;
    uint64_t *y = nullptr;
    // variables for indexing
    // std::size_t gap = 1;
    std::size_t gap = n >> 1;
    // std::size_t m_2 = n >> 1; // Difference
    std::size_t m_2 = 1;
    // DEBUG
    // std::cout << "m_2: " << m_2 << std::endl;

    // some variable just for debug
    int x_index = 0;
    int y_index = 0;
    int u_index = 0;
    int v_index = 0;
    int root_index = 0;
    int value_index = 0;

    // std::cout << "vlaues: " << std::endl;
    // for (int i=0; i<slot; i++){
    //     std::cout << values[i] << " ";
    // }
    // std::cout << std::endl;

    std::cout << "Start Encode NTT: " << std::endl;

    for (; m_2 < (n >> 1); m_2 <<= 1)
    {
        // DEBUG
        // std::cout << "m_2: " << m_2 << std::endl;
        // std::cout << "gap: " << gap << std::endl;

        std::size_t offset = 0;
        if (gap < 4)
        {
            for (std::size_t i = 0; i < m_2; i++)
            {
                // std::cout << "gap < 4" << std::endl;
                // std::cout << "i: " << i << std::endl;
                r = *++roots;                                      // root_index++; std::cout << "root_index: " << root_index << std::endl;
                // std::cout << "r: " << r.operand << std::endl;
                // std::cout << "roots: ";
                // for (int i=0; i<slot; i++){
                //     std::cout << roots[i].operand << " ";
                // }
                // std::cout << std::endl;
                x = values + offset;                                // x_index = value_index + offset; std::cout << "x_index: " << x_index << std::endl;
                // std::cout << "x: " << *x << std::endl;
                y = x + gap;                                        // y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
                // std::cout << "y: " << *y << std::endl;
                for (std::size_t j = 0; j < gap; j++)
                {
                    u = *x;                                         // u_index = x_index;
                    // std::cout << "u: " << u << std::endl;
                    v = seal::util::multiply_uint_mod(*y, r.operand, mod_plain);    
                    // std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); /* arithmetic_.guard(arithmetic_.add(u, v));*/  // std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::sub_uint_mod(u, v, mod_plain); /*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ // std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++;
                    // std::cout << "vlaues: " << std::endl;
                    // for (int i=0; i<slot; i++){
                    //     std::cout << values[i] << " ";
                    // }
                    // std::cout << std::endl;
                }
                offset += gap << 1;                                 //std::cout << "off set: " << offset << std::endl;
            }
        }
        else
        {
            for (std::size_t i = 0; i < m_2; i++)
            {
                // std::cout << "gap !< 4" << std::endl;
                // std::cout << "i: " << i << std::endl;
                r = *++roots;                                       //root_index++; std::cout << "root_index: " << root_index << std::endl;
                // std::cout << "r: " << r.operand << std::endl;
                // std::cout << "roots: ";
                for (int i=0; i<slot; i++){
                    std::cout << roots[i].operand << " ";
                }
                std::cout << std::endl;
                x = values + offset;                                //x_index = value_index + offset; std::cout << "x_index: " << x_index << std::endl;
                // std::cout << "x: " << *x << std::endl;
                y = x + gap;                                        //y_index = x_index + gap; std::cout << "y_index: " << y_index << std::endl;
                // std::cout << "y: " << *y << std::endl;
                for (std::size_t j = 0; j < gap; j += 4)
                {
                    u = *x;                                         u_index = x_index;
                    // std::cout << "u: " << u << std::endl;
                    v = seal::util::multiply_uint_mod(*y, r.operand, mod_plain);    
                    // std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); ///* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::sub_uint_mod(u, v, mod_plain); ///*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    // std::cout << "vlaues: " << std::endl;
                    // for (int i=0; i<slot; i++){
                    //     std::cout << values[i] << " ";
                    // }
                    // std::cout << std::endl;

                    u = *x;                                         u_index = x_index;
                    // std::cout << "u: " << u << std::endl;
                    v = seal::util::multiply_uint_mod(*y, r.operand, mod_plain);    
                    // std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); ///* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::sub_uint_mod(u, v, mod_plain); ///*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    // std::cout << "vlaues: " << std::endl;
                    // for (int i=0; i<slot; i++){
                    //     std::cout << values[i] << " ";
                    // }
                    // std::cout << std::endl;

                    u = *x;                                         u_index = x_index;
                    // std::cout << "u: " << u << std::endl;
                    v = seal::util::multiply_uint_mod(*y, r.operand, mod_plain);    
                    // std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); ///* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::sub_uint_mod(u, v, mod_plain); ///*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;
                    
                    u = *x;                                         u_index = x_index;
                    // std::cout << "u: " << u << std::endl;
                    v = seal::util::multiply_uint_mod(*y, r.operand, mod_plain);    
                    // std::cout << "v: " << v << std::endl;
                    *x++ = seal::util::add_uint_mod(u, v, mod_plain); ///* arithmetic_.guard(arithmetic_.add(u, v));*/  std::cout << x_index << " = " << u_index << " + " << v_index << std::endl; x_index++;
                    *y++ = seal::util::sub_uint_mod(u, v, mod_plain); ///*arithmetic_.mul_root(arithmetic_.sub(u, v), r);*/ std::cout << y_index << " = " << "( " << u_index << " - " << v_index << " )" << " * root[" << root_index << "]"  <<  std::endl; y_index++; 
                    for (int i=0; i<slot; i++){
                        std::cout << values[i] << " ";
                    }
                    std::cout << std::endl;
                    
                }
                offset += gap << 1;
            }
        }
        gap >>= 1;
    }
    // std::cout << "for loop done" << std::endl;
    // std::cout << std::endl;
    // std::cout << "roots: ";
    // for (int i=0; i<slot; i++){
    //     std::cout << roots[i].operand << " ";
    // }
    // std::cout << std::endl;

    x_index = 0;
    y_index = 0;
    u_index = 0;
    v_index = 0;
    // root_index = 0;
    if (scalar != nullptr)
    {
        uint64_t scaled_r = 0;
        for (std::size_t i=0; i<m_2; i++){
            r = *++roots;
            scaled_r = seal::util::multiply_uint_mod(scalar->operand, r.operand, mod_plain);
            u = seal::util::multiply_uint_mod(values[0], scalar->operand, mod_plain);
            v = seal::util::multiply_uint_mod(values[1], scaled_r, mod_plain);
            values[0] = seal::util::add_uint_mod(u, v, mod_plain);
            values[1] = seal::util::sub_uint_mod(u, v, mod_plain);
            values += 2;
        }
    }
    else
    {
        for (std::size_t i=0; i<m_2; i++){
            r = *++roots;
            u = values[0];
            v = seal::util::multiply_uint_mod(values[1], r.operand, mod_plain);
            values[0] = seal::util::add_uint_mod(u, v, mod_plain);
            values[1] = seal::util::sub_uint_mod(u, v, mod_plain);
            values += 2;
        }
    }
    // std::cout << "roots: ";
    // for (int i=0; i<slot; i++){
    //     std::cout << roots[i].operand << " ";
    // }
    // std::cout << std::endl;


    // Final adjustments; compute a[j] = a[j] * n^{-1} mod q.
    // We incorporated the final adjustment in the butterfly. Only need to reduce here.
    for(int i=0; i<slot; i++){
        if(encode_api[i] >= *mod_plain.data()){
            encode_api[i] -= *mod_plain.data();
        }
    }

    std::cout << "NTT result is: ";
    for (int i=0; i<slot; i++){
        std::cout << encode_api[i] << " ";
    }
    std::cout << std::endl;

    ptxt_encode_scale.resize(slot);
    for (uint64_t i=0; i<slot; i++){
        ptxt_encode_scale[i] = encode_api[seal::util::reverse_bits(i, logn)];
    }

    std::cout << "Remap NTT result is: ";
    for (int i=0; i<slot; i++){
        std::cout << ptxt_encode_scale[i] << " ";
    }
    std::cout << std::endl;


    // gen INTT matrix
    seal::MatrixData matrix_encode;
    matrix_encode.resize(slot, seal::VecData(slot));
    for (int i=slot/2; i<slot; i++)
    {   
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t exp = i;
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, 2*exp, mod_plain);
        // seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        // std::cout << "zeta: " << zeta << std::endl;
        for (int j=0; j<slot; j++){
            matrix_encode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            // matrix_encode[i][j] = seal::util::multiply_uint_mod(matrix_encode[i][j], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }
    for (int i=0; i<slot/2; i++)
    {   
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t exp = i;
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, 2*exp, mod_plain);
        // seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        // std::cout << "zeta: " << zeta << std::endl;
        for (int j=0; j<slot; j++){
            matrix_encode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            // matrix_encode[i][j] = seal::util::multiply_uint_mod(matrix_encode[i][j], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }

    std::cout << "NTT Matrix: " << std::endl;
    for (int i=0; i<slot; i++){
        for (int j=0; j<slot; j++){
            std::cout << matrix_encode[i][j] << " ";
        }
        std::cout << std::endl;
    }
    
    std::vector<uint64_t> values_matrix_scale(slot, 0ULL);
    values_matrix_scale.resize(slot);
    for (int i=0; i<slot; i++){
        uint64_t scale = 0;
        scale = seal::util::exponentiate_uint_mod(root, i, mod_plain);
        // seal::util::try_invert_uint_mod(scale, mod_plain, scale);
        // std::cout << "scale: " << scale << std::endl;
        values_matrix_scale[i] = seal::util::multiply_uint_mod(values_matrix[i], scale ,mod_plain);
    }

    std::cout << "Scaled input: " << std::endl;
    for(int i=0; i<slot; i++){
        std::cout << values_matrix_scale[i] << " ";
    }
    std::cout << std::endl;

    // NTT execution
    seal::VecData ptxt_encode(slot, 0);
    for(int i=0; i<slot; i++){
        for(int j=0; j<slot; j++){
            ptxt_encode[i] = seal::util::add_uint_mod(ptxt_encode[i], seal::util::multiply_uint_mod(matrix_encode[i][j], values_matrix_scale[j], mod_plain), mod_plain);
        }
    }

    

    

    std::cout << "Manual encode result is: ";
    for (int i=0; i<slot; i++){
        std::cout << ptxt_encode[i] << " ";
    }
    std::cout << std::endl;

    


    std::cout << "Done" << std::endl;
    return;
}

void Cryptor::ntt_intt_mirror(std::vector<uint64_t> values_matrix, uint64_t slot, seal::Modulus mod_plain) const
{
        
    seal::Modulus mod_degree(2*slot);
    uint64_t degree_inv;
    seal::util::try_invert_uint_mod(slot, mod_plain, degree_inv);
    uint64_t root = 0;
    seal::util::try_minimal_primitive_root(2*slot, mod_plain, root);
    std::cout << "degree: " << slot << " plain: " << *mod_plain.data() << " root: " << root << std::endl;

    // seal::VecData values_matrix(slot, 0ULL);

    // gen INTT matrix
    seal::MatrixData matrix_encode;
    matrix_encode.resize(slot, seal::VecData(slot));
    for (int i=slot/2; i<slot; i++)
    {   
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t exp = i;
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, 2*exp, mod_plain);
        seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        // std::cout << "zeta: " << zeta << std::endl;
        for (int j=0; j<slot; j++){
            matrix_encode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            // matrix_encode[i][j] = seal::util::multiply_uint_mod(matrix_encode[i][j], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }
    for (int i=0; i<slot/2; i++)
    {   
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t exp = i;
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, 2*exp, mod_plain);
        seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        // std::cout << "zeta: " << zeta << std::endl;
        for (int j=0; j<slot; j++){
            matrix_encode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            // matrix_encode[i][j] = seal::util::multiply_uint_mod(matrix_encode[i][j], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }

    std::cout << "INTT Matrix: " << std::endl;
    for (int i=0; i<slot; i++){
        for (int j=0; j<slot; j++){
            std::cout << matrix_encode[i][j] << " ";
        }
        std::cout << std::endl;
    }


    // INTT execution
    seal::VecData ptxt_encode(slot, 0);
    for(int i=0; i<slot; i++){
        for(int j=0; j<slot; j++){
            ptxt_encode[i] = seal::util::add_uint_mod(ptxt_encode[i], seal::util::multiply_uint_mod(matrix_encode[i][j], values_matrix[j], mod_plain), mod_plain);
        }
    }

    std::cout << "INTT result is: ";
    for (int i=0; i<slot; i++){
        std::cout << ptxt_encode[i] << " ";
    }
    std::cout << std::endl;

    // gen NTT matrix
    // seal::MatrixData matrix_encode;
    matrix_encode.resize(slot, seal::VecData(slot));
    for (int i=slot/2; i<slot; i++)
    {   
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t exp = i;
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, 2*exp, mod_plain);
        // seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        // std::cout << "zeta: " << zeta << std::endl;
        for (int j=0; j<slot; j++){
            matrix_encode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            // matrix_encode[i][j] = seal::util::multiply_uint_mod(matrix_encode[i][j], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }
    for (int i=0; i<slot/2; i++)
    {   
        // uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t exp = i;
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, 2*exp, mod_plain);
        // seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        // std::cout << "zeta: " << zeta << std::endl;
        for (int j=0; j<slot; j++){
            matrix_encode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
            // matrix_encode[i][j] = seal::util::multiply_uint_mod(matrix_encode[i][j], degree_inv, mod_plain);// remember to mult N^{-1}
        }
    }

    std::cout << "NTT Matrix: " << std::endl;
    for (int i=0; i<slot; i++){
        for (int j=0; j<slot; j++){
            std::cout << matrix_encode[i][j] << " ";
        }
        std::cout << std::endl;
    }

    // Do permute of input matrix
    seal::VecData values_matrix_permute(slot, 0ULL);
    for (int i=0; i<slot; i++){
        if(i==0){
            values_matrix_permute[i] = values_matrix[i];
        }
        else {
            values_matrix_permute[i] = values_matrix[slot-i];
        }
        
    }

    std::cout << "Permute input is: ";
    for (int i=0; i<slot; i++){
        std::cout << values_matrix_permute[i] << " ";
    }
    std::cout << std::endl;
    
    // Initialize ptxt_ntt
    seal::VecData ptxt_ntt(slot, 0);

    // NTT execution
    for(int i=0; i<slot; i++){
        for(int j=0; j<slot; j++){
            ptxt_ntt[i] = seal::util::add_uint_mod(ptxt_ntt[i], seal::util::multiply_uint_mod(matrix_encode[i][j], values_matrix_permute[j], mod_plain), mod_plain);
        }
    }

    std::cout << "NTT result is: ";
    for (int i=0; i<slot; i++){
        std::cout << ptxt_ntt[i] << " ";
    }
    std::cout << std::endl;
}

// TODO: Implement LWEMultScalar
void Cryptor::LWEMultScalar(const LWECipher &ilwe, uint64_t scalar, LWECipher &olwe) const
{   
    std::vector<Modulus> vec_mod = lwe_parms_->coeff_modulus();
    for (int i = 0; i<vec_mod.size(); i++){
        std::cout << i <<"-th modulus is: " << *vec_mod[i].data()  << std::endl;
    }

    auto poly_modulus_degree = LWEParams::poly_modulus_degree;
    auto coeff_modulus_size = LWEParams::coeff_modulus_size;
    auto total_length = coeff_modulus_size * (poly_modulus_degree + 1);
    
    // resize to [b, vec_a] * coeff_modulus_size
    olwe.resize(coeff_modulus_size * (poly_modulus_degree + 1));
    #pragma omp parallel for num_threads(num_th)
    for (int i=0; i<coeff_modulus_size; i++){
        Modulus mod_coeff = vec_mod.data()[i];
        for (int j=0; j<poly_modulus_degree + 1; j++){
            olwe.data()[j+(poly_modulus_degree + 1)*i] = seal::util::multiply_uint_mod(ilwe.data()[j+(poly_modulus_degree + 1)*i], scalar, mod_coeff);
        }
    }
    return;
}

namespace util
{

const size_t bitrev(const size_t idx, const size_t count)
{
    size_t result = 0;
    for (size_t i = 1, j = count >> 1; i < count; i <<= 1, j >>= 1) {
        result |= ((idx & j) / j) * i;
    }
    return result;
}

void print_example_banner(std::string title)
{
    if (!title.empty())
    {
        std::size_t title_length = title.length();
        std::size_t banner_length = title_length + 2 * 10;
        std::string banner_top = "+" + std::string(banner_length - 2, '-') + "+";
        std::string banner_middle = "|" + std::string(9, ' ') + title + std::string(9, ' ') + "|";

        std::cout << std::endl << banner_top << std::endl << banner_middle << std::endl << banner_top << std::endl;
    }
}

void printInBinary(uint64_t num) {
    if (num == 0) {
        std::cout << "0_1" << std::endl;
        return;
    }

    int length = 0;
    uint64_t temp = num;
    while (temp) {
        length++;
        temp >>= 1;
    }

    for (int i = length - 1; i >= 0; --i) {
        std::cout << ((num >> i) & 1);
    }

    std::cout << "(" << length << ")" << std::endl;
}

/*Return the degree of the polynomial described by coefficients,
which is the index of the last non-zero element in the coefficients - 1.
Don't throw an error if all the coefficients are zero, but return 0. */
const size_t Degree(const VecData &coeffs)
{
    size_t deg = 1;
    for (int i = coeffs.size() - 1; i > 0; i--) {
        if (coeffs[i] == 0) {
            deg += 1;
        }
        else
            break;
    }
    return coeffs.size() - deg;
}

const std::vector<uint32_t> ComputeDegreesPS(const uint32_t n) {
    if (n == 0) {
        // OPENFHE_THROW(math_error, "ComputeDegreesPS: The degree is zero. There is no need to evaluate the polynomial.");
        throw std::invalid_argument("ComputeDegreesPS: The degree is zero. There is no need to evaluate the polynomial.");
    }

    std::vector<uint32_t> klist;
    std::vector<uint32_t> mlist;

    double sqn2 = sqrt(n / 2);
    // double sqn2 = sqrt(n);

    for (uint32_t k = 1; k <= n; k++) {
        for (uint32_t m = 1; m <= ceil(log2(n / k) + 1) + 1; m++) {
            if (int32_t(n - k * ((1 << m) - 1)) < 0) {
                if ((static_cast<double>(k - sqn2) >= -2) && ((static_cast<double>(k - sqn2) <= 2))) {
                    klist.push_back(k);
                    mlist.push_back(m);
                }
            }
        }
    }

    uint32_t minIndex = std::min_element(mlist.begin(), mlist.end()) - mlist.begin();

    return std::vector<uint32_t>{{klist[minIndex], mlist[minIndex]}};
}

bool isPowerOf2(const int &i) {
    return (i > 0) && ((i & (i-1)) == 0);
}

// NAND DRaM function
const int DRaM_NAND(int x, int t) 
{
    if (x >= 2 * std::floor(t / 3.0))
        return 0;
    return std::floor(t / 3.0);
}

// Function to process an 8-bit number as described
const uint8_t process_high_pair(uint8_t pair) {
    // If the pair is 01, return 01. Otherwise, return 00.
    return (pair == 0x01) ? 0x02 : 0x00;
}
const uint8_t process_low_pair(uint8_t pair) {
    // If the pair is 01, return 01. Otherwise, return 00.
    return (pair == 0x01) ? 0x01 : 0x00;
}

// XOR High 4 bit function
const int DRaM_highxor(int x, int t) {
    // DEBUG
    // std::cout << "x: " << x << " in binary: ";
    // util::printInBinary(x);

    size_t bias = 7;
    // Process the bits of x.
    uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.

    // DEBUG
    // std::cout << "down_x: " << (int) down_x << " in binary: ";
    // util::printInBinary(down_x);
    
    uint8_t result = 0;
    // Process each pair of bits and combine them into the result.
    result |= process_high_pair((down_x >> 6) & 0x03) << 6; // Process x7x6 and place at x7x6
    result |= process_high_pair((down_x >> 4) & 0x03) << 4; // Process x5x4 and place at x5x4
    result |= process_high_pair((down_x >> 2) & 0x03) << 2; // Process x3x2 and place at x3x2
    result |= process_high_pair(down_x & 0x03);              // Process x1x0 and place at x1x0

	// DEBUG
    // std::cout << "result: " << (int) result << " in binary: ";
    // util::printInBinary(result);
    // std::cout << "result >> bias: " << (result <<bias) << " in binary: ";
    // util::printInBinary((result << bias));
    
    return result << bias;
}

// XOR High 4 bit function 9bit version
const int DRaM_highxor9bit(int x, int t) {
    // DEBUG
    // std::cout << "x: " << x << " in binary: ";
    // util::printInBinary(x);

    size_t bias = 7;
    // Process the bits of x.
    uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.

    // DEBUG
    // std::cout << "down_x: " << (int) down_x << " in binary: ";
    // util::printInBinary(down_x);
    
    uint8_t result = 0;
    // Process each pair of bits and combine them into the result.
    result |= process_high_pair((down_x >> 7) & 0x03) << 6; // Process x7x6 and place at x7x6
    result |= process_high_pair((down_x >> 5) & 0x03) << 4; // Process x5x4 and place at x5x4
    result |= process_high_pair((down_x >> 3) & 0x03) << 2; // Process x3x2 and place at x3x2
    result |= process_high_pair((down_x >> 1) & 0x03) << 1; // Process x1x0 and place at x1x0

	// DEBUG
    // std::cout << "result: " << (int) result << " in binary: ";
    // util::printInBinary(result);
    // std::cout << "result >> bias: " << (result <<bias) << " in binary: ";
    // util::printInBinary((result << bias));
    
    return result << bias;
}

// XOR Low 4 bit function
const int DRaM_lowxor(int x, int t) {
    // DEBUG
    // std::cout << "x: " << x << " in binary: ";
    // util::printInBinary(x);

    size_t bias = 7;
    // Process the bits of x.
    uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.

    // DEBUG
    // std::cout << "down_x: " << (int) down_x << " in binary: ";
    // util::printInBinary(down_x);
    
    uint8_t result = 0;
    // Process each pair of bits and combine them into the result.
    result |= process_low_pair((down_x >> 6) & 0x03) << 6; // Process x7x6 and place at x7x6
    result |= process_low_pair((down_x >> 4) & 0x03) << 4; // Process x5x4 and place at x5x4
    result |= process_low_pair((down_x >> 2) & 0x03) << 2; // Process x3x2 and place at x3x2
    result |= process_low_pair(down_x & 0x03);              // Process x1x0 and place at x1x0

	// DEBUG
    // std::cout << "result: " << (int) result << " in binary: ";
    // util::printInBinary(result);
    // std::cout << "result >> bias: " << (result <<bias) << " in binary: ";
    // util::printInBinary((result << bias));
    
    return result << bias;
}

// Extract High 4 bit function
const int DRaM_H4(int x, int t)
{
    // DEBUG
    // std::cout << "x: " << x << " in binary: ";
    // util::printInBinary(x);

    size_t bias = 7;

    // Process the bits of x.
    uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.

    // DEBUG
    // std::cout << "down_x: " << (int) down_x << " in binary: ";
    // util::printInBinary(down_x);

    uint8_t result = 0;

    // Extract bits x7, x5, x3, x1 and place them in the result at positions x7, x5, x3, x1, with 0s in between.
    result |= ((down_x >> 7) & 0x01) << 6; // Extract x7 and place at x6
    result |= ((down_x >> 5) & 0x01) << 4; // Extract x5 and place at x4
    result |= ((down_x >> 3) & 0x01) << 2; // Extract x3 and place at x2
    result |= ((down_x >> 1) & 0x01);        // Extract x1 and place at x0

    // DEBUG
    // std::cout << "result: " << (int) result << " in binary: ";
    // util::printInBinary(result);
    // std::cout << "result >> bias: " << (result <<bias) << " in binary: ";
    // util::printInBinary((result << bias));

    // Shift the final result right by the bias.
    return result << bias;
}

// Extract Low 4 bit function
const int DRaM_L4(int x, int t)
{
    // DEBUG
    // std::cout << "x: " << x << " in binary: ";
    // util::printInBinary(x);

    size_t bias = 7;

    // Process the bits of x.
    uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.

    // DEBUG
    // std::cout << "down_x: " << (int) down_x << " in binary: ";
    // util::printInBinary(down_x);

    uint8_t result = 0;

    // Extract bits x7, x5, x3, x1 and place them in the result at positions x7, x5, x3, x1, with 0s in between.
    result |= ((down_x >> 6) & 0x01) << 6; // Extract x7 and place at x6
    result |= ((down_x >> 4) & 0x01) << 4; // Extract x5 and place at x4
    result |= ((down_x >> 2) & 0x01) << 2; // Extract x3 and place at x2
    result |= ((down_x) & 0x01);        // Extract x1 and place at x0

    // DEBUG
    // std::cout << "result: " << (int) result << " in binary: ";
    // util::printInBinary(result);
    // std::cout << "result >> bias: " << (result <<bias) << " in binary: ";
    // util::printInBinary((result << bias));

    // Shift the final result right by the bias.
    return result << bias;
}

// sign function
const int DRaM_sign(int x, int t, uint64_t Q)
{
    // int scale = 1;
    // if(Q > t){
    //     scale = std::round((double)Q / t);
    // }
    // std::cout << "Q: " << Q << std::endl;
    // std::cout << "t: " << t << std::endl;
    // std::cout << "scale: " << scale << std::endl;
    if (x >= 0 && x < t/2)
        return 1; // /4.0
    return 0; // /4.0
}

// f0 function
const int DRaM_f0(int x, int t, uint64_t Q)
{
    // int scale = std::round((double)Q / t);
    int scale = 1;
    if(Q > t){
        scale = std::round((double)Q / t);
    }
    // std::cout << "scale: " << scale << std::endl;
    if (x >= 0 && x < t/2)
        return std::round(3.0 * t / (4.0 * scale)); // /4.0
    return std::round(t / (4.0 * scale)); // /4.0
}

// f1 function
const int DRaM_f1(int x, int t, uint64_t Q)
{
    int scale = 1;
    if(Q > t){
        scale = std::round((double)Q / t);
    }
    
    if (x < t/2)
        return std::round(x / scale); // x
    return std::round(3.0 * t / (2.0 * scale) - x / scale); // /2.0; x
}

const std::vector<int> get_customize_Coefficients(int t, const util::DRaMOp& dramOp) 
{
    std::vector<int> coefficients(t, 0);
    // Coefficient for x^0 term is DRaM(0)
    coefficients[0] = dramOp(0, t);

    Modulus t_mod(t);
    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < t; i++) {
        for (int a = 0; a < t; a++) {
            int temp_pow = seal::util::exponentiate_uint_mod(a, t-1-i, t_mod);
            temp_pow = seal::util::multiply_uint_mod(temp_pow, dramOp(a, t), t_mod);
            coefficients[i] = seal::util::sub_uint_mod(coefficients[i], temp_pow, t_mod);
        }
    }
    return coefficients;
}

const std::vector<int> get_NAND_Coefficients(int t) 
{
    std::vector<int> coefficients(t, 0);

    // Coefficient for x^0 term is DRaM(0)
    coefficients[0] = DRaM_NAND(0, t);

    Modulus t_mod(t);

    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < t; i++) {
        for (int a = 0; a < t; a++) {
            int temp_pow = seal::util::exponentiate_uint_mod(a, t-1-i, t_mod);
            temp_pow = seal::util::multiply_uint_mod(temp_pow, DRaM_NAND(a, t), t_mod);
            coefficients[i] = seal::util::sub_uint_mod(coefficients[i], temp_pow, t_mod);
        }
        // std::cout << "i: " << i << std::endl;
    }


    return coefficients;
}

const std::vector<int> get_highxor9bit_Coefficients(int t) 
{
    std::vector<int> coefficients(t, 0);

    // Coefficient for x^0 term is DRaM(0)
    coefficients[0] = DRaM_highxor9bit(0, t);

    Modulus t_mod(t);

    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < t; i++) {
        for (int a = 0; a < t; a++) {
            int temp_pow = seal::util::exponentiate_uint_mod(a, t-1-i, t_mod);
            temp_pow = seal::util::multiply_uint_mod(temp_pow, DRaM_highxor9bit(a, t), t_mod);
            coefficients[i] = seal::util::sub_uint_mod(coefficients[i], temp_pow, t_mod);
        }
        // std::cout << "i: " << i << std::endl;
    }


    return coefficients;
}

const std::vector<int> get_highxor_Coefficients(int t) 
{
    std::vector<int> coefficients(t, 0);

    // Coefficient for x^0 term is DRaM(0)
    coefficients[0] = DRaM_highxor(0, t);

    Modulus t_mod(t);

    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < t; i++) {
        for (int a = 0; a < t; a++) {
            int temp_pow = seal::util::exponentiate_uint_mod(a, t-1-i, t_mod);
            temp_pow = seal::util::multiply_uint_mod(temp_pow, DRaM_highxor(a, t), t_mod);
            coefficients[i] = seal::util::sub_uint_mod(coefficients[i], temp_pow, t_mod);
        }
        // std::cout << "i: " << i << std::endl;
    }


    return coefficients;
}

const std::vector<int> get_lowxor_Coefficients(int t) 
{
    std::vector<int> coefficients(t, 0);

    // Coefficient for x^0 term is DRaM(0)
    coefficients[0] = DRaM_lowxor(0, t);

    Modulus t_mod(t);

    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < t; i++) {
        for (int a = 0; a < t; a++) {
            int temp_pow = seal::util::exponentiate_uint_mod(a, t-1-i, t_mod);
            temp_pow = seal::util::multiply_uint_mod(temp_pow, DRaM_lowxor(a, t), t_mod);
            coefficients[i] = seal::util::sub_uint_mod(coefficients[i], temp_pow, t_mod);
        }
        // std::cout << "i: " << i << std::endl;
    }


    return coefficients;
}

const std::vector<int> get_H4_Coefficients(int t) 
{
    std::vector<int> coefficients(t, 0);

    // Coefficient for x^0 term is DRaM(0)
    coefficients[0] = DRaM_H4(0, t);

    Modulus t_mod(t);

    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < t; i++) {
        for (int a = 0; a < t; a++) {
            int temp_pow = seal::util::exponentiate_uint_mod(a, t-1-i, t_mod);
            temp_pow = seal::util::multiply_uint_mod(temp_pow, DRaM_H4(a, t), t_mod);
            coefficients[i] = seal::util::sub_uint_mod(coefficients[i], temp_pow, t_mod);
        }
        // std::cout << "i: " << i << std::endl;
    }


    return coefficients;
}

const std::vector<int> get_L4_Coefficients(int t) 
{
    std::vector<int> coefficients(t, 0);

    // Coefficient for x^0 term is DRaM(0)
    coefficients[0] = DRaM_L4(0, t);

    Modulus t_mod(t);

    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < t; i++) {
        for (int a = 0; a < t; a++) {
            int temp_pow = seal::util::exponentiate_uint_mod(a, t-1-i, t_mod);
            temp_pow = seal::util::multiply_uint_mod(temp_pow, DRaM_L4(a, t), t_mod);
            coefficients[i] = seal::util::sub_uint_mod(coefficients[i], temp_pow, t_mod);
        }
        // std::cout << "i: " << i << std::endl;
    }


    return coefficients;
}

const std::vector<int> get_sign_Coefficients(int t, uint64_t Q) 
{
    std::vector<int> coefficients(t, 0);

    // Coefficient for x^0 term is DRaM(0)
    coefficients[0] = DRaM_sign(0, t, Q);

    Modulus t_mod(t);

    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < t; i++) {
        for (int a = 0; a < t; a++) {
            int temp_pow = seal::util::exponentiate_uint_mod(a, t-1-i, t_mod);
            temp_pow = seal::util::multiply_uint_mod(temp_pow, DRaM_sign(a, t, Q), t_mod);
            coefficients[i] = seal::util::sub_uint_mod(coefficients[i], temp_pow, t_mod);
        }
        // std::cout << "i: " << i << std::endl;
    }


    return coefficients;
}

const std::vector<int> get_f0_Coefficients(int t, uint64_t Q) 
{
    std::vector<int> coefficients(t, 0);

    // Coefficient for x^0 term is DRaM(0)
    coefficients[0] = DRaM_f0(0, t, Q);

    Modulus t_mod(t);

    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < t; i++) {
        for (int a = 0; a < t; a++) {
            int temp_pow = seal::util::exponentiate_uint_mod(a, t-1-i, t_mod);
            temp_pow = seal::util::multiply_uint_mod(temp_pow, DRaM_f0(a, t, Q), t_mod);
            coefficients[i] = seal::util::sub_uint_mod(coefficients[i], temp_pow, t_mod);
        }
        // std::cout << "i: " << i << std::endl;
    }


    return coefficients;
}

const std::vector<int> get_f1_Coefficients(int t, uint64_t Q) 
{
    std::vector<int> coefficients(t, 0);

    // Coefficient for x^0 term is DRaM(0)
    coefficients[0] = DRaM_f1(0, t, Q);

    Modulus t_mod(t);

    #pragma omp parallel for num_threads(num_th)
    for (int i = 1; i < t; i++) {
        for (int a = 0; a < t; a++) {
            int temp_pow = seal::util::exponentiate_uint_mod(a, t-1-i, t_mod);
            temp_pow = seal::util::multiply_uint_mod(temp_pow, DRaM_f1(a, t, Q), t_mod);
            coefficients[i] = seal::util::sub_uint_mod(coefficients[i], temp_pow, t_mod);
        }
        // std::cout << "i: " << i << std::endl;
    }


    return coefficients;
}

const int evaluateDraMpoly(int x, std::vector<int> coefficients) {
    
    //DEBUG
    // for (int i = 0; i < coefficients.size(); i++){
    //     std::cout << "Coeff[" << i << "] = " << coefficients[i] << " ";
    // }
    // std::cout << std::endl;

    int t = coefficients.size();
    Modulus t_mod(t);
    
    int result = 0;

    for (int i = 0; i < t; i++) {
        // result += coefficients[i] * std::pow(x, i);
        int temp_pow = seal::util::exponentiate_uint_mod(x, i, t_mod);
        temp_pow = seal::util::multiply_uint_mod(temp_pow, coefficients[i], t_mod);
        result = seal::util::add_uint_mod(result, temp_pow, t_mod);
    }

    return result;
}

const void test_customize_poly(int t, const util::DRaMOp& dramOp) {
    bool allPassed = true;

    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(t) + "_" + dramOp.getFileSuffix() + ".txt";
    
    // A vector to hold the coefficients
    std::vector<int> coefficients;

    // Check if the file exists
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        // File doesn't exist, generate the coefficients
        coefficients = get_customize_Coefficients(t, dramOp);
        
        // 使用 filesystem::path 解析文件路径
        std::filesystem::path path(filename);

        // 检查父路径（文件夹）是否存在
        if (!std::filesystem::exists(path.parent_path())) {
            // 尝试创建所有不存在的父路径（文件夹）
            bool created = std::filesystem::create_directories(path.parent_path());
            if (!created) {
                // 如果创建文件夹失败，则打印错误信息并返回
                std::cerr << "Failed to create directories for: " << path.parent_path() << std::endl;
                return;
            }
        }
        // Open the file for writing
        std::ofstream outFile(filename);
        
        // Check if the file opened successfully
        if (outFile.is_open()) {
            for (const auto &coef : coefficients) {
                outFile << coef << std::endl; // Write each coefficient on a new line
            }
            outFile.close(); // Close the file
        } else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }

    if (t < 1000)
    {
        #pragma omp parallel for num_threads(num_th)
        for (int x = 0; x < t; x++) {
            int temp = evaluateDraMpoly(x, coefficients);
            if (dramOp(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << dramOp(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }
    else
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < 1000; i++) {
            // x is a random integer between [0,1,...,t-1]
            std::random_device rd; 
            std::mt19937 gen(rd()); 
            std::uniform_int_distribution<> distrib(0, t - 1);
            int x = distrib(gen);
            
            int temp = evaluateDraMpoly(x, coefficients);
            if (dramOp(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << dramOp(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }

    if (allPassed) {
        std::cout << "All tests passed!" << std::endl;
    }
}

const void test_NAND_poly(int t) {
    bool allPassed = true;

    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(t) + "_NAND_Poly.txt";
    
    // A vector to hold the coefficients
    std::vector<int> coefficients;

    // Check if the file exists
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        // File doesn't exist, generate the coefficients
        coefficients = get_NAND_Coefficients(t);
        
        // 使用 filesystem::path 解析文件路径
        std::filesystem::path path(filename);

        // 检查父路径（文件夹）是否存在
        if (!std::filesystem::exists(path.parent_path())) {
            // 尝试创建所有不存在的父路径（文件夹）
            bool created = std::filesystem::create_directories(path.parent_path());
            if (!created) {
                // 如果创建文件夹失败，则打印错误信息并返回
                std::cerr << "Failed to create directories for: " << path.parent_path() << std::endl;
                return;
            }
        }
        
        // Open the file for writing
        std::ofstream outFile(filename);
        
        // Check if the file opened successfully
        if (outFile.is_open()) {
            for (const auto &coef : coefficients) {
                outFile << coef << std::endl; // Write each coefficient on a new line
            }
            outFile.close(); // Close the file
        } else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }

    if (t < 1000)
    {
        #pragma omp parallel for num_threads(num_th)
        for (int x = 0; x < t; x++) {
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_NAND(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_NAND(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }
    else
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < 1000; i++) {
            // x is a random integer between [0,1,...,t-1]
            std::random_device rd; 
            std::mt19937 gen(rd()); 
            std::uniform_int_distribution<> distrib(0, t - 1);
            int x = distrib(gen);
            
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_NAND(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_NAND(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }

    if (allPassed) {
        std::cout << "All tests passed!" << std::endl;
    }
}

const void test_highxor9bit_poly(int t) {
    bool allPassed = true;

    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(t) + "_highxor9bit_Poly.txt";
    
    // A vector to hold the coefficients
    std::vector<int> coefficients;

    // Check if the file exists
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        // File doesn't exist, generate the coefficients
        coefficients = get_highxor9bit_Coefficients(t);
        
        // 使用 filesystem::path 解析文件路径
        std::filesystem::path path(filename);

        // 检查父路径（文件夹）是否存在
        if (!std::filesystem::exists(path.parent_path())) {
            // 尝试创建所有不存在的父路径（文件夹）
            bool created = std::filesystem::create_directories(path.parent_path());
            if (!created) {
                // 如果创建文件夹失败，则打印错误信息并返回
                std::cerr << "Failed to create directories for: " << path.parent_path() << std::endl;
                return;
            }
        }

        // Open the file for writing
        std::ofstream outFile(filename);
        
        // Check if the file opened successfully
        if (outFile.is_open()) {
            for (const auto &coef : coefficients) {
                outFile << coef << std::endl; // Write each coefficient on a new line
            }
            outFile.close(); // Close the file
        } else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }

    if (t < 1000)
    {
        #pragma omp parallel for num_threads(num_th)
        for (int x = 0; x < t; x++) {
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_highxor9bit(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_highxor9bit(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }
    else
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < 1000; i++) {
            // x is a random integer between [0,1,...,t-1]
            std::random_device rd; 
            std::mt19937 gen(rd()); 
            std::uniform_int_distribution<> distrib(0, t - 1);
            int x = distrib(gen);
            
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_highxor9bit(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_highxor9bit(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }

    if (allPassed) {
        std::cout << "All tests passed!" << std::endl;
    }
}

const void test_highxor_poly(int t) {
    bool allPassed = true;

    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(t) + "_highxor_Poly.txt";
    
    // A vector to hold the coefficients
    std::vector<int> coefficients;

    // Check if the file exists
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        // File doesn't exist, generate the coefficients
        coefficients = get_highxor_Coefficients(t);
        
        // 使用 filesystem::path 解析文件路径
        std::filesystem::path path(filename);

        // 检查父路径（文件夹）是否存在
        if (!std::filesystem::exists(path.parent_path())) {
            // 尝试创建所有不存在的父路径（文件夹）
            bool created = std::filesystem::create_directories(path.parent_path());
            if (!created) {
                // 如果创建文件夹失败，则打印错误信息并返回
                std::cerr << "Failed to create directories for: " << path.parent_path() << std::endl;
                return;
            }
        }

        // Open the file for writing
        std::ofstream outFile(filename);
        
        // Check if the file opened successfully
        if (outFile.is_open()) {
            for (const auto &coef : coefficients) {
                outFile << coef << std::endl; // Write each coefficient on a new line
            }
            outFile.close(); // Close the file
        } else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }

    if (t < 1000)
    {
        #pragma omp parallel for num_threads(num_th)
        for (int x = 0; x < t; x++) {
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_highxor(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_highxor(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }
    else
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < 1000; i++) {
            // x is a random integer between [0,1,...,t-1]
            std::random_device rd; 
            std::mt19937 gen(rd()); 
            std::uniform_int_distribution<> distrib(0, t - 1);
            int x = distrib(gen);
            
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_highxor(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_highxor(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }

    if (allPassed) {
        std::cout << "All tests passed!" << std::endl;
    }
}

const void test_lowxor_poly(int t) {
    bool allPassed = true;

    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(t) + "_lowxor_Poly.txt";
    
    // A vector to hold the coefficients
    std::vector<int> coefficients;

    // Check if the file exists
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        // File doesn't exist, generate the coefficients
        coefficients = get_L4_Coefficients(t);

        // 使用 filesystem::path 解析文件路径
        std::filesystem::path path(filename);

        // 检查父路径（文件夹）是否存在
        if (!std::filesystem::exists(path.parent_path())) {
            // 尝试创建所有不存在的父路径（文件夹）
            bool created = std::filesystem::create_directories(path.parent_path());
            if (!created) {
                // 如果创建文件夹失败，则打印错误信息并返回
                std::cerr << "Failed to create directories for: " << path.parent_path() << std::endl;
                return;
            }
        }

        // Open the file for writing
        std::ofstream outFile(filename);
        
        // Check if the file opened successfully
        if (outFile.is_open()) {
            for (const auto &coef : coefficients) {
                outFile << coef << std::endl; // Write each coefficient on a new line
            }
            outFile.close(); // Close the file
        } else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }

    if (t < 1000)
    {
        #pragma omp parallel for num_threads(num_th)
        for (int x = 0; x < t; x++) {
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_L4(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_L4(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }
    else
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < 1000; i++) {
            // x is a random integer between [0,1,...,t-1]
            std::random_device rd; 
            std::mt19937 gen(rd()); 
            std::uniform_int_distribution<> distrib(0, t - 1);
            int x = distrib(gen);
            
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_L4(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_L4(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }

    if (allPassed) {
        std::cout << "All tests passed!" << std::endl;
    }
}

const void test_H4_poly(int t) {
    bool allPassed = true;

    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(t) + "_H4_Poly.txt";
    
    // A vector to hold the coefficients
    std::vector<int> coefficients;

    // Check if the file exists
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        // File doesn't exist, generate the coefficients
        coefficients = get_H4_Coefficients(t);
        
        // 使用 filesystem::path 解析文件路径
        std::filesystem::path path(filename);

        // 检查父路径（文件夹）是否存在
        if (!std::filesystem::exists(path.parent_path())) {
            // 尝试创建所有不存在的父路径（文件夹）
            bool created = std::filesystem::create_directories(path.parent_path());
            if (!created) {
                // 如果创建文件夹失败，则打印错误信息并返回
                std::cerr << "Failed to create directories for: " << path.parent_path() << std::endl;
                return;
            }
        }

        // Open the file for writing
        std::ofstream outFile(filename);
        
        // Check if the file opened successfully
        if (outFile.is_open()) {
            for (const auto &coef : coefficients) {
                outFile << coef << std::endl; // Write each coefficient on a new line
            }
            outFile.close(); // Close the file
        } else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }

    if (t < 1000)
    {
        #pragma omp parallel for num_threads(num_th)
        for (int x = 0; x < t; x++) {
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_H4(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_H4(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }
    else
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < 1000; i++) {
            // x is a random integer between [0,1,...,t-1]
            std::random_device rd; 
            std::mt19937 gen(rd()); 
            std::uniform_int_distribution<> distrib(0, t - 1);
            int x = distrib(gen);
            
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_H4(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_H4(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }

    if (allPassed) {
        std::cout << "All tests passed!" << std::endl;
    }
}

const void test_L4_poly(int t) {
    bool allPassed = true;

    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(t) + "_L4_Poly.txt";
    
    // A vector to hold the coefficients
    std::vector<int> coefficients;

    // Check if the file exists
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        // File doesn't exist, generate the coefficients
        coefficients = get_L4_Coefficients(t);
        
        // 使用 filesystem::path 解析文件路径
        std::filesystem::path path(filename);

        // 检查父路径（文件夹）是否存在
        if (!std::filesystem::exists(path.parent_path())) {
            // 尝试创建所有不存在的父路径（文件夹）
            bool created = std::filesystem::create_directories(path.parent_path());
            if (!created) {
                // 如果创建文件夹失败，则打印错误信息并返回
                std::cerr << "Failed to create directories for: " << path.parent_path() << std::endl;
                return;
            }
        }

        // Open the file for writing
        std::ofstream outFile(filename);
        
        // Check if the file opened successfully
        if (outFile.is_open()) {
            for (const auto &coef : coefficients) {
                outFile << coef << std::endl; // Write each coefficient on a new line
            }
            outFile.close(); // Close the file
        } else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }

    if (t < 1000)
    {
        #pragma omp parallel for num_threads(num_th)
        for (int x = 0; x < t; x++) {
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_L4(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_L4(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }
    else
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < 1000; i++) {
            // x is a random integer between [0,1,...,t-1]
            std::random_device rd; 
            std::mt19937 gen(rd()); 
            std::uniform_int_distribution<> distrib(0, t - 1);
            int x = distrib(gen);
            
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_L4(x, t) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_L4(x, t) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }

    if (allPassed) {
        std::cout << "All tests passed!" << std::endl;
    }
}

const void test_sign_poly(int t, uint64_t Q) {
    bool allPassed = true;

    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(t) + "_" + std::to_string(Q) + "_sign_Poly.txt";
    
    // A vector to hold the coefficients
    std::vector<int> coefficients;

    // Check if the file exists
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        // File doesn't exist, generate the coefficients
        coefficients = get_sign_Coefficients(t, Q);
        
        // 使用 filesystem::path 解析文件路径
        std::filesystem::path path(filename);

        // 检查父路径（文件夹）是否存在
        if (!std::filesystem::exists(path.parent_path())) {
            // 尝试创建所有不存在的父路径（文件夹）
            bool created = std::filesystem::create_directories(path.parent_path());
            if (!created) {
                // 如果创建文件夹失败，则打印错误信息并返回
                std::cerr << "Failed to create directories for: " << path.parent_path() << std::endl;
                return;
            }
        }

        // Open the file for writing
        std::ofstream outFile(filename);
        
        // Check if the file opened successfully
        if (outFile.is_open()) {
            for (const auto &coef : coefficients) {
                outFile << coef << std::endl; // Write each coefficient on a new line
            }
            outFile.close(); // Close the file
        } else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }

    if (t < 1000)
    {
        #pragma omp parallel for num_threads(num_th)
        for (int x = 0; x < t; x++) {
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_sign(x, t, Q) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_sign(x, t, Q) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }
    else
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < 1000; i++) {
            // x is a random integer between [0,1,...,t-1]
            std::random_device rd; 
            std::mt19937 gen(rd()); 
            std::uniform_int_distribution<> distrib(0, t - 1);
            int x = distrib(gen);
            
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_sign(x, t, Q) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_sign(x, t, Q) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }

    if (allPassed) {
        std::cout << "All tests passed!" << std::endl;
    }
}

const void test_f0_poly(int t, uint64_t Q) {
    bool allPassed = true;

    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(t) + "_" + std::to_string(Q) + "_f0_Poly.txt";
    
    // A vector to hold the coefficients
    std::vector<int> coefficients;

    // Check if the file exists
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        // File doesn't exist, generate the coefficients
        coefficients = get_f0_Coefficients(t, Q);
        
        // 使用 filesystem::path 解析文件路径
        std::filesystem::path path(filename);

        // 检查父路径（文件夹）是否存在
        if (!std::filesystem::exists(path.parent_path())) {
            // 尝试创建所有不存在的父路径（文件夹）
            bool created = std::filesystem::create_directories(path.parent_path());
            if (!created) {
                // 如果创建文件夹失败，则打印错误信息并返回
                std::cerr << "Failed to create directories for: " << path.parent_path() << std::endl;
                return;
            }
        }

        // Open the file for writing
        std::ofstream outFile(filename);
        
        // Check if the file opened successfully
        if (outFile.is_open()) {
            for (const auto &coef : coefficients) {
                outFile << coef << std::endl; // Write each coefficient on a new line
            }
            outFile.close(); // Close the file
        } else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }

    if (t < 1000)
    {
        #pragma omp parallel for num_threads(num_th)
        for (int x = 0; x < t; x++) {
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_f0(x, t, Q) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_f0(x, t, Q) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }
    else
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < 1000; i++) {
            // x is a random integer between [0,1,...,t-1]
            std::random_device rd; 
            std::mt19937 gen(rd()); 
            std::uniform_int_distribution<> distrib(0, t - 1);
            int x = distrib(gen);
            
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_f0(x, t, Q) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_f0(x, t, Q) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }

    if (allPassed) {
        std::cout << "All tests passed!" << std::endl;
    }
}

const void test_f1_poly(int t, uint64_t Q) {
    bool allPassed = true;

    // Specify the path
    // std::string path = "PolyGenerator/poly/";
    std::string path = "PolyGenerator/poly/";
    // Create the filename
    std::string filename = path + std::to_string(t) + "_" + std::to_string(Q) +  "_f1_Poly.txt";
    
    // A vector to hold the coefficients
    std::vector<int> coefficients;

    // Check if the file exists
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        // File exists, read the content
        int value;
        while (inFile >> value) {
            coefficients.push_back(value);
        }
        inFile.close();
    } else {
        // File doesn't exist, generate the coefficients
        coefficients = get_f1_Coefficients(t, Q);
        
        // 使用 filesystem::path 解析文件路径
        std::filesystem::path path(filename);

        // 检查父路径（文件夹）是否存在
        if (!std::filesystem::exists(path.parent_path())) {
            // 尝试创建所有不存在的父路径（文件夹）
            bool created = std::filesystem::create_directories(path.parent_path());
            if (!created) {
                // 如果创建文件夹失败，则打印错误信息并返回
                std::cerr << "Failed to create directories for: " << path.parent_path() << std::endl;
                return;
            }
        }

        // Open the file for writing
        std::ofstream outFile(filename);
        
        // Check if the file opened successfully
        if (outFile.is_open()) {
            for (const auto &coef : coefficients) {
                outFile << coef << std::endl; // Write each coefficient on a new line
            }
            outFile.close(); // Close the file
        } else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }

    if (t < 1000)
    {
        #pragma omp parallel for num_threads(num_th)
        for (int x = 0; x < t; x++) {
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_f1(x, t, Q) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_f1(x, t, Q) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }
    else
    {
        #pragma omp parallel for num_threads(num_th)
        for (int i = 0; i < 1000; i++) {
            // x is a random integer between [0,1,...,t-1]
            std::random_device rd; 
            std::mt19937 gen(rd()); 
            std::uniform_int_distribution<> distrib(0, t - 1);
            int x = distrib(gen);
            
            int temp = evaluateDraMpoly(x, coefficients);
            if (DRaM_f1(x, t, Q) != temp) {
                std::cout << "Test failed for x = " << x << ". DRaM: " << DRaM_f1(x, t, Q) << ", DRaMpoly: " << temp << std::endl;
                allPassed = false;
            }
            // std::cout << "x: " << x << std::endl;
        }
    }

    if (allPassed) {
        std::cout << "All tests passed!" << std::endl;
    }
}

const void NWC_Manual(const VecData &operand1, const VecData &operand2, const size_t poly_size, const size_t mod_size,  const Modulus modulus, const std::vector<Modulus> &vec_mod, VecData &result){
    
    Modulus mod(modulus);
    // std::cout << "modulus: " << mod.value() << std::endl;
    // std::cout << "size: " << size << std::endl;

    result.resize(poly_size * mod_size);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0;i<poly_size * mod_size;i++){
        result[i] = 0;
    }

    // for (int i=0;i<16;i++){
    //     std::cout << "operand2[i]: " << operand2[i] << std::endl;
    // }


    // Initialize to zero
    VecData result_2N((2*poly_size-1)*mod_size, 0ULL);
    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<mod_size; i++){
        for(int j=0; j<2*poly_size-1; j++){
            result_2N[j+i*poly_size] = 0;
        }
    }
    // std::cout << "result_2N: ";
    // util::Display(result_2N);

    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<mod_size; i++){
        for(int j=0; j<poly_size; j++){
            for(int t=0; t<j+1; t++){
                result_2N[j+i*(2*poly_size-1)] = seal::util::add_uint_mod(result_2N[j+i*(2*poly_size-1)], seal::util::multiply_uint_mod(operand1[i*poly_size+t], operand2[i*poly_size+j-t], vec_mod[i]), vec_mod[i]);
            }
        }
    }
    // std::cout << "result_2N: ";
    // util::Display(result_2N);
    // for (int i=0; i<poly_size; i++){
    //     for (int j=0; j<i+1; j++){
    //         result_2N[i] = seal::util::add_uint_mod(result_2N[i], seal::util::multiply_uint_mod(operand1[j], operand2[i-j], mod), mod);
            // std::cout << "i-j: " << i-j << std::endl;
            // std::cout << "operand1[j]: " << operand1[j] << std::endl;
            // std::cout << "operand2[i-j]: " << operand2[i-j] << std::endl;
            // std::cout << "result_2N: " << result_2N[i] << std::endl;
    //     }
    // }

    #pragma omp parallel for num_threads(num_th)
    for (int i=0; i<mod_size; i++){
        for(int j=poly_size; j<2*poly_size-1; j++){
            for(int t=j-poly_size+1; t<poly_size; t++){
                result_2N[j+i*(2*poly_size-1)] = seal::util::add_uint_mod(result_2N[j+i*(2*poly_size-1)], seal::util::multiply_uint_mod(operand1[t+i*poly_size], operand2[i*poly_size+j-t], vec_mod[i]), vec_mod[i]);
            }
        }
    }
    // for (int i=poly_size; i<2*poly_size-1; i++){
    //     for (int j=i-poly_size+1; j<poly_size; j++){
    //         // if (i==size)
    //         //     std::cout << "j: " << j << "(" << operand1[j] << ")" << "i-j: " << i-j << "(" << operand2[i-j] << ")" << " ";
    //         result_2N[i] = seal::util::add_uint_mod(result_2N[i], seal::util::multiply_uint_mod(operand1[j], operand2[i-j], mod), mod);
    //         // std::cout << "result_2N: " << result_2N[i] << std::endl;
    //     }
    // }


    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<mod_size; i++){
        for(int j=0; j<poly_size; j++){
            result[j+i*poly_size] = result_2N[j+i*(2*poly_size-1)];
        }
    }
    // for (int i=0; i<poly_size; i++){
    //     result[i] = result_2N[i];
    //     // std::cout << "result[i]: " << result[i] << std::endl;
    // }

    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<mod_size; i++){
        for(int j=poly_size; j<2*poly_size-1; j++){
            result[i*poly_size+j-poly_size] = seal::util::add_uint_mod(result[i*poly_size+j-poly_size], seal::util::negate_uint_mod(result_2N[i*(2*poly_size-1)+j], vec_mod[i]) , vec_mod[i]);
        }
    }
    // for (int i=poly_size; i<2*poly_size-1; i++){
    //     result[i-poly_size] = seal::util::add_uint_mod(result[i-poly_size], seal::util::negate_uint_mod(result_2N[i], mod) , mod);
    //     // std::cout << "result[i-size]: " << result[i-size]<< std::endl;
    // }

    // std::cout << " ";
    // util::Display(operand1);
    // std::cout << "Operand2: ";
    // util::Display(operand2);
    // std::cout << "result_2N: ";
    // util::Display(result_2N);
    // std::cout << "result: ";
    // util::Display(result);

    return;

}

const void NTT_Matrix_Trans(const VecData &operand, const size_t size, const Modulus modulus, VecData &result){

    result.resize(size);
    for (int i=0; i<size; i++){
        result[i] = 0;
    }
    uint64_t prim_root = 0;
    util::try_minimal_primitive_root(size*2, modulus, prim_root);
    // std::cout << "Primitive root: " << prim_root << std::endl;

    // std::cout << "NTT input: ";
    // for (int i=0; i<size; i++){
    //     std::cout << operand[i] << " ";
    // }
    // std::cout << std::endl;
    
    // Gen NTT transmatrix
    MatrixData Matrix_NTT(size, VecData(size));
    for (int i=0; i<size; i++){
        size_t exp = 2*i;
        uint64_t zeta = util::exponentiate_uint_mod(prim_root, exp, modulus);
        for(int j=0; j<size; j++){
            Matrix_NTT[i][j] = exponentiate_uint_mod(zeta, j, modulus);
        }
    }

    // std::cout << "NTT matrix is: " << std::endl;
    // for (int i=0; i<size; i++){
    //     for (int j=0; j<size; j++){
    //         std::cout << Matrix_NTT[i][j] << " ";
    //     }
    //     std::cout << std::endl;
    // }
    // std::cout << std::endl;

    // Do element-wise multiplication
    VecData ele_wi_result(size, 0ULL);
    for (int i=0; i<size; i++){
        uint64_t zeta = util::exponentiate_uint_mod(prim_root, i, modulus);
        ele_wi_result[i] = util::multiply_uint_mod(operand[i], zeta, modulus);
    }

    // std::cout << "NTT element wise result: ";
    // for (int i=0; i<size; i++){
    //     std::cout << ele_wi_result[i] << " ";
    // }
    // std::cout << std::endl;
    

    // Do MVP
    for (int i=0; i<size; i++){
        for (int j=0; j<size; j++){
            result[i] = util::add_uint_mod(   result[i] , util::multiply_uint_mod(   Matrix_NTT[i][j], ele_wi_result[j], modulus   ) , modulus   );
        }
    }

    // std::cout << "NTT trans result: ";
    // for (int i=0; i<size; i++){
    //     std::cout << result[i] << " ";
    // }
    // std::cout << std::endl;


    return;
}

const void Inverse_NTT_Matrix_Trans(const VecData &operand, const size_t size, const Modulus modulus, VecData &result){

    result.resize(size);
    for (int i=0; i<size; i++){
        result[i] = 0;
    }
    uint64_t prim_root = 0;
    util::try_minimal_primitive_root(size*2, modulus, prim_root);
    util::try_invert_uint_mod(prim_root, modulus, prim_root);
    // std::cout << "Inverse Primitive root: " << prim_root << std::endl;

    // std::cout << "Inverse NTT input: ";
    // for (int i=0; i<size; i++){
    //     std::cout << operand[i] << " ";
    // }
    // std::cout << std::endl;


    
    // Gen Inverse NTT transmatrix
    MatrixData Matrix_NTT(size, VecData(size));
    for (int i=0; i<size; i++){
        size_t exp = 2*i;
        uint64_t zeta = util::exponentiate_uint_mod(prim_root, exp, modulus);
        for(int j=0; j<size; j++){
            Matrix_NTT[i][j] = exponentiate_uint_mod(zeta, j, modulus);
        }
    }

    // std::cout << "Inverse NTT matrix is: " << std::endl;
    // for (int i=0; i<size; i++){
    //     for (int j=0; j<size; j++){
    //         std::cout << Matrix_NTT[i][j] << " ";
    //     }
    //     std::cout << std::endl;
    // }
    // std::cout << std::endl;

    // Do MVP
    for (int i=0; i<size; i++){
        for (int j=0; j<size; j++){
            result[i] = util::add_uint_mod(   result[i] , util::multiply_uint_mod(   Matrix_NTT[i][j], operand[j], modulus   ) , modulus   );
        }
    }

    // std::cout << "Inverse NTT MVP result: ";
    // for (int i=0; i<size; i++){
    //     std::cout << result[i] << " ";
    // }
    // std::cout << std::endl;

    // Do element-wise multiplication
    for (int i=0; i<size; i++){
        uint64_t zeta = util::exponentiate_uint_mod(prim_root, i, modulus);
        result[i] = util::multiply_uint_mod(result[i], zeta, modulus);
    }

    // std::cout << "Inverse NTT element wise result: ";
    // for (int i=0; i<size; i++){
    //     std::cout << result[i] << " ";
    // }
    // std::cout << std::endl;

    // Do 1/N
    uint64_t inv_n = 0;
    util::try_invert_uint_mod(size, modulus, inv_n);
    for(int i=0; i<size; i++){
        result[i] = util::multiply_uint_mod(result[i], inv_n, modulus);
    }
    // std::cout << "Inverse N is: ";
    // std::cout << inv_n << std::endl;

    // std::cout << "Inverse NTT trans result: ";
    // for (int i=0; i<size; i++){
    //     std::cout << result[i] << " ";
    // }
    // std::cout << std::endl;

    return;
}

const void component_wise_mod_mul(const VecData &operand1, const VecData &operand2, const size_t &size, const Modulus modulus, VecData &result){

    for (int i=0; i<size; i++){
        result[i] = util::multiply_uint_mod(operand1[i], operand2[i], modulus);
    }
    return;
}

const void poly_mul_use_matrix_ntt(const VecData &operand1, const VecData &operand2, const size_t &size, const Modulus modulus, VecData &result)
{

    VecData ntt_1 (size, 0ULL);
    VecData ntt_2 (size, 0ULL);

    util::NTT_Matrix_Trans(operand1, size, modulus, ntt_1);
    util::NTT_Matrix_Trans(operand2, size, modulus, ntt_2);
    VecData ntt_3 (size, 0ULL);
    util::component_wise_mod_mul(ntt_1, ntt_2, size, modulus, ntt_3);
    util::Inverse_NTT_Matrix_Trans(ntt_3, size, modulus, result);

    return;

}

const void Negate_Manual(const VecData &operand1, const size_t &poly_size, const size_t &mod_size,  const Modulus modulus, const std::vector<Modulus> &vec_mod,  VecData &result)
{
    result.resize(poly_size * mod_size);

    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<mod_size; i++){
        for(int j=0; j<poly_size; j++){
            result[j+i*poly_size] = util::negate_uint_mod(operand1[j+i*poly_size], vec_mod[i]);
        }
    }

    // for (int i=0; i<size; i++){
    //     result[i] = util::negate_uint_mod(operand1[i], modulus);
    // }

    return;
}

const void Shift_Manual(const VecData &operand1, const size_t size, const size_t shift_idx, VecData &result)
{   
    // left shift

    if(shift_idx > 0 & shift_idx <= size){
        std::cout << "Before left shift: ";
        util::Display(operand1);
        for (int i=0; i<(size-shift_idx); i++){
            result[i] = operand1[size-shift_idx-1+i];
        }
        for (int i=(size-shift_idx); i<size; i++){
            result[i] = operand1[i-shift_idx-1];
        }
        std::cout << "After left shift: ";
        util::Display(result);
    }
    // right shift
    else{
        std::cout << "Before right shift: ";
        util::Display(operand1);
        size_t shift;
        shift = -shift_idx;
        for (int i=0; i<shift; i++){
            result[i] = operand1[size-shift+i];
        }
        for (int i=shift; i<size; i++){
            result[i] = operand1[i-shift];
        }
        std::cout << "After right shift: ";
        util::Display(result);
    }
}

const void Add_Manual(const VecData &operand1, const VecData &operand2, const size_t &poly_size, const size_t &mod_size, const Modulus modulus, std::vector<Modulus> vec_mod,  VecData &result)
{
    result.resize(poly_size * mod_size);

    #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<mod_size; i++){
        for(int j=0; j<poly_size; j++){
            result[j+i*poly_size] = util::add_uint_mod(operand1[j+i*poly_size], operand2[j+i*poly_size], vec_mod[i]);
        }
    }
    // for(int i=0; i<size; i++){
    //     result[i] = util::add_uint_mod(operand1[i], operand2[i], modulus);
    // }

    return;
}

const void Sub_Manual(const VecData &operand1, const VecData &operand2, const size_t size,  const Modulus modulus, VecData &result)
{
    result.resize(size);
    for(int i=0; i<size; i++){
        result[i] = util::sub_uint_mod(operand1[i], operand2[i], modulus);
    }

    return;
}

const void Encrypt_Manual(const VecData &ptxt, const VecData &seckey, const size_t &poly_size, const size_t &mod_size, const Modulus modulus, const std::vector<Modulus> &vec_mod, MatrixData &ctxt)
{
    ctxt.resize(2, VecData(poly_size * mod_size));
    VecData temp_mask(poly_size * mod_size, 0ULL);
    // #pragma omp parallel for num_threads(num_th)
    for(int i=0; i<mod_size; i++){
        for(int j=0; j<poly_size; j++){
            uint64_t rd = random_uint64();
            // uint64_t rd = 1; // we fix random mask
            temp_mask[j + i*poly_size] = util::multiply_uint_mod(rd, 1, vec_mod[i]); 
        }
        std::cout << "vec_mod: " << vec_mod[i].value() << std::endl;
    }
    // for(int i=0; i<poly_size; i++){
    //     // temp_mask[i] = modulus.value() - i - 1;
    //     uint64_t rd = random_uint64();
    //     temp_mask[i] = util::multiply_uint_mod(rd, 1, modulus); 
    // }
    std::cout << "encryption mask is: ";
    util::Display(temp_mask);
    VecData as (poly_size * mod_size, 0ULL);
    util::NWC_Manual(temp_mask, seckey, poly_size, mod_size, modulus, vec_mod, as);
    std::cout << "a*s is: ";
    util::Display(as);
    VecData neg_as (mod_size * poly_size, 0ULL);
    util::Negate_Manual(as, poly_size, mod_size, modulus, vec_mod, neg_as);
    std::cout << "negative a*s is: ";
    util::Display(neg_as);
    VecData m_neg_as (poly_size, 0ULL);
    util::Add_Manual(ptxt, neg_as, poly_size, mod_size, modulus, vec_mod, m_neg_as);
    std::cout << "m - a*s is: ";
    util::Display(m_neg_as);
    ctxt[0] = m_neg_as;
    ctxt[1] = temp_mask;

    return;
}

const void Decrypt_Manual( MatrixData &ctxt, const VecData &seckey,  const size_t &poly_size, const size_t &mod_size, const Modulus modulus, const std::vector<Modulus> &mod_vec, VecData &ptxt)
{
    VecData as(poly_size * mod_size, 0ULL);
    NWC_Manual(ctxt[1], seckey, poly_size, mod_size, modulus, mod_vec, as);
    ptxt.resize(poly_size * mod_size);
    Add_Manual(ctxt[0], as, poly_size, mod_size, modulus, mod_vec, ptxt);

    return;
}

// nothing
const void try_to_find_poly(const size_t n, const seal::Modulus mod_plain)
{   
    seal::MatrixData matrix_decode;
    seal::Modulus mod_degree(2*n);
    matrix_decode.resize(n, seal::VecData(n));
    uint64_t root;
    seal::util::try_primitive_root(2*n, mod_plain, root);
    // gen decode matrix
    for (int i=0; i<n/2; i++)
    {   
        uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
        for (int j=0; j<n; j++){
            matrix_decode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
        }
    }
    for (int i=n/2; i<n; i++)
    {   
        uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
        seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        for (int j=0; j<n; j++){
            matrix_decode[i][j] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
        }
    }

    std::cout << "Decode Matrix: " << std::endl;
    for (int i=0; i<n; i++){
        for (int j=0; j<n; j++){
            std::cout << matrix_decode[i][j] << " ";
        }
        std::cout << std::endl;
    }

    // define test vector
    seal::VecData vec_test(n, 0ULL);
    for(int i=0; i<n; i++){
        vec_test[i] = i+1;
    }

    // Cryptor cryptor;
    // seal::MatrixData matrix_decode_crypto;
    // cryptor.GenDecodeMatrix(matrix_decode_crypto);

    // std::cout << "Crypto Decode Matrix: " << std::endl;
    // for (int i=0; i<n; i++){
    //     for (int j=0; j<n; j++){
    //         std::cout << matrix_decode_crypto[i][j] << " ";
    //     }
    //     std::cout << std::endl;
    // }

    // Modulus mod_crypto(RLWEParams::plain_modulus);
    // uint64_t row_sum = 0;
    // for (int i=0; i<RLWEParams::poly_modulus_degree; i++){
    //     row_sum = seal::util::add_uint_mod(matrix_decode_crypto[1][i], row_sum, mod_crypto);
    // }

    // std::cout << "row_sum: " << row_sum << std::endl;

    seal::MatrixData matrix_decode_rev;
    matrix_decode_rev.resize(n, seal::VecData(n));

    for (int i=0; i<n; i++){
        for(int j=0; j<n; j++){
            if(j==0){
                matrix_decode_rev[i][0] = matrix_decode[i][0];
            }
            else{
                matrix_decode_rev[i][j] = matrix_decode[i][n-j];
                matrix_decode_rev[i][j] = seal::util::negate_uint_mod(matrix_decode_rev[i][j], mod_plain);
            }
        }
    }

    // gen encode matrix
    seal::MatrixData matrix_encode;
    matrix_encode.resize(n, seal::VecData(n));
    for (int i=n/2; i<n; i++)
    {   
        uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
        for (int j=0; j<n; j++){
            matrix_encode[j][i] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
        }
    }
    for (int i=0; i<n/2; i++)
    {   
        uint64_t exp = seal::util::exponentiate_uint_mod(3, i, mod_degree);
        uint64_t zeta = seal::util::exponentiate_uint_mod(root, exp, mod_plain);
        seal::util::try_invert_uint_mod(zeta, mod_plain, zeta);
        for (int j=0; j<n; j++){
            matrix_encode[j][i] = seal::util::exponentiate_uint_mod(zeta, j, mod_plain);
        }
    }

    std::cout << "Encode Matrix: " << std::endl;
    for (int i=0; i<n; i++){
        for (int j=0; j<n; j++){
            std::cout << matrix_encode[i][j] << " ";
        }
        std::cout << std::endl;
    }

    // encode to plaintext
    seal::VecData ptxt_test(n, 0);
    for(int i=0; i<n; i++){
        for(int j=0; j<n; j++){
            ptxt_test[i] = seal::util::add_uint_mod(ptxt_test[i], seal::util::multiply_uint_mod(matrix_encode[i][j], vec_test[j], mod_plain), mod_plain);
        }
    }

    // do plaintext convolution
    
    for (int i=0; i<n; i++){
        seal::VecData ptxt_result(n, 0ULL);
        seal::VecData matrix_temp(n, 0ULL);
        for (int j=0; j<n; j++){
            matrix_temp[j] = matrix_decode_rev[i][j];
        }
        seal::util::NWC_Manual(matrix_temp, ptxt_test, n, 1, mod_plain, {mod_plain}, ptxt_result);
        std::cout << "ptxt_result: " << std::endl;
        for (int j=0; j<n; j++){
            std::cout << ptxt_result[j] << " ";
        }
        std::cout << std::endl;
    }
    

}

// TFHE part
void sample_poly_binary(
    std::shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination)
{
    auto coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.poly_modulus_degree();

    RandomToStandardAdapter engine(prng);
    std::uniform_int_distribution<uint64_t> dist(0, 1);

    SEAL_ITERATE(iter(destination), coeff_count, [&](auto &I) {
                uint64_t rand = dist(engine);
                // uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(rand == 0));
                SEAL_ITERATE(
                    iter(StrideIter<uint64_t *>(&I, coeff_count), coeff_modulus), coeff_modulus_size,
                    [&](auto J) { *get<0>(J) = rand; }); });
}

const uint64_t pow2mod(const size_t exponent, const Modulus modulus)
{
    uint64_t scale = util::multiply_uint_mod((1ULL << 63), 2, modulus);
    uint64_t val = util::multiply_uint_mod((1ULL << (exponent & 63)), 1, modulus);
    for (size_t i = 0; i < exponent / 64; i++)
        val = util::multiply_uint_mod(val, scale, modulus);
    return val;
}

TFHERNSTool::TFHERNSTool(const SEALContext &context, const ParamSet paramset)
{
    context_ = std::make_shared<SEALContext>(context);
    switch (paramset) {
    case ParamSet::LWE:
        Bgbits = LWEParams::decompose_log_base;
        lognmod = LWEParams::lognmod;
        break;
    case ParamSet::RGSW:
        Bgbits = RGSWParams::decompose_log_base;
        lognmod = RGSWParams::lognmod;
        break;
    default:
        Bgbits = RGSWParams::decompose_log_base;
        lognmod = RGSWParams::lognmod;
        break;
    }

    auto &context_data = *context_->first_context_data().get();
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    coeff_modulus_size = coeff_modulus.size();

    Qbits = context_data.total_coeff_modulus_bit_count() + lognmod;
    auto Wlen = Bgbits;
    if (coeff_modulus_size > 1) {
        Qsize = context_data.rns_tool()->base_q()->size();
        Qword = (Qbits + Wlen - 1) / Wlen;
        poly_modulus_degree = parms.poly_modulus_degree();
        auto punctured_prod_array = context_data.rns_tool()->base_q()->punctured_prod_array();
        auto inv_punctured_prod = context_data.rns_tool()->base_q()->inv_punctured_prod_mod_base_array();
        auto base_prod = context_data.rns_tool()->base_q()->base_prod();

        Qbar.resize(coeff_modulus_size);
        Qinv.resize(coeff_modulus_size);
        Qtot.resize(Qword);
        vec_sft_red(base_prod, Qtot.data());
        for (size_t i = 0; i < coeff_modulus_size; i++)
            Qinv[i] = inv_punctured_prod[i].operand;
        for (size_t i = 0; i < coeff_modulus_size; i++) {
            Qbar[i].resize(Qword);
            vec_sft_red(punctured_prod_array + Qsize * i, Qbar[i].data());
        }
    } else {
        Qsize = 1;
        Qword = (Qbits + Wlen - 1) / Wlen;
        poly_modulus_degree = parms.poly_modulus_degree();
        Qbar.resize(coeff_modulus_size);
        Qinv.resize(coeff_modulus_size);
        Qtot.resize(Qword);
        uint64_t base_prod[1] = {coeff_modulus[0].value()};
        vec_sft_red(base_prod, Qtot.data());
        Qinv[0] = 1;
        for (size_t i = 0; i < coeff_modulus_size; i++) {
            Qbar[i].resize(Qword);
            base_prod[0] = 1;
            vec_sft_red(base_prod, Qbar[i].data());
        }
    }
}

inline void TFHERNSTool::vec_sft_red(const uint64_t *vec_in, uint64_t *vec_out) const
{
    std::vector<uint64_t> buffer(Qsize + 1);
    std::copy_n(vec_in, Qsize, buffer.begin() + 1);
    buffer[0] = 0;
    uint64_t mask = (1UL << Bgbits) - 1;
    for (size_t i = 0; i < Qword; i++) {
        int start = Qbits + 64 - Bgbits * (i + 1), end = Qbits + 64 - Bgbits * i;
        int wstart = start / 64, wend = end / 64;
        int bstart = start - wstart * 64, bend = end - wend * 64;
        if (wstart == wend)
            vec_out[i] = (buffer[wstart] >> bstart) & mask;
        else
            vec_out[i] = (buffer[wstart] >> bstart) | ((buffer[wend] & (mask >> (Bgbits - bend))) << (Bgbits - bend));
        // vec_out[i] = buffer[0] & mask;
        // for (size_t j = 0; j < Qsize - 1; j++) {
        //     buffer[j] >>= Bgbits;
        //     buffer[j] |= ((buffer[j + 1] & mask) << (64 - Bgbits));
        // }
        // buffer[Qsize - 1] >>= Bgbits;
    }
}

void TFHERNSTool::CRTDecPoly(const std::uint64_t *poly, std::vector<std::vector<uint64_t>> &crtdec) const
{
    size_t Wlen = Bgbits;
    uint64_t mask = (1UL << Bgbits) - 1;
    auto &coeff_modulus = context_->first_context_data()->parms().coeff_modulus();
    std::vector<uint64_t> poly_copy(coeff_modulus_size * poly_modulus_degree);
    for (size_t i = 0; i < coeff_modulus_size; i++)
        for (size_t j = 0; j < poly_modulus_degree; j++)
            poly_copy[j + i * poly_modulus_degree] = util::multiply_uint_mod(poly[j + i * poly_modulus_degree], Qinv[i], coeff_modulus[i]);
    crtdec.resize(Qword);
    for (size_t k = 0; k < Qword; k++)
        crtdec[k].resize(poly_modulus_degree);
    for (size_t j = 0; j < poly_modulus_degree; j++)
        for (size_t i = 0; i < coeff_modulus_size; i++) {
            __uint128_t prod = 0;
            for (size_t k = 0; k < Qword; k++) {
                uint64_t val = Qbar[i][Qword - 1 - k];
                prod += static_cast<__uint128_t>(poly_copy[j + i * poly_modulus_degree]) * val + crtdec[Qword - 1 - k][j];
                crtdec[Qword - 1 - k][j] = prod & mask;
                prod >>= Wlen;
            }
        }
}

// RLWE Key Switch simple verification
const void Display(const seal::VecData &vec, const size_t display_length){
    size_t length = vec.size();
    if(display_length != 0){
        for(int i = 0; i<display_length; i++){
            std::cout << vec[i] << " ";
        }
    }
    else{
        for(int i = 0; i<length; i++){
            std::cout << vec[i] << " ";
        }
    }
    std::cout << std::endl;
    return;
}

const void mul_coeff_mod(const seal::VecData &vec, const size_t poly_size, const size_t &mod_size, const uint64_t scale, const seal::Modulus modulus, const std::vector<Modulus> &vec_mod, VecData &result)
{
    result.resize(poly_size * mod_size);
    for(int i=0; i<mod_size; i++){
        for(int j=0; j<poly_size; j++){
            result[j+i*poly_size] = util::multiply_uint_mod(vec[j+i*poly_size], scale, vec_mod[i]);
        }
    }
    // for (int i=0; i<size; i++){
    //     result[i] = util::multiply_uint_mod(vec[i], scale, modulus);
    // }
    return;
}

const void divide_coeff_mod(const seal::VecData &vec, const size_t &poly_size,const size_t &mod_size, const size_t dec_base, const size_t idx, const seal::Modulus modulus, const std::vector<Modulus> &vec_mod, VecData &result)
{   
    Modulus mod_base((uint64_t) 1 << dec_base);
    std::cout << "dec base: " << ((uint64_t) 1 << dec_base) << " " << idx << "-th scale: " << ((uint64_t) 1 << (dec_base * idx)) << std::endl;
    result.resize(poly_size * mod_size);
    // std::cout << "      Before divide: ";
    // util::Display(vec);
    std::cout << "oringin data: " ;
    util::Display(vec);
    for(int i=0; i<poly_size * mod_size; i++){
        result[i] = vec[i] >> (dec_base * idx);
    }
    std::cout << "after divide data: " ;
    util::Display(result);
    for(int i=0; i<poly_size*mod_size; i++){
        util::modulo_uint_inplace(&result[i], 1, mod_base);
    }
    std::cout << "after mod base " << ((uint64_t) 1 << dec_base) << ": ";
    util::Display(result);
    return;
}

const void extract_temp_key(const VecData &long_key, const size_t &long_n, const size_t &short_n, const size_t &mod_size, const size_t &idx, VecData &short_key)
{
    short_key.resize(short_n * mod_size);
    size_t npoly = long_n / short_n;
    for(int i=0; i<mod_size; i++){
        for(int j=0; j<short_n; j++){
            short_key[j+i*short_n] = long_key[j*npoly+idx+i*long_n];
        }
    }
    std::cout << "Long key is: ";
    util::Display(long_key);
    std::cout << idx << "-th extract short key is: ";
    util::Display(short_key);

    // for(int i=0; i<short_n; i++){
    //     short_key[i] = long_key[i*npoly+idx];
    // }

    return;
}

const void poly_rlwe_mul(const MatrixData &rlwe, const VecData &poly, const size_t &poly_size, const size_t &mod_size, const Modulus modulus, const std::vector<Modulus> &vec_mod, MatrixData &result_rlwe)
{
    result_rlwe.resize(2, VecData(poly_size * mod_size));
    for(int i=0; i<2; i++){
        std::cout << i << "-th of rlwe: ";
        util::Display(rlwe[i]);
        std::cout << "poly is: ";
        util::Display(poly);
        util::NWC_Manual(rlwe[i], poly, poly_size, mod_size, modulus, vec_mod, result_rlwe[i]);
        std::cout << i << "-th result: ";
        util::Display(result_rlwe[i]);
    }
    // for (int i=0; i<2; i++){
    //     util::NWC_Manual(rlwe[i], poly, size, 1, modulus, {modulus}, result_rlwe[i]);
    // }
    return;
}

const void rlwe_add_inplace(MatrixData &rlwe1, const MatrixData &rlwe2, const size_t &poly_size, const size_t &mod_size, const Modulus &modulus, const std::vector<Modulus> &vec_mod)
{

    for (int i=0; i<2; i++){
        for (int j=0; j<mod_size; j++){
            for(int t=0; t<poly_size; t++){
                rlwe1[i][t+j*poly_size] = util::add_uint_mod(rlwe1[i][t+j*poly_size], rlwe2[i][t+j*poly_size], vec_mod[j]);
            }
        }
    }
    
    // for (int i=0; i<2; i++){
    //     for (int j=0; j<size; j++){
    //         rlwe1[i][j] = util::add_uint_mod(rlwe1[i][j], rlwe2[i][j], modulus);
    //     }
    // }

    return;
}

const void rlwe_sub_inplace(MatrixData &rlwe1, const MatrixData &rlwe2, const size_t &poly_size, const size_t &mod_size, const Modulus &modulus, const std::vector<Modulus> &vec_mod)
{
    for (int i=0; i<2; i++){
        for (int j=0; j<mod_size; j++){
            for(int t=0; t<poly_size; t++){
                rlwe1[i][t+j*poly_size] = util::sub_uint_mod(rlwe1[i][t+j*poly_size], rlwe2[i][t+j*poly_size], vec_mod[j]);
            }
        }
    }

    // for (int i=0; i<2; i++){
    //     for (int j=0; j<size; j++){
    //         rlwe1[i][j] = util::sub_uint_mod(rlwe1[i][j], rlwe2[i][j], modulus);
    //     }
    // }

    return;
}

const void bias_poly(const VecData &poly, const size_t &poly_size, const size_t &mod_size, const Modulus &modulus, const std::vector<Modulus> &vec_mod, VecData &biased_poly)
{
    for(int i=0; i<mod_size; i++){
        for(int j=0; j<poly_size; j++){
            if(j==0){
                biased_poly[j+i*poly_size] = vec_mod[i].value() - poly[poly_size-1+i*poly_size];
            }
            else{
                biased_poly[j+i*poly_size] = poly[j-1+i*poly_size];
            }
        }
    }
    return;
}

const void Generate_RLWE_KSkey_Manual(const VecData &longkey, const VecData &shortkey, const size_t &long_n, const size_t &short_n, const size_t &mod_size, const size_t &dec_base, const size_t &dec_level, const Modulus &modulus, const std::vector<Modulus> &vec_mod, std::vector<std::vector<MatrixData>> &rlwe_switch_key)
{
    size_t npoly = long_n / short_n;
    rlwe_switch_key.resize(npoly);

    for (int i=0; i<npoly; i++){
        std::vector<MatrixData> temp_rlev(dec_level);
        VecData temp_key(short_n*mod_size, 0ULL);
        util::extract_temp_key(longkey, long_n, short_n, mod_size, i, temp_key);
        // std::cout << i << "-th short key is: ";
        // util::Display(temp_key);
        for (int j=0; j<dec_level; j++){
            VecData temp_key_scale(short_n*mod_size, 0ULL);
            uint64_t scale = (uint64_t) 1 << (dec_base*j);
            std::cout << "-----------------------------------------" << std::endl;
            std::cout << "dec base: " << (1<<dec_base) << " " << j << "-th scale: " <<  scale  << std::endl;
            util::mul_coeff_mod(temp_key, short_n, mod_size, scale, modulus, vec_mod, temp_key_scale);
            std::cout << i << "-th little lwe with " << j << "-th dec levle: ";
            util::Display(temp_key_scale);
            MatrixData temp_rlwe(2, VecData(short_n));
            util::Encrypt_Manual(temp_key_scale, shortkey, short_n, mod_size, modulus, vec_mod, temp_rlwe);
            VecData temp_decrypt(short_n);
            util::Decrypt_Manual(temp_rlwe, shortkey, short_n, mod_size, modulus, vec_mod, temp_decrypt);
            std::cout << "decrypt scale key result: ";
            util::Display(temp_decrypt);
            std::cout << "-----------------------------------------" << std::endl;
            temp_rlev[j] = temp_rlwe;
        }
        rlwe_switch_key[i] = temp_rlev;
    }

    return;
}

const void RLWE_Key_Switch_Manual(const MatrixData &long_rlwe, const VecData &short_key, const std::vector<std::vector<MatrixData>> &rlwe_switch_key, const size_t &long_n, const size_t &short_n, const size_t &mod_size, const size_t dec_level, const size_t dec_base, const Modulus &modulus, const std::vector<Modulus> &vec_mod, std::vector<MatrixData> &vec_short_rlwe)
{
    std::cout << std::endl;
    std::cout << "mod size: " << mod_size << " short n: " << short_n << std::endl;
    size_t npoly = long_n / short_n;
    for (int i=0; i<npoly; i++){
        VecData trivial_a(short_n * mod_size, 0ULL);
        VecData trivial_b(short_n * mod_size, 0ULL);
        std::cout << "// extract " << i << "-th b //" << std::endl; 
        util::extract_temp_key(long_rlwe[0],long_n, short_n, mod_size, i, trivial_b);
        MatrixData trivial_rlwe(2, VecData(short_n*mod_size));
        trivial_rlwe[1] = trivial_a;
        trivial_rlwe[0] = trivial_b;

        std::cout << "now rlwe[0]: ";
        util::Display(trivial_rlwe[0]);
        std::cout << "now rlwe[1]: ";
        util::Display(trivial_rlwe[1]);

        for (int j=0; j<(i+1); j++){
            std::vector<MatrixData> temp_rlev = rlwe_switch_key[j];
            size_t idx = i - j;
            
            VecData temp_a(short_n * mod_size, 0ULL);
            std::cout << "// under " << i << "-th b extract " << j << "-th a/ /" << std::endl; 
            util::extract_temp_key(long_rlwe[1], long_n, short_n, mod_size, idx, temp_a);
            // std::cout << "Before scale down temp a: ";
            // util::Display(temp_a);
            for(int t = 0; t<dec_level; t++){
                VecData temp_a_scale(short_n, 0ULL);
                std::cout << "// under " << i << "-th b and " << j << "-th a do " << t << "-th decompose //" << std::endl; 
                util:: divide_coeff_mod(temp_a, short_n, mod_size, dec_base, t, modulus, vec_mod, temp_a_scale);
                // std::cout << "    dec_base: " << ((uint64_t) 1<<(dec_base*t)) << " -> ";
                // util::Display(temp_a_scale);
                MatrixData temp_rlwe = temp_rlev[t];
                // VecData temp_rlwe_decrypt(short_n);
                // util::Decrypt_Manual(temp_rlwe,short_key, short_n, modulus, temp_rlwe_decrypt);
                // std::cout << "    switch key decryption: ";
                // util::Display(temp_rlwe_decrypt);
                MatrixData new_key(2, VecData(short_n*mod_size));
                util::poly_rlwe_mul(temp_rlwe, temp_a_scale, short_n, mod_size, modulus, vec_mod, new_key);
                // VecData new_key_decryption(short_n*mod_size);
                // util::Decrypt_Manual(new_key,short_key, short_n, 1, modulus, vec_mod, new_key_decryption);
                // std::cout << "    scaled down switch key decryption: ";
                // util::Display(new_key_decryption);
                // VecData trivial_rlwe_decryption(short_n*mod_size, 0ULL);
                // util::Decrypt_Manual(trivial_rlwe,short_key, short_n, 1, modulus, vec_mod, trivial_rlwe_decryption);
                // std::cout << "    before add trivial rlwe: ";
                // util::Display(trivial_rlwe_decryption);
                util::rlwe_add_inplace(trivial_rlwe, new_key, short_n, mod_size, modulus, vec_mod);
                std::cout << "now rlwe[0]: ";
                util::Display(trivial_rlwe[0]);
                std::cout << "now rlwe[1]: ";
                util::Display(trivial_rlwe[1]);
                // util::Decrypt_Manual(trivial_rlwe,short_key, short_n, 1, modulus, vec_mod, trivial_rlwe_decryption);
                // std::cout << "    after add trivial rlwe: ";
                // util::Display(trivial_rlwe_decryption);
                // std::cout << "    ShortRlwe[" << i << "] = b[" << i << "]  +  " << "SwitchKey[" << j << "," << t << "]" << "  *  " << "a[" << idx << "]/B[" << t << "]" << std::endl << std::endl;
            }
                

        }

        for (int j=i+1; j<npoly; j++){
            std::vector<MatrixData> temp_rlev = rlwe_switch_key[j];
            size_t idx = npoly + i - j;
            
            VecData temp_a(short_n, 0ULL);
            std::cout << "// under " << i << "-th b extract " << j << "-th a/ /" << std::endl; 
            util::extract_temp_key(long_rlwe[1], long_n, short_n, mod_size, idx, temp_a);
            // std::cout << "Before scale down temp a: ";
            // util::Display(temp_a);
            for(int t = 0; t<dec_level; t++){
                VecData temp_a_scale(short_n, 0ULL);
                std::cout << "// under " << i << "-th b and " << j << "-th a do " << t << "-th decompose //" << std::endl;
                util:: divide_coeff_mod(temp_a, short_n, mod_size, dec_base, t, modulus, vec_mod, temp_a_scale);
                std::cout << "before bais, scaled a: ";
                util::Display(temp_a_scale);
                // std::cout << "    dec_base: " << ((uint64_t) 1<<(dec_base*t));
                // std::cout << "    before bais, scaled a: ";
                // util::Display(temp_a_scale);
                // VecData bias(short_n * mod_size, 0ULL);
                // bias[1] = 1;
                // std::cout << "bias vector: ";
                // util::Display(bias);
                VecData temp_a_scale_bias(short_n * mod_size, 0ULL);
                // util::NWC_Manual(bias, temp_a_scale, short_n, mod_size, modulus, vec_mod, temp_a_scale_bias);
                // if(short_n == 1){
                //     for(int l=0; l<mod_size; l++){
                //         temp_a_scale_bias[l] = vec_mod[l].value() - temp_a_scale[l];
                //     }
                    
                // }
                util::bias_poly(temp_a_scale, short_n, mod_size, modulus, vec_mod, temp_a_scale_bias);
                std::cout << "after bais, scaled a: ";
                util::Display(temp_a_scale_bias);
                MatrixData temp_rlwe = temp_rlev[t];
                // VecData temp_rlwe_decrypt(short_n);
                // util::Decrypt_Manual(temp_rlwe,short_key, short_n, 1, modulus, vec_mod, temp_rlwe_decrypt);
                // std::cout << "    switch key decryption: ";
                // util::Display(temp_rlwe_decrypt);
                MatrixData new_key(2, VecData(short_n));
                util::poly_rlwe_mul(temp_rlwe, temp_a_scale_bias, short_n, mod_size, modulus, vec_mod, new_key);
                // VecData new_key_decryption(short_n);
                // util::Decrypt_Manual(new_key,short_key, short_n,1, modulus, vec_mod, new_key_decryption);
                // std::cout << "    scaled down switch key decryption: ";
                // util::Display(new_key_decryption);
                // VecData trivial_rlwe_decryption(short_n, 0ULL);
                // util::Decrypt_Manual(trivial_rlwe,short_key, short_n, 1, modulus, vec_mod, trivial_rlwe_decryption);
                // std::cout << "    before sub trivial rlwe: ";
                // util::Display(trivial_rlwe_decryption);
                util::rlwe_add_inplace(trivial_rlwe, new_key, short_n, mod_size, modulus, vec_mod);
                std::cout << "now rlwe[0]: ";
                util::Display(trivial_rlwe[0]);
                std::cout << "now rlwe[1]: ";
                util::Display(trivial_rlwe[1]);
                // util::Decrypt_Manual(trivial_rlwe,short_key, short_n, 1, modulus, vec_mod, trivial_rlwe_decryption);
                // std::cout << "    after sub trivial rlwe: ";
                // util::Display(trivial_rlwe_decryption);
                // std::cout << "    ShortRlwe[" << i << "] = b[" << i << "]  -  " << "SwitchKey[" << j << "," << t << "]" << "  *  " << "a[" << idx << "]/B[" << t << "]" << std::endl << std::endl;
            }
        }

        VecData trivial_rlwe_decryption(short_n, 0ULL);
        util::Decrypt_Manual(trivial_rlwe,short_key, short_n, mod_size, modulus, vec_mod, trivial_rlwe_decryption);
        std::cout << i << "-th final trivial rlwe: ";
        util::Display(trivial_rlwe_decryption);
        std::cout << std::endl;


    }
}

const void Extract_NWC_test()
{
    size_t long_n = 32;
    size_t short_n = 4;
    size_t npoly = long_n / short_n;
    Modulus mod_coeff(257);
    
    VecData poly1(long_n, 1ULL);
    for(int i=0; i<long_n; i++){
        poly1[i] = i;
    }
    VecData poly_result(long_n, 1ULL);
    std::cout << "Oringinal Poly is: ";
    util::Display(poly1);
    util::NWC_Manual(poly1, poly1, long_n, 1, mod_coeff, {mod_coeff}, poly_result);
    std::cout << "NWC result: ";
    util::Display(poly_result);

    MatrixData poly_extract;
    poly_extract.resize(npoly);
    for(int i=0; i<npoly; i++){
        VecData poly_temp(short_n, 0ULL);
        util::extract_temp_key(poly1, long_n, short_n, 1, i, poly_temp);
        poly_extract[i] = poly_temp;
        std::cout << i << "-th poly is: ";
        util::Display(poly_temp);
    }

    for (int i=0; i<npoly; i++){
        VecData trivial_poly(short_n, 0ULL);
        for (int j=0; j<i+1; j++){
            size_t idx = i - j;
            VecData temp_poly_1(short_n, 0ULL);
            temp_poly_1 = poly_extract[idx];
            std::cout << idx << "-th extract poly is: ";
            util::Display(temp_poly_1);
            VecData temp_poly_2(short_n, 0ULL);
            temp_poly_2 = poly_extract[j];
            std::cout << j << "-th extract poly is: ";
            util::Display(temp_poly_2);
            VecData poly_mul(short_n,0ULL);
            util::NWC_Manual(temp_poly_1, temp_poly_2, short_n, 1, mod_coeff, {mod_coeff}, poly_mul);
            std::cout << "multiplication result: ";
            util::Display(poly_mul);
            VecData copy_poly(short_n, 0ULL);
            copy_poly = trivial_poly;
            util::Add_Manual(copy_poly,poly_mul, short_n, 1, mod_coeff, {mod_coeff}, trivial_poly);
            std::cout << "add result: ";
            util::Display(trivial_poly);
        }
        for (int j=i+1; j<npoly; j++){
            size_t idx = i + npoly - j;
            VecData temp_poly_1(short_n, 0ULL);
            temp_poly_1 = poly_extract[idx];
            std::cout << idx << "-th extract poly is: ";
            util::Display(temp_poly_1);
            VecData temp_poly_2(short_n, 0ULL);
            temp_poly_2 = poly_extract[j];
            std::cout << j << "-th extract poly is: ";
            util::Display(temp_poly_2);
            VecData poly_mul(short_n,0ULL);
            util::NWC_Manual(temp_poly_1, temp_poly_2, short_n, 1, mod_coeff, {mod_coeff}, poly_mul);
            std::cout << "multiplication result: ";
            util::Display(poly_mul);
            VecData bias(short_n, 0ULL);
            bias[1] = 1;
            VecData bia_poly_mul(short_n, 0ULL);
            util::NWC_Manual(poly_mul, bias, short_n, 1, mod_coeff, {mod_coeff}, bia_poly_mul);
            std::cout << "biased multiplication result: ";
            util::Display(bia_poly_mul);
            VecData copy_poly(short_n, 0ULL);
            copy_poly = trivial_poly;
            // util::Sub_Manual(copy_poly,poly_shift, short_n, mod_coeff, trivial_poly);
            util::Add_Manual(copy_poly,bia_poly_mul, short_n, 1, mod_coeff, {mod_coeff}, trivial_poly);
            std::cout << "sub result: ";
            util::Display(trivial_poly);
        }
        std::cout << "Final result: ";
        util::Display(trivial_poly);
    }


    return;
}

const void RLWEKeySwitchVerify()
{
    // Encryption Parameter
    util::print_example_banner("Parameter Setting");
    size_t long_n = 4;
    size_t short_n = 2;
    std::cout << "N: " << long_n << std::endl;
    std::cout << "n: " << short_n << std::endl;
    size_t step = long_n / short_n;
    size_t npoly = long_n / short_n;
    std::vector<Modulus> vec_mod{ 5, 7, 13 };
    seal::Modulus mod_coeff(5*7*13); // 35 = 7 * 5
    size_t mod_size = vec_mod.size();
    std::cout << "mod_size: " << mod_size << std::endl;
    size_t dec_base = 3;
    size_t dec_level = 3;
    for(int i=0; i<mod_size; i++){
        size_t count_mod = std::ceil(std::log2(vec_mod[i].value()));
        std::cout << i << "-th modulo bit size: " << count_mod << std::endl;
        if(dec_base*dec_level<count_mod){
            std::cout<<"Decompose parameter error" << std::endl;
            return;
        }
    }
    

    // Encryption Element
    util::print_example_banner("Key Setting");
    seal::VecData rlwe_long_key(long_n*mod_size, 0ULL);  // Long key
    for(int i=0; i<long_n; i++){
        uint64_t rd = seal::random_uint64() % 3;
        // uint64_t rd = 1; // we fix long key
        if(rd == 2){
            rd = mod_coeff.value() - 1;
        }
        for(int j=0; j<mod_size; j++){
            rlwe_long_key[i + j * long_n] = rd % vec_mod[j].value();
        }
    }
    // for(int i=0; i<long_n; i++){
    //     uint64_t rd = seal::random_uint64() % 3;
    //     if(rd == 2){
    //         rd = mod_coeff.value() - 1;
    //     }
    //     rlwe_long_key[i] = rd;
    // }
    std::cout << "rlwe long key: ";
    util::Display(rlwe_long_key);

    seal::VecData rlwe_short_key(short_n*mod_size, 0ULL); // Short Key
    for(int i=0; i<short_n; i++){
        uint64_t rd = seal::random_uint64() % 3;
        // uint64_t rd = 1; // we fix short key
        if(rd == 2){
            rd = mod_coeff.value() - 1;
        }
        for(int j=0; j<mod_size; j++){
            rlwe_short_key[i + j * short_n] = rd % vec_mod[j].value();
        }
    }
    std::cout << "rlwe short key: ";
    util::Display(rlwe_short_key);

    util::print_example_banner("Plaintext Setting");
    seal::VecData long_ptxt(long_n * mod_size, 0ULL); // Long Plaintext
    for(int i=0; i<long_n; i++){
        uint64_t rd = random_uint64() % mod_coeff.value();
        // uint64_t rd = 1; // we fix plaintext
        std::cout << i << "-th ptxt: " << rd << std::endl; 
        for(int j=0; j<mod_size; j++){
            long_ptxt[i+j*long_n] = util::multiply_uint_mod(rd, 1, vec_mod[j]);
        }
    }
    // for(int i=0; i<long_n; i++){
    //     // long_ptxt[i] = 1;
    //     uint64_t rd = random_uint64();
    //     long_ptxt[i] = util::multiply_uint_mod(rd, 1, mod_coeff); 
    // }
    std::cout << "rlwe long ptxt: ";
    util::Display(long_ptxt);

    // seal::VecData short_ptxt(short_n, 0ULL); // Short Plaintext
    // for(int i=0; i<short_n; i++){
    //     short_ptxt[i] = 1;
    // }
    // std::cout << "rlwe short ptxt: ";
    // util::Display(short_ptxt);

    // Encrypt
    util::print_example_banner("Encryption Test");
    MatrixData long_ctxt(2, VecData(long_n * mod_size));
    util::Encrypt_Manual(long_ptxt, rlwe_long_key,long_n, mod_size, mod_coeff, vec_mod, long_ctxt);
    // std::cout << "rlwe long b: ";
    // util::Display(long_ctxt[0]);

    util::print_example_banner("Decryption Test");
    // Decrypt
    VecData decrypt_test(long_n * mod_size, 0ULL);
    util::Decrypt_Manual(long_ctxt, rlwe_long_key, long_n, mod_size, mod_coeff, vec_mod, decrypt_test);
    std::cout << "decrypt result: ";
    util::Display(decrypt_test);

    // Generate Key Switch key
    util::print_example_banner("Generating Key switch key");
    std::vector<std::vector<MatrixData>> rlwe_switch_key;
    rlwe_switch_key.resize(npoly);
    util::Generate_RLWE_KSkey_Manual(rlwe_long_key,rlwe_short_key, long_n, short_n, mod_size, dec_base, dec_level, mod_coeff, vec_mod, rlwe_switch_key);
    // Decryption Debug
    for (int i=0; i<npoly; i++){
        for (int j=0; j<dec_level; j++){
            MatrixData switch_key = rlwe_switch_key[i][j];
            VecData switch_key_decrypt(short_n, 0ULL);
            util::Decrypt_Manual(switch_key, rlwe_short_key, short_n, mod_size, mod_coeff, vec_mod, switch_key_decrypt);
            // std::cout << "[" << i << "," << j << "] switch key is: ";
            // util::Display(switch_key_decrypt);
        }
    }

    // Do RLWE Keyswitch
    util::print_example_banner("Doing Key switch");
    std::vector<MatrixData> vec_lwe;
    vec_lwe.resize(npoly);
    RLWE_Key_Switch_Manual(long_ctxt, rlwe_short_key, rlwe_switch_key, long_n, short_n, mod_size, dec_level, dec_base, mod_coeff, vec_mod, vec_lwe);

    util::print_example_banner("Show answer!");
    std::cout << "rlwe long ptxt: ";
    util::Display(long_ptxt);

    return;

}

const void PolyEvalMotzkin(const uint64_t &x, const std::vector<uint64_t> &coefficients, uint64_t &result) {

    uint64_t n = 6; // polynomial degree
    if(n < 4) return; // Since n >= 3

    // Step 1: Compute t and z
    // firstly we assume that a0=1(coefficient of y^n)
    seal::Modulus mod_plain = 65537;
    uint64_t inv_n = 0;
    seal::util::try_invert_uint_mod(n, mod_plain, inv_n);
    uint64_t t = 0;
    t = seal::util::sub_uint_mod(coefficients[n - 2], 1, mod_plain);
    t = seal::util::multiply_uint_mod(t, inv_n, mod_plain);
    uint64_t z = seal::util::add_uint_mod(x, t, mod_plain);

    // Initialize variables to store intermediate values of polynomial evaluation
    uint64_t P = 0;
    std::vector<uint64_t> reduced_coefficients(coefficients.begin(), coefficients.end());

    // Step 2: Evaluate the reduced polynomials iteratively
    while(n > 2) { // Until we reduce the polynomial to second degree
        uint64_t m = n / 2;

        // If n is even, we proceed with the described algorithm
        if(n % 2 == 0) {
            // Try to solve the (m-1)st degree reduction equation
            double alpha;
            bool has_real_root = false;

            // Here, you may need to implement the code to find the real root of the reduction equation
            // This would generally involve finding roots of the polynomial formed by the odd-indexed coefficients
            // If the real root is found, set has_real_root to true and assign the root to alpha

            if(has_real_root) {
                // Apply squaring rule
                for(uint64_t i = 0; i < n; i+=2) {
                    reduced_coefficients[i / 2] = reduced_coefficients[i] + alpha * (i > 0 ? reduced_coefficients[i - 2] : 0);
                }
            } else {
                // Apply Horner's rule twice to reduce the degree
                for(uint64_t i = 0; i < n - 1; i++) {
                    reduced_coefficients[i] = reduced_coefficients[i] * z + reduced_coefficients[i + 1];
                }
            }
            n = m; // Reduce the degree
        } else {
            // If n is odd, we need a different approach like applying Horner’s method once
            for(uint64_t i = 0; i < n; i++) {
                reduced_coefficients[i] = reduced_coefficients[i] * z + reduced_coefficients[i + 1];
            }
            n--; // Reduce the degree
        }
    }

    // Step 3: Compute the final value of P
    P = (pow(z, 2) + z + reduced_coefficients[0]) * (pow(z, 2) - reduced_coefficients[2]) + reduced_coefficients[3];
    result = (uint64_t) P; // Convert the result to uint64_t

}



}


}
