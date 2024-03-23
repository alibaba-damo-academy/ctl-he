// #include "crypto_test.h"
#include "crypto_test.h"
#include "cryptor.h"
using std::cout;
using std::endl;

void BSGSTest(seal::Cryptor cryptor)
{
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    size_t degree = 16; // Now Tree Max Degree is log2Degree + 4 < ?

    // generate random input.
    seal::VecData x(seal::RLWEParams::poly_modulus_degree, 0ULL);
    size_t row_size = seal::RLWEParams::poly_modulus_degree / 2;
    for (int i = 0; i < row_size; i++)
    {
        x.data()[i] = 1;
        x.data()[i + row_size] = 1;
    }
    seal::RLWECipher ctx;
    cryptor.encrypt(x, ctx);

    // generate random polynomial
    // cout << "Poly = ";
    seal::VecData coeffs(degree+1, 0ULL);
    for (size_t i = 0; i < degree + 1; i++) {
        // coeffs[i] = (double)rand() / 10;
        // coeffs[i] = rand() % 32 + 1;
        coeffs[i] = 2;
        // cout << coeffs[i] << ", "; 
    }
    // cout << endl;

    // compute expected result
    double expected_result = coeffs[degree];
    for (int i = degree - 1; i >= 0; i--) {      
        expected_result *= x[0]; 
        expected_result += coeffs[i]; 
    }

    // // compute actual result in tree method
    // std::cout << "Tree Method" << std::endl;
    seal::RLWECipher res;
    seal::VecData result;
    // time_start = chrono::high_resolution_clock::now();
    // cryptor.PolyEvalTree(coeffs, ctx, res);
    // time_end = chrono::high_resolution_clock::now();
    // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    // std::cout << "Done [" << time_diff.count() << " microseconds]" << std::endl;
    // cryptor.decrypt(res, result);
    // // print expected result and actual result
    // std::cout << "Actual : " << result[0] << ", Expected : " << expected_result << ", diff : " << abs(result[0] - expected_result) << std::endl;


    // // compute actual result in Horner method
    // std::cout << "Horner Method" << std::endl;
    // time_start = chrono::high_resolution_clock::now();
    // cryptor.PolyEvalHorner(coeffs, ctx, res);
    // time_end = chrono::high_resolution_clock::now();
    // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    // std::cout << "Done [" << time_diff.count() << " microseconds]" << std::endl;
    // cryptor.decrypt(res, result);

    // // print expected result and actual result
    // std::cout << "Actual : " << result[0] << ", Expected : " << expected_result << ", diff : " << abs(result[0] - expected_result) << std::endl;

    // cryptor.Test_Square_Opt(ctx, ctx);

    // compute actual result in BSGS method
    std::cout << "BSGS Method" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    cryptor.PolyEvalBSGS(coeffs, ctx, res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Done [" << time_diff.count() << " microseconds]" << std::endl;
    cryptor.decrypt(res, result);
    
    // print expected result and actual result
    std::cout << "Actual : " << result[0] << ", Expected : " << expected_result << ", diff : " << abs(result[0] - expected_result) << std::endl;


    return;
}

void DoubleLTest(seal::Cryptor cryptor)
{
    // vec construct in way 1
    seal::VecData vec_s2c_test(seal::RLWEParams::poly_modulus_degree, 0ULL);
    for (int i = 0; i < seal::RLWEParams::poly_modulus_degree; i++)
    {
        vec_s2c_test.data()[i] = i;
        // vec_s2c_test.data()[i + RLWEParams::poly_modulus_degree/2] = 2;
    }
    // vec_s2c_test.data()[2] = 1;

    // vec construct in way 2
    // int repeat_times = 8192;
    // int repeat_length = RLWEParams::poly_modulus_degree / repeat_times;
    // // Assuming vec_s2c_test is some kind of vector-like data structure that supports size() and data() methods.
    // // Ensure the size is 32 * 1024
    // for (int val = 0; val < repeat_length; val++) {
    //     for (int i = 0; i < repeat_times; i++) {
    //         vec_s2c_test.data()[val * repeat_times + i] = val+1;
    //     }
    // }
    
    // DEBUG: cout test vector
    // std::cout << "test vector is: " << std::endl;
    // for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+1024) {
    //     std::cout << vec_s2c_test[i] << " ";
    // }
    // std::cout << std::endl;
    // std::cout << "test vector is: " << std::endl;
    // for (size_t i = 0; i < 16; i=i+1) {
    //     std::cout << vec_s2c_test[i] << " ";
    // }
    // std::cout << std::endl;

    // test encode and decode matrix
    seal::Plaintext ptxt_s2c_test;
    cryptor.encode_manual(vec_s2c_test, ptxt_s2c_test);
    cryptor.decode_manual(ptxt_s2c_test,vec_s2c_test);

    seal::RLWECipher ctxt_s2c_test, ctxt_s2c_result;
    seal::VecData vec_s2c_result(seal::RLWEParams::poly_modulus_degree, 0ULL);
    cryptor.encrypt(vec_s2c_test, ctxt_s2c_test);

    // Test Double LT algorithm
    seal::MatrixData matrix_test;
    matrix_test.resize(seal::RLWEParams::poly_modulus_degree, seal::VecData(seal::RLWEParams::poly_modulus_degree));
    for (int i = 0; i < seal::RLWEParams::poly_modulus_degree/2; i++){
        for (int j = 0; j < seal::RLWEParams::poly_modulus_degree/2; j++){
            matrix_test[i][j] = 1;
            matrix_test[i][j+seal::RLWEParams::poly_modulus_degree/2] = 1;
            matrix_test[i+seal::RLWEParams::poly_modulus_degree/2][j] = 1;
            matrix_test[i+seal::RLWEParams::poly_modulus_degree/2][j+seal::RLWEParams::poly_modulus_degree/2] = 1;
        }
    }
    // // DEBUG:: cout Matrix
    // std::cout << "test matrix is: " << std::endl;
    // for (size_t i = 0; i < RLWEParams::poly_modulus_degree; i=i+1024) {
    //     for (size_t j = 0; j < RLWEParams::poly_modulus_degree; j=j+1024) {
    //         std::cout << matrix_test[i][j] << " ";
    //     }
    //         std::cout << std::endl;
    // }

    cryptor.TestDoubleLT(ctxt_s2c_test, matrix_test);
    cryptor.decrypt(ctxt_s2c_test, vec_s2c_result);
    
    std::cout << "result vector is: " << std::endl;
    for (size_t i = 0; i < seal::RLWEParams::poly_modulus_degree; i=i+1024) {
        std::cout << vec_s2c_result[i] << " ";
    }
    std::cout << std::endl;

}

void HomoXORTest(seal::Cryptor cryptor)
{   
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;
    uint64_t message_debug = 0;
    
    // 1. Initialize LWE ciphertext

    // (1) set up LWE Q
    uint64_t Q = seal::RLWEParamsLittle::plain_modulus; // WARNING: max is 26 bit (16 bit for message) now
    std::cout << "LWE Modulus Q: " << Q << " in binary: ";
    seal::util::printInBinary(Q);
    // (2) set up message (maximum here)
    uint64_t Delta = std::round((double) Q / (double) 512);
    std::cout << "Delta: " << Delta << " in binary: ";
    seal::util::printInBinary(Delta);
    // (3) set up message
    uint64_t message1 = 100; // located in [0,255]
    std::cout << "message1: " << message1 << " in binary: ";
    seal::util::printInBinary(message1);
    uint64_t message2 = 0; // located in [0,255]
    std::cout << "message2: " << message2 << " in binary: ";
    seal::util::printInBinary(message2);
    uint64_t plaintext1 = message1 * Delta<Q?message1 * Delta:Q;
    std::cout << "plaintext1: " << plaintext1 << " in binary: ";
    seal::util::printInBinary(plaintext1);
    uint64_t plaintext2 = (message2 * Delta)<Q?(message2 * Delta):Q;
    std::cout << "plaintext2: " << plaintext2 << " in binary: ";
    seal::util::printInBinary(plaintext2);
    std::vector<seal::LWECipher> c1_vec_lwe;
    std::vector<seal::LWECipher> c2_vec_lwe;
    // encrypt message
    cryptor.construct_lwe_XOR(plaintext1, Q, c1_vec_lwe);
    cryptor.construct_lwe_XOR(plaintext2, Q, c2_vec_lwe);
    
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
    
    // six PBS implementation
    /*
    // 3. we insert zero to C1 to produce 2 digit encrypted ciphertext
    // c1 high four bit 0_X7_0_X5_0_X3_0_X1
    std::vector<seal::LWECipher> c1_h4_vec_lwe;
    cryptor.Batch_ExtractHigh4bit(Q, c1_vec_lwe, c1_h4_vec_lwe);
    // c1 low four bit 0_X6_0_X4_0_X2_0_X0
    std::vector<seal::LWECipher> c1_l4_vec_lwe;
    cryptor.Batch_ExtractLow4bit(Q, c1_vec_lwe, c1_l4_vec_lwe);

    std::vector<seal::LWECipher> c2_h4_vec_lwe;
    cryptor.Batch_ExtractHigh4bit(Q, c2_vec_lwe, c2_h4_vec_lwe);
    std::vector<seal::LWECipher> c2_l4_vec_lwe;
    cryptor.Batch_ExtractLow4bit(Q, c2_vec_lwe, c2_l4_vec_lwe);
    
    // 4. add lwe
    std::vector<seal::LWECipher> add_h4_vec_lwe;
    cryptor.lwe_add(c1_h4_vec_lwe, c2_h4_vec_lwe, Q, add_h4_vec_lwe);
    cryptor.lwe_manual_decrypt(add_h4_vec_lwe[index], message_debug, true, Q, 65537);
    std::vector<seal::LWECipher> add_l4_vec_lwe;
    cryptor.lwe_add(c1_l4_vec_lwe, c2_l4_vec_lwe, Q, add_l4_vec_lwe);
    cryptor.lwe_manual_decrypt(add_l4_vec_lwe[index], message_debug, true, Q, 65537);

    // 5. 
    // XOR( LOW4(a) + LOW4(b) )
    // XOR( HIGH4(a) + HIGH4(b) )
    std::vector<seal::LWECipher> xor_h4_vec_lwe;
    cryptor.Batch_HighXOR(Q, add_h4_vec_lwe, xor_h4_vec_lwe);
    std::vector<seal::LWECipher> xor_l4_vec_lwe;
    cryptor.Batch_LowXOR(Q, add_l4_vec_lwe, xor_l4_vec_lwe);

    // 6. XOR( LOW4(a) + LOW4(b) ) + XOR( HIGH4(a) + HIGH4(b) )
    std::vector<seal::LWECipher> final_vec_lwe;
    cryptor.lwe_add(xor_h4_vec_lwe, xor_l4_vec_lwe, Q, final_vec_lwe);
    cryptor.lwe_manual_decrypt(final_vec_lwe[index], message_debug, true, Q, 65537);

    return;
    */
    
    // four PBS implementation
    
    // 1. Extract high and low 4 bit
    
    // c1 low four bit 0_X6_0_X4_0_X2_0_X0
    std::vector<seal::LWECipher> c1_l4_vec_lwe;
    cryptor.Batch_Customize(Q, c1_vec_lwe, c1_l4_vec_lwe, dramOp_L4);
    // cryptor.Batch_ExtractLow4bit(Q, c1_vec_lwe, c1_l4_vec_lwe);
    // c1 high four bit X7_0_X5_0_X3_0_X1_0 using lwe substract
    std::vector<seal::LWECipher> c1_h4_vec_lwe;
    cryptor.lwe_sub(c1_vec_lwe, c1_l4_vec_lwe, Q, c1_h4_vec_lwe);
    // DEBUG
    cryptor.lwe_manual_decrypt(c1_h4_vec_lwe[index], message_debug, true, Q, 65537);
    
    // c2 low four bit 0_X6_0_X4_0_X2_0_X0
    std::vector<seal::LWECipher> c2_l4_vec_lwe;
    cryptor.Batch_Customize(Q, c2_vec_lwe, c2_l4_vec_lwe, dramOp_L4);
    // cryptor.Batch_ExtractLow4bit(Q, c2_vec_lwe, c2_l4_vec_lwe);
    // c1 high four bit X7_0_X5_0_X3_0_X1_0 using lwe substract
    std::vector<seal::LWECipher> c2_h4_vec_lwe;
    cryptor.lwe_sub(c2_vec_lwe, c2_l4_vec_lwe, Q, c2_h4_vec_lwe);
    // DEBUG
    cryptor.lwe_manual_decrypt(c2_h4_vec_lwe[index], message_debug, true, Q, 65537);
    
    // 2. XOR( LOW(C1) + LOW(C2) )
    std::vector<seal::LWECipher> add_l4_vec_lwe;
    cryptor.lwe_add(c1_l4_vec_lwe, c2_l4_vec_lwe, Q, add_l4_vec_lwe);
    cryptor.lwe_manual_decrypt(add_l4_vec_lwe[index], message_debug, true, Q, 65537);
    std::vector<seal::LWECipher> xor_l4_vec_lwe;
    cryptor.Batch_Customize(Q, add_l4_vec_lwe, xor_l4_vec_lwe, dramOp_LXOR);
    // cryptor.Batch_LowXOR(Q, add_l4_vec_lwe, xor_l4_vec_lwe);
    
    // 3. XOR( HIGH(C1) + HIGH(C2) )
    std::vector<seal::LWECipher> add_h4_vec_lwe;
    cryptor.lwe_add(c1_h4_vec_lwe, c2_h4_vec_lwe, Q, add_h4_vec_lwe);
    cryptor.lwe_manual_decrypt(add_h4_vec_lwe[index], message_debug, true, Q, 65537);
    std::vector<seal::LWECipher> xor_h4_vec_lwe;
    cryptor.Batch_Customize(Q, add_h4_vec_lwe, xor_h4_vec_lwe, dramOp_HXOR9bit);
    // cryptor.Batch_HighXOR9bit(Q, add_h4_vec_lwe, xor_h4_vec_lwe);

    // 4. XOR( LOW4(a) + LOW4(b) ) + XOR( HIGH4(a) + HIGH4(b) )
    std::vector<seal::LWECipher> final_vec_lwe;
    cryptor.lwe_add(xor_h4_vec_lwe, xor_l4_vec_lwe, Q, final_vec_lwe);
    // cryptor.lwe_add_beta(xor_h4_vec_lwe, Q, 80, final_vec_lwe); // forbide round zero problem
    cryptor.lwe_manual_decrypt(final_vec_lwe[index], message_debug, true, Q, 65537);

    std::cout << "Golden: " << (message1 ^ message2) * Delta << std::endl;
    return;
}

void HomoFloorTest(seal::Cryptor cryptor)
{

    // 0. set up parameter
    uint64_t Q = 1<<(18-1); // total LWE Modulus WARNING: fix 17now!
    // uint64_t Q = 16777472;
    std::cout << "Q: " << Q << " in binary: ";
    seal::util::printInBinary(Q);
    uint64_t q = seal::RLWEParams::plain_modulus; // PBS Modulus
    std::cout << "q: " << q << " in binary: ";
    seal::util::printInBinary(q);
    uint64_t N = seal::RLWEParamsLittle::poly_modulus_degree; // total LWE degree
    std::cout << "N: " << N << " in binary: ";
    seal::util::printInBinary(N);
    uint64_t alpha = 1 << (10-1);
    std::cout << "alpha: " << alpha << " in binary: ";
    seal::util::printInBinary(alpha);
    uint64_t message_debug = 0; // for debug
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    // std::cout << "index: " << index <<  std::endl;

    // 1. Initialize LWE ciphertext
    uint64_t bit = q/(alpha) -  1; // limitation: bit should less than SEAL::RLWEParamsLittle:plain_modulus here
    std::cout << "bit: " << bit << " in binary: ";
    seal::util::printInBinary(bit);
    // uint64_t message = bit * alpha; // message here is scale up from bit to Q
    uint64_t message = 65025;
    std::cout << "message: " << message << " in binary: ";
    seal::util::printInBinary(message);
    std::vector<seal::LWECipher> initial_vec_lwe;
    cryptor.construct_lwe_sign(message, Q, initial_vec_lwe); // LWE in Q encrypting (bit / 2) 
    // TODO: why bit/2?(because q is not power of 2), our strategy is modify message

    // 2. d = d + b
    uint64_t beta = 70; // 70 is from experiment
    std::vector<seal::LWECipher> lwe_beta;
    cryptor.lwe_add_beta(initial_vec_lwe, Q, beta, lwe_beta);
    cryptor.lwe_manual_decrypt(lwe_beta[index], message_debug, true, Q, 65537);

    // 3. Line3: (a,b) = (c,d) mod q 
    // WARNING: we change to mod 65536 but not mod q
    std::vector<seal::LWECipher> lwe_in_q;
    cryptor.lwe_mod_q(lwe_beta, lwe_in_q);
    cryptor.lwe_manual_decrypt(lwe_beta[index], message_debug, true, Q, 65537);
    cryptor.lwe_manual_decrypt(lwe_in_q[index], message_debug, true, 65537, 65537);
    
    // 4. Line 4: Boot[f0(x)](a,b) mod q
    std::vector<seal::LWECipher> lwe_f0;
    lwe_f0.resize(seal::RLWEParams::poly_modulus_degree);
    cryptor.Batch_f0(Q, lwe_in_q, lwe_f0);
    cryptor.lwe_manual_decrypt(lwe_f0[index], message_debug, true, Q, 65537);

    // 5. Line 4: (c,d) = (c,d) - Boot[f0(x)](a,b) mod Q
    std::vector<seal::LWECipher> lwe_step5;
    lwe_step5.resize(seal::RLWEParams::poly_modulus_degree);
    cryptor.lwe_sub(lwe_beta, lwe_f0, Q, lwe_step5);
    cryptor.lwe_manual_decrypt(lwe_step5[index], message_debug, true, Q, 65537);

    // 6. Line 5: d = d + beta - q/4
    uint64_t beta_q_4 = seal::util::sub_uint_mod(70, q/4, Q); // beta - q/4; TODO: should we use 65536?
    std::cout << "beta_q_4: " << beta_q_4 << std::endl;
    std::vector<seal::LWECipher> lwe_step_six;
    lwe_step_six.resize(seal::RLWEParams::poly_modulus_degree);
    cryptor.lwe_add_beta(lwe_step5, Q, beta_q_4, lwe_step_six);
    cryptor.lwe_manual_decrypt(lwe_step_six[index], message_debug, true, Q, 65537);

    // 7. Line 6: (a,b) = (c,d) mod q
    // WARNING: we change to mod 65536 but not mod q
    cryptor.lwe_mod_q(lwe_step_six, lwe_in_q);
    cryptor.lwe_manual_decrypt(lwe_in_q[index], message_debug, true, 65537, 65537);

    // 8. Line 7: Boot[f1(x)](a,b)
    std::vector<seal::LWECipher> lwe_f1;
    lwe_f1.resize(seal::RLWEParams::poly_modulus_degree);
    cryptor.Batch_f1(Q, lwe_in_q, lwe_f1);
    cryptor.lwe_manual_decrypt(lwe_f1[index], message_debug, true, Q, 65537);

    // 9. Line 7: (c,d) = (c,d) - Boot[f1(x)](a,b) mod Q
    std::vector<seal::LWECipher> lwe_step9;
    lwe_step9.resize(seal::RLWEParams::poly_modulus_degree);
    cryptor.lwe_sub(lwe_step_six, lwe_f1, Q, lwe_step9);
    cryptor.lwe_manual_decrypt(lwe_step9[index], message_debug, true, Q, 65537);


    // // 2. Do BatchPBS for NAND function
    // for(int i=0; i<10; i++){
    //     std::vector<seal::LWECipher> vec_lwe_1st;
    //     vec_lwe_1st.resize(seal::RLWEParams::poly_modulus_degree);
    //     cryptor.BatchPBS(initial_vec_lwe, vec_lwe_1st);
    //     std::cout << "Golden NAND: " << (bit==1?0:1) << std::endl;
    // }

    return;
    
}

void HomoSignTest(seal::Cryptor cryptor)
{
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;
    uint64_t message_debug = 0;
    
    // 1. Initialize LWE ciphertext
    // (1) set up LWE Q
    uint64_t Q = (1<<17); // we can clean 16(log q) bit each time cause q = 65537
    // uint64_t Q = (1<<26); // WARNING: max is 26 bit (16 bit for message) now
    std::cout << "Q: " << Q << " in binary: ";
    seal::util::printInBinary(Q);
    // (2) set up PBS Q'
    uint64_t q = seal::RLWEParamsLittle::plain_modulus;
    std::cout << "q: " << q << " in binary: ";
    seal::util::printInBinary(q);
    // (3) set up alpha for noise
    uint64_t alpha = 10; // alpha - 1 bit for noise
    uint64_t bias = (1<<alpha) - 1;
    std::cout << "bias: " << bias << " in binary: ";
    seal::util::printInBinary(bias);
    // (4) set up message (maximum here)
    uint64_t message = std::round((double)(Q-1-bias) / (double) Q * (double) q); // max message we can encrypt
    std::cout << "message: " << message << " in binary: ";
    seal::util::printInBinary(message);
    uint64_t step = round(Q/q);
    std::vector<seal::LWECipher> initial_vec_lwe;
    // encrypt message
    cryptor.construct_lwe_sign(message, Q, initial_vec_lwe); // LWE in Q encrypting (bit / 2) 
    // TODO: why bit/2?(because q is not power of 2), our strategy is modify message

    // Run HomoFloor to clean log(q) significant bits
    size_t times = 0;
    while (Q > q){
        // print title
        std::string title = std::to_string(times) + "-th HomoFloor Start!";
        seal::util::print_example_banner(title);

        // step 1: run HomoFloor
        cryptor.HomoFloor(Q, initial_vec_lwe);
        // step2: scale down LWE
        cryptor.lwe_scale_down((q-1), (1<<alpha), initial_vec_lwe);
        // step3: scale down Q
        Q = std::round( (double) Q * ( (double) (1<<alpha) / (double) (q-1) )); 
        // WARNING:scale down to alpha/q operation creates larege noise, so we scale to alpha/(q-1)
        
        cryptor.lwe_manual_decrypt(initial_vec_lwe[index], message_debug, true, Q, 65537);

        times++;
    }
    // Q < q now

    // d = d + beta
    uint64_t beta = 70; // 70 is from experiment
    std::vector<seal::LWECipher> lwe_beta;
    cryptor.lwe_add_beta(initial_vec_lwe, Q, beta, lwe_beta);
    cryptor.lwe_manual_decrypt(lwe_beta[index], message_debug, true, Q, 65537);

    // (a,b) = (Q/q) * (c,d)
    cryptor.lwe_scale_down(Q, (q-1), lwe_beta); // modify to q-1
    cryptor.lwe_manual_decrypt(lwe_beta[index], message_debug, true, q, 65537);

    // (c,d) = Boot[f0(a,b)] (mod Q)
    seal::Modulus mod_RLWE = cryptor.get_first_modulus();
    std::vector<seal::LWECipher> vec_lwe_final;
    cryptor.Batch_sign(mod_RLWE.value(), lwe_beta, vec_lwe_final);
    cryptor.lwe_manual_decrypt(vec_lwe_final[index], message_debug, true, mod_RLWE.value(), 65537);
    
    // (c,d) = -(c,d)
    // cryptor.lwe_neg(q, vec_lwe_final);
    // cryptor.lwe_manual_decrypt(vec_lwe_final[index], message_debug, true, q, 65537);

    return;
}

void HomoGFMulTest(seal::Cryptor cryptor)
{   
    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;
    uint64_t message_debug = 0;

    // 1. Initialize LWE ciphertext

    // (1) set up LWE Q
    uint64_t Q = seal::RLWEParamsLittle::plain_modulus; // WARNING: max is 26 bit (16 bit for message) now
    std::cout << "LWE Modulus Q: " << Q << " in binary: ";
    seal::util::printInBinary(Q);
    // (2) set up message (maximum here)
    uint64_t Delta = std::round((double) Q / (double) 512);
    std::cout << "Delta: " << Delta << " in binary: ";
    seal::util::printInBinary(Delta);
    // (3) set up message
    uint64_t message1 = 100; // located in [0,255]
    std::cout << "message1: " << message1 << " in binary: ";
    seal::util::printInBinary(message1);
    uint64_t message2 = 100; // located in [0,255]
    std::cout << "message2: " << message2 << " in binary: ";
    seal::util::printInBinary(message2);
    uint64_t plaintext1 = message1 * Delta<Q?message1 * Delta:Q;
    std::cout << "plaintext1: " << plaintext1 << " in binary: ";
    seal::util::printInBinary(plaintext1);
    std::vector<seal::LWECipher> c1_vec_lwe;
    // encrypt message
    cryptor.construct_lwe_XOR(plaintext1, Q, c1_vec_lwe);

    // function of multipliaction in GF(256)
    auto dram_mult_0E_GF256 = [](int x, int t) -> int {
        const uint8_t kIrreduciblePolynomial = 0x1B; // For AES, x^8 + x^4 + x^3 + x + 1.
        size_t bias = 7;
        uint8_t down_x =  std::round ( (double) x / (double) 128); // static_cast<uint8_t>(x);  // Ensure x is treated as an 8-bit number.
        uint8_t p = 0;
        uint8_t b = 0X0E;
        uint8_t carry = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) {
                p ^= down_x; // If the rightmost bit of b is set, XOR the product p by down_xx.
            }
            carry = down_x & 0x80; // Check if leftmost bit of down_x is set (carry out of multiplication).
            down_x <<= 1; // Multiply down_x by down_x (shift left by 1).
            if (carry) {
                down_x ^= kIrreduciblePolynomial; // If carry is set, reduce modulo irreducible polynomial.
            }
            b >>= 1; // Divide b by down_x (shift right by 1).
        }
        return p << bias;
    };
    seal::util::DRaMOp dramOp_mult_0E_GF256(dram_mult_0E_GF256, "Mult_0E_GF256");

    // c1 low four bit 0_X6_0_X4_0_X2_0_X0
    std::vector<seal::LWECipher> c1_l4_vec_lwe;
    cryptor.Batch_Customize(Q, c1_vec_lwe, c1_l4_vec_lwe, dramOp_mult_0E_GF256);
    // DEBUG
    cryptor.lwe_manual_decrypt(c1_l4_vec_lwe[index], message_debug, true, Q, 65537);
    std::cout << "Golden: " << (dram_mult_0E_GF256(plaintext1, 65537)) << std::endl;

    return;
}

void HomoAESTest(seal::Cryptor cryptor)
{   
    // TODO: We have zero problem!!!

    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;
    uint64_t message_debug = 0;
    uint8_t down_message = 0;

    // 1. Initialize LWE ciphertext

    // (1) set up LWE Q
    uint64_t Q = seal::RLWEParamsLittle::plain_modulus; // WARNING: max is 26 bit (16 bit for message) now
    std::cout << "LWE Modulus Q: " << Q << " in binary: ";
    seal::util::printInBinary(Q);

    // (2) set up message (maximum here)
    uint64_t Delta = std::round((double) Q / (double) 512);
    std::cout << "Delta: " << Delta << " in binary: ";
    seal::util::printInBinary(Delta);

    // (3) set up message
    uint64_t message1 = 100; // located in [0,255]
    std::cout << "message1: " << message1 << " in binary: ";
    seal::util::printInBinary(message1);
    uint64_t plaintext1 = message1 * Delta<Q?message1 * Delta:Q;
    std::cout << "plaintext1: " << plaintext1 << " in binary: ";
    seal::util::printInBinary(plaintext1);
    std::vector<seal::LWECipher> state_vec_lwe;
    // encrypt message
    cryptor.construct_lwe_AES(Q, state_vec_lwe);

    // (4) set up key
    uint64_t key = 100; // located in [0,255]
    std::cout << "key: " << key << " in binary: ";
    seal::util::printInBinary(key);
    uint64_t key_ptxt = (key * Delta)<Q?(key * Delta):Q;
    std::cout << "key_ptxt: " << key_ptxt << " in binary: ";
    seal::util::printInBinary(key_ptxt);
    // encrypt key
    std::vector<seal::LWECipher> key_vec_lwe;
    cryptor.construct_lwe_XOR(key_ptxt, Q, key_vec_lwe);

    // 2. Key addition test
    seal::util::print_example_banner("Key Addition");
    cryptor.KeyAddition(Q, state_vec_lwe, key_vec_lwe);
    // DEBUG
    cryptor.lwe_manual_decrypt(state_vec_lwe[0], message_debug, true, Q, 65537);
    std::cout << "Golden: " << (1 ^ key) << " Passed: " << ((1 ^ key) == std::round((double) message_debug / (double) Delta) ) << std::endl;

    // 3. SubBytes test
    seal::util::print_example_banner("SubBytes");
    cryptor.SubBytes(Q,state_vec_lwe);
    down_message =  std::round ( (double) message_debug / (double) Delta);
    uint8_t row = (down_message >> 4) & 0x0F; 
    uint8_t col = down_message & 0x0F;
    uint8_t sbox_golden = seal::inverse_sbox[row][col];
    cryptor.lwe_manual_decrypt(state_vec_lwe[0], message_debug, true, Q, 65537);
    std::cout << "Golden: " << (uint64_t)sbox_golden << " Passed: " << (sbox_golden == std::round((double) message_debug / (double) Delta)) << std::endl;

    // 4. Shift Rows test
    // DEBUG
    // std::vector<uint64_t> shif_rows_debug(16, 0ULL);
    // seal::util::print_example_banner("Mixcolum");
    // for(int i=0; i<4; i++){
    //     for(int j=0; j<4; j++){
    //         cryptor.lwe_manual_decrypt(state_vec_lwe[4*i+j], shif_rows_debug[4*i+j], true, Q, 65537);
    //     }
    // }
    // std::cout << "Before shift rows" << std::endl;
    // for(int i=0; i<4; i++){
    //     for(int j=0; j<4; j++){
    //         std::cout << std::round ( (double) shif_rows_debug[4*i+j] / (double) Delta) << " ";
    //     }
    //     std::cout << std::endl;
    // }

    // Shift Rows
    cryptor.ShiftRows(Q,state_vec_lwe);

    // DEBUG
    // for(int i=0; i<4; i++){
    //     for(int j=0; j<4; j++){
    //         cryptor.lwe_manual_decrypt(state_vec_lwe[4*i+j], shif_rows_debug[4*i+j], true, Q, 65537);
    //     }
    // }
    // std::cout << "After shift rows" << std::endl;
    // for(int i=0; i<4; i++){
    //     for(int j=0; j<4; j++){
    //         std::cout << std::round ( (double) shif_rows_debug[4*i+j] / (double) Delta) << " ";
    //     }
    //     std::cout << std::endl;
    // }

    // 5. MixColum test
    cryptor.MixColum(Q,state_vec_lwe);

    return;
}

void HomoReLUTest(seal::Cryptor cryptor, const uint64_t &message)
{

    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;
    uint64_t message_debug = 0;
    
    // 1. Initialize LWE ciphertext
    // (1) set up LWE Q
    // uint64_t Q = (1<<17); // we can clean 16(log q) bit each time cause q = 65537
    uint64_t Q = std::pow(2,34); // (1<<25); // WARNING: max is 26 bit (16 bit for message) now
    // uint64_t Q = cryptor.get_first_modulus().value();
    // uint64_t Q = 67043329; // 26bit prime modulus
    // uint64_t Q = 1152921504583647233;
    std::cout << "Q: " << Q << " in binary: ";
    seal::util::printInBinary(Q);
    // (2) set up PBS Q'
    uint64_t q = seal::RLWEParamsLittle::plain_modulus;
    std::cout << "q: " << q << " in binary: ";
    seal::util::printInBinary(q);
    // (3) set up alpha for noise
    uint64_t alpha = 7; // alpha bit for noise
    // uint64_t alpha = std::ceil(log2(Q) - log2(q));
    uint64_t bias = std::pow(2,alpha) - 1;
    std::cout << "bias: " << bias << " in binary: ";
    seal::util::printInBinary(bias);
    // (4) set up message (maximum here)
    // uint64_t message = std::round((double)(Q-1-bias) / (double) Q * (double) q); // max message we can encrypt
    // uint64_t message = 46252;
    // uint64_t message = seal::random_uint64() % seal::RLWEParams::plain_modulus;
    // uint64_t message = 1424;
    std::cout << "message: " << message << " in binary: ";
    seal::util::printInBinary(message);
    uint64_t step = round(Q/q);
    std::vector<seal::LWECipher> initial_vec_lwe;
    // encrypt message
    cryptor.construct_lwe_sign(message, Q, initial_vec_lwe); // LWE in Q encrypting (bit / 2) 
    // TODO: why bit/2?(because q is not power of 2), our strategy is modify message


    // 2. Homo Sign Evaluation
    uint64_t final_sign;
    std::vector<seal::LWECipher> output_vec_lwe;
    cryptor.HomoSign(Q, alpha, initial_vec_lwe, output_vec_lwe, final_sign);
    std::cout << "Golden sign: " << (message < (q/2)?1:0) << std::endl;

    // 3. Pack to RLWE
    // 3. We use LWEtoRLWE to simply verify
    // seal::RLWECipher rlwe_pack;
    // seal::VecData ini_vec(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    // cryptor.encrypt(ini_vec, rlwe_pack, seal::ParamSet::RLWELittle);
    // cryptor.LWEtoRLWE(output_vec_lwe[index], rlwe_pack);
    // seal::Plaintext ptxt_debug;
    // cryptor.decrypt(rlwe_pack, ptxt_debug, seal::ParamSet::RLWELittle);
    // std::cout << "LWE to RLWE result: " << ptxt_debug.data()[0] << std::endl;
    // multiplication test
    // cryptor.pack_mul_test(rlwe_pack, message);

    // std::cout << "Golden ReLU result: " << (message < (q/2)?1:0) * message << std::endl;

    std::ofstream out_share;
    out_share.open("/DEBUG/wrong", std::ios::app);
    if( (message < (q/2)?1:0) != final_sign)
        out_share << "wrong: " << message << std::endl;
    else 
        out_share << "Right: " << message << std::endl;
    out_share.close();

    
    // cryptor.packlwes(output_vec_lwe, rlwe_pack, false);

    // 4. C2S
    // seal::RLWECipher rlwe_c2s;
    // cryptor.CtxtCoeff2Slot(rlwe_pack, rlwe_c2s);
    // seal::Plaintext vec_debug;
    // cryptor.decrypt(rlwe_pack, vec_debug, seal::ParamSet::RLWELittle);
    // std::cout << "C2S result: " << vec_debug[0] << std::endl;

    

    // 5. Multiplication for ReLU



    return;
}

void BatchPBStest(seal::Cryptor cryptor)
{
    // 1. Initialize LWE ciphertext
    uint64_t bit = 1;
    uint64_t message = bit * seal::RLWEParamsLittle::plain_modulus / 3;
    std::vector<seal::LWECipher> initial_vec_lwe;
    cryptor.construct_lwe(message, initial_vec_lwe);

    // 2. Do BatchPBS for NAND function
    for(int i=0; i<1; i++){
        std::vector<seal::LWECipher> vec_lwe_1st;
        vec_lwe_1st.resize(seal::RLWEParams::poly_modulus_degree);
        cryptor.BatchPBS(initial_vec_lwe, vec_lwe_1st);

        std::cout << "Golden NAND: " << (bit==1?0:1) << std::endl;

    }

    return;
    
}

void ReLUtest(seal::Cryptor cryptor)
{
    cryptor.beta_detection();
    return;
}

void AmortizedTest(seal::Cryptor cryptor)
{
    // Time counter
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    // Random index
    uint64_t index = seal::random_uint64() % seal::RLWEParams::poly_modulus_degree;
    std::cout << "index: " << index <<  std::endl;

    // Strandard Initialize b-As TODO: implement (p,t=q) lwe apart from(t, Q) lwe in SEAL and modswitch
    // seal::VecData vec_initial(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL); // vector of all 0 result should be t/3
    seal::Plaintext ptxt_initial(seal::RLWEParamsLittle::poly_modulus_degree);  // ptxt of all 0 result should be t/3
    for(int i=0; i<seal::RLWEParamsLittle::poly_modulus_degree; i++){
        // vec_initial[i] = 21845;
        ptxt_initial.data()[i] = 21845;
    }
    seal::RLWECipher ctxt_initial;
    // cryptor.encrypt(vec_initial, ctxt_initial, seal::ParamSet::RLWELittle);
    cryptor.encrypt(ptxt_initial, ctxt_initial, seal::ParamSet::RLWELittle);
    std::vector<seal::LWECipher> lwe_initial_vec;
    lwe_initial_vec.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        cryptor.SampleExtract(ctxt_initial, lwe_initial_vec[i], i%(seal::RLWEParamsLittle::poly_modulus_degree), false, seal::ParamSet::LWE);
    }
    std::cout << index << "-th LWE decryption: " << cryptor.decrypt(lwe_initial_vec[index], seal::ParamSet::RLWELittle) << std::endl;
    std::vector<seal::LWECipher> lwe_initial_vec_ms;
    lwe_initial_vec_ms.resize(seal::RLWEParams::poly_modulus_degree);
    #pragma omp parallel for
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        cryptor.ModSwitchLWE(lwe_initial_vec[i], 65537, 65537, lwe_initial_vec_ms[i]);
    }
    uint64_t manual_result = 0;
    cryptor.lwe_manual_decrypt(lwe_initial_vec_ms[index], manual_result, true, 65537, 65537);
    std::cout << index << "-th LWE manual decryption: " << manual_result << std::endl;
    seal::Plaintext ptxt_b; 
    cryptor.initial_b(lwe_initial_vec_ms, ptxt_b);// Initialize b
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(seal::LWEParams::poly_modulus_degree, 0ULL));
    cryptor.initial_A(lwe_initial_vec_ms, A); // Initialize A
    seal::RLWECipher ctxt_lwe_s;
    cryptor.initial_s(ctxt_lwe_s); // Initialize s
    // Compute A*s
    time_start = std::chrono::high_resolution_clock::now();
    cryptor.LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Compute b - A s
    seal::RLWECipher ctxt_b_as;
    // cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    cryptor.ctxt_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    seal::Plaintext ptxt_b_as(seal::RLWEParamsLittle::poly_modulus_degree);
    seal::VecData m_b_as(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    cryptor.decrypt(ctxt_b_as, m_b_as, seal::ParamSet::RLWE);
    for(int i=0; i<128; i++){
        std::cout << "m_b_as[" << i << "]: " <<  m_b_as[i] << " ";
        // std::cout << "ptxt_b_as[" << i << "]: " <<  ptxt_b_as.data()[i] << " ";
    }
    std::cout << std::endl;

    /* // Manual initialize b-As
    // Construct a simple LWE for simulation
    int n = seal::LWEParams::poly_modulus_degree; // LWE dimension
    // construct LWE secret s = [1,0,...,0]
    seal::VecData lwe_s(seal::RLWEParams::poly_modulus_degree, 0ULL);
    size_t renum = seal::RLWEParams::poly_modulus_degree / seal::LWEParams::poly_modulus_degree;
    #pragma omp parallel for
    for (int i = 0; i < n; i++)
    {
        if(i == 0)
        {
            for (int j = 0; j < (seal::RLWEParams::poly_modulus_degree / n); j++)
            {
                lwe_s.data()[i + j * n] = 1;
            }
        }
        else{
            for (int j = 0; j < (seal::RLWEParams::poly_modulus_degree / n); j++)
            {
                lwe_s.data()[i + j * n] = 0;
            }
        }
    }
    seal::RLWECipher ctxt_lwe_s;
    cryptor.encrypt(lwe_s, ctxt_lwe_s);
    // Construct the matrix A = [ [1,0,...,0] ; ... ;[1,0,...,0] ] with size [N,n]
    seal::MatrixData A(seal::RLWEParams::poly_modulus_degree, std::vector<uint64_t>(n, 0ULL));
    for (int i = 0; i < seal::RLWEParams::poly_modulus_degree; i++){
        for (int j = 0; j < n; j++)
        {
            A[i][0] = 1;
        }
    }
    // compute A * s
    time_start = std::chrono::high_resolution_clock::now();
    cryptor.LinearTransform(ctxt_lwe_s, A);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "LT Done [" << time_diff.count() << " microseconds]" << std::endl;
    // Construct b = [2,2,...,2] with size 1 X N, indicate that m = [1,...,1] with size 1 X N
    // NAND [0,1]->1, [2]->0
    std::vector<uint64_t> m_b(seal::RLWEParams::poly_modulus_degree, 0ULL);
    for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        m_b[i] = 65532;
    }
    seal::Plaintext ptxt_b;
    cryptor.encode(m_b, ptxt_b);
    // b - A s
    seal::RLWECipher ctxt_b_as;
    cryptor.negate_add_plain(ctxt_lwe_s, ptxt_b, ctxt_b_as);
    std::vector<uint64_t> m_b_as(seal::RLWEParams::poly_modulus_degree, 0ULL);
    cryptor.decrypt(ctxt_b_as, m_b_as);
    std::cout << "========DEBUG========" << std::endl;
    std::cout << index << "-th b + as: " << m_b_as[index] << std::endl;
    std::cout << "====================="<< std::endl; */


    // Launch Poly evaluation
    seal::RLWECipher ctxt_polyeval_res;
    seal::VecData vec_polyeval_res;
    seal::util::test_NAND_poly(seal::RLWEParams::plain_modulus);
    // seal::util::test_NAND_poly(383);
    // Specify the path
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
    cryptor.PolyEvalBSGS(coefficients, ctxt_b_as, ctxt_polyeval_res);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "BSGS Done [" << time_diff.count() << " microseconds]" << std::endl;
    cryptor.decrypt(ctxt_polyeval_res, vec_polyeval_res);
    // print expected result and actual result
    std::cout << "Actual : " << vec_polyeval_res[index] << ", Expected : " << expected_result << ", diff : " << abs(vec_polyeval_res[index] - expected_result) << std::endl;

    // // Perform S2C Original
    // seal::RLWECipher ctxt_s2c_result;
    // seal::Plaintext ptxt_s2c_result;
    // seal::VecData vec_s2c_result;
    // std::cout << "Slot to Coefficient" << std::endl;
    // time_start = std::chrono::high_resolution_clock::now();
    // cryptor.CtxtSlot2Coeff(ctxt_polyeval_res, ctxt_s2c_result);
    // // cryptor.S2C_DFT_Extract_Add(ctxt_polyeval_res, ctxt_s2c_result);
    // // std::vector<seal::LWECipher> vec_lwe;
    // // modswitch to last one
    // // cryptor.S2C_no_Add(ctxt_polyeval_res, vec_lwe);
    // time_end = std::chrono::high_resolution_clock::now();
    // time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    // std::cout << "S2C Done [" << time_diff.count() << " microseconds]" << std::endl;
    // cryptor.decrypt(ctxt_s2c_result, ptxt_s2c_result);
    // int index = 0;
    // std::cout << "Actual : " << ptxt_s2c_result.data()[index] << ", Expected : " << vec_polyeval_res[index] << ", diff : " << ptxt_s2c_result.data()[index] - vec_polyeval_res[index] << std::endl;
    // // Perform extraction
    // std::vector<seal::LWECipher> vec_lwe_extract;
    // vec_lwe_extract.resize(seal::RLWEParams::poly_modulus_degree);
    // time_start = std::chrono::high_resolution_clock::now();
    // cryptor.vecSampleExtract(ctxt_s2c_result, vec_lwe_extract, seal::ParamSet::RLWE);
    // time_end = std::chrono::high_resolution_clock::now();
    // time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    // std::cout << "Extraction Done [" << time_diff.count() << " microseconds]" << std::endl;
    // uint64_t lwe_extract_result = cryptor.decrypt(vec_lwe_extract[index], seal::ParamSet::LWE);
    // // Perform LWE Keyswtich
    // std::vector<seal::LWECipher> vec_lwe_result;
    // vec_lwe_result.resize(seal::RLWEParams::poly_modulus_degree);
    // time_start = std::chrono::high_resolution_clock::now();
    // cryptor.veclwekeyswtich(vec_lwe_extract, seal::RLWEParams::poly_modulus_degree, vec_lwe_result);
    // time_end = std::chrono::high_resolution_clock::now();
    // time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    // uint64_t lwe_result = cryptor.decrypt(vec_lwe_result[index], seal::ParamSet::LWE);
    // std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;
    // std::cout << "LWE Keyswitch Done [" << time_diff.count() << " microseconds]" << std::endl;

    // Improvement: Perform KeySwitch
    cryptor.generate_rlwe_switchkeys();
    std::vector<seal::RLWECipher> vec_rlwe_l;
    time_start = std::chrono::high_resolution_clock::now();
    cryptor.rlwekeyswitch(ctxt_polyeval_res, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch Done: " << time_diff.count() << " microseconds" << std::endl;
    // correction check
    std::cout << "BSGS result ";
    cryptor.print_noise(ctxt_polyeval_res,seal::ParamSet::RLWE);
    size_t print_length = seal::LWEParams::npoly + 1;
    seal::Plaintext long_ptxt_dec(seal::RLWEParams::poly_modulus_degree);
    cryptor.decrypt(ctxt_polyeval_res, long_ptxt_dec);
    std::cout << "BSGS plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << long_ptxt_dec.data()[i+(index % (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree))] << " ";
    }
    std::cout << std::endl;
    std::cout << "keyswitch result ";
    cryptor.print_noise(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)],seal::ParamSet::RLWELittle);
    seal::Plaintext short_ptxt_dec(seal::RLWEParamsLittle::poly_modulus_degree);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    cryptor.decrypt(vec_rlwe_l[index% (seal::RLWEParams::poly_modulus_degree / seal::RLWEParamsLittle::poly_modulus_degree)], short_ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "key switch plain result: " << std::endl;
    for(int i=0; i<print_length; i++){
        std::cout << short_ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;
    // Perform S2C and Extract after keyswitch improvement
    std::vector<seal::LWECipher> vec_lwe;
    cryptor.S2C_no_Add_after_KS(vec_rlwe_l, vec_lwe);
    uint64_t lwe_result = cryptor.decrypt(vec_lwe[index], seal::ParamSet::RLWELittle);
    std::cout << "Expected : " << vec_polyeval_res[index] << " S2C result: " << lwe_result << std::endl;
    
    // Perform ModSwitch at last
    seal::LWECipher lwe_ms;
    cryptor.ModSwitchLWE(vec_lwe[index], seal::RLWEParamsLittle::plain_modulus, seal::RLWEParamsLittle::plain_modulus, lwe_ms);
    uint64_t ms_result = 0; // Modswitch decryption result
    cryptor.lwe_manual_decrypt(lwe_ms, ms_result, true, seal::RLWEParamsLittle::plain_modulus, seal::RLWEParamsLittle::plain_modulus);
    std::cout << "Expected : " << round((double) vec_polyeval_res[index] / (double) (21845)) << " ModSwitch result: " << round((double) ms_result / (double) (21845)) << std::endl;
}

void LTtest(seal::Cryptor cryptor)
{
    size_t N = seal::RLWEParams::poly_modulus_degree;
    size_t n = seal::RLWEParamsLittle::poly_modulus_degree;
    size_t print_length = 16;
    size_t npoly = N / n;
    seal::Modulus mod_plain(seal::RLWEParams::plain_modulus);
    seal::MatrixData A(N, seal::VecData(n, 1ULL));

    #pragma omp parallel for
    for(int i=0; i<N; i++){
        for(int j=0; j<n; j++){
            // A[i][j] = seal::random_uint64() % mod_plain.value();
            A[i][j] = i + j;
        }
    }

    std::cout << "Matix A: " << std::endl;
    for(int i=0; i<print_length; i++){
        for(int j=0; j<print_length; j++){
            std::cout << A[i][j] << " ";
        }
        std::cout << std::endl;
    }

    seal::VecData s(N, 0ULL);
    #pragma omp parallel for
    for(int j=0; j<n; j++){
        uint64_t random = j; // seal::random_uint64() % mod_plain.value();
        for(int i=0; i<npoly; i++){
            s[j + i*n] = random;
        }
    }

    std::cout << "Vector s: " << std::endl;
    for(int j=0; j<print_length; j++){
        std::cout << s[j] << " ";
    }
    std::cout << std::endl;

    seal::RLWECipher ctxt_A_s;
    cryptor.encrypt(s, ctxt_A_s, seal::ParamSet::RLWE);
    cryptor.LinearTransform(ctxt_A_s, A);

    seal::VecData b(N, 0ULL);
    for(int i=0; i<N; i++){
        b[i] = i+2;
    }
    std::cout << "Vector b: " << std::endl;
    for(int j=0; j<print_length; j++){
        std::cout << b[j] << " ";
    }
    std::cout << std::endl;
    seal::Plaintext ptxt_b;
    cryptor.encode(b, ptxt_b, seal::ParamSet::RLWE);

    cryptor.ctxt_add_plain(ctxt_A_s, ptxt_b, ctxt_A_s);

    seal::VecData A_s(N, 0ULL);
    cryptor.decrypt(ctxt_A_s, A_s);

    // for(int i=0; i<N; i=i+1119){
    //     std::cout << i << "-th: " << A_s[i] << " ";
    // }
    // std::cout << std::endl;

    seal::VecData vec_golden(N, 0ULL);
    #pragma omp parallel for
    for(int i=0; i<N; i++){
        for(int j=0; j<n; j++){
            vec_golden[i] = seal::util::add_uint_mod(  vec_golden[i],   seal::util::multiply_uint_mod(s[j] , A[i][j],  mod_plain),   mod_plain   );
        }
        vec_golden[i] = seal::util::add_uint_mod(vec_golden[i], b[i], mod_plain);
    }
    
    for(int i=0; i<N; i=i+1119){
        std::cout << i << "-th: " << vec_golden[i] << " " << A_s[i] << std::endl;
    }
    std::cout << std::endl;

    return;
}

void ModSwitchTest(seal::Cryptor cryptor)
{
    size_t RLWE_N = seal::RLWEParamsLittle::poly_modulus_degree;
    seal::VecData vec_test(RLWE_N, 1ULL);
    seal::Plaintext ptxt_test;
    cryptor.encode(vec_test, ptxt_test, seal::ParamSet::RLWELittle);
    for(int i=0; i<RLWE_N; i++){
        ptxt_test.data()[i] = 0;
    }
    seal::RLWECipher rlwe_test;
    cryptor.encrypt(ptxt_test, rlwe_test, seal::ParamSet::RLWELittle);
    // Extract
    seal::LWECipher lwe_test;
    cryptor.SampleExtract(rlwe_test, lwe_test, 0, false, seal::ParamSet::LWE);
    uint64_t extract_result = cryptor.decrypt(lwe_test, seal::ParamSet::RLWELittle);
    std::cout << "Extract result: " << extract_result << std::endl;
    // Manual Decryption
    uint64_t man_dec_result;
    cryptor.lwe_manual_decrypt(lwe_test, man_dec_result);
    std::cout << "Manual decrypt result: " << man_dec_result << std::endl;
    // Manual ModSwitch
    seal::LWECipher lwe_ms;
    // cryptor.ModSwitchLWE(lwe_test, 65537, 1152921504598720513, lwe_ms); // mod switch but not change 
    // cryptor.lwe_manual_decrypt(lwe_ms, man_dec_result, true, 1152921504598720513, 65537);
    // Best Result from 60bit
    cryptor.ModSwitchLWE(lwe_test, 65537, 65537 , lwe_ms); // p = 3, q = 65537
    cryptor.lwe_manual_decrypt(lwe_ms, man_dec_result, true, 65537 , 65537);
    // cryptor.ModSwitchLWE(lwe_test, 3, 65537, lwe_ms); // p = 3, q = 65537
    // cryptor.lwe_manual_decrypt(lwe_ms, man_dec_result, true, 65537, 3);
    std::cout << "MS decrypt result: " << round((double) man_dec_result / (double) (21845)) << std::endl;

    // Analyze noise
    cryptor.NoiseAnal();
    return;
}

void iNttNttTest(seal::Cryptor cryptor)
{
    seal::VecData vec_test(seal::RLWEParams::poly_modulus_degree, 4ULL);
    // add some random number
    for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        vec_test[i] = i;
    }
    seal::Plaintext ptxt_test;

    cryptor.encode(vec_test, ptxt_test);
    seal::Plaintext ptxt_ntt, ptxt_intt;
    // cryptor.NTT_manual(ptxt_test);
    // cryptor.iNTT_manual(ptxt_test);
    cryptor.doubleNTT_manual(ptxt_test);

    seal::MatrixData matrix_ntt;
    cryptor.GenNttMatrix(matrix_ntt);
    seal::MatrixData matrix_ntt_manual;
    cryptor.GenNTTMatrixManual(matrix_ntt_manual);
    // cryptor.GenNttRevMatrix(matrix_ntt);

    int N = seal::RLWEParams::poly_modulus_degree;
    int step = 4;
    uint64_t root = 531;
    uint64_t prim_coeff = 995329;

    // generate ntt index matrix
    seal::MatrixData matrix_ntt_index;
    matrix_ntt_index.resize(step, seal::VecData(step));
    #pragma omp parallel for
    for (int i = 0; i<step; i++){
        for (int j = 0; j<step; j++){
            for(int t=0; t < 2*N; t++){
                uint64_t exp = seal::util::exponentiate_uint_mod(root, t, prim_coeff);
                if(exp == matrix_ntt[i][j]){
                    matrix_ntt_index[i][j] = t;
                }
            }
        }
    }

    // generate manual ntt index matrix
    seal::MatrixData matrix_ntt_manual_index;
    matrix_ntt_manual_index.resize(step, seal::VecData(step));
    #pragma omp parallel for
    for (int i = 0; i<step; i++){
        for (int j = 0; j<step; j++){
            for(int t=0; t < 2*N; t++){
                uint64_t exp = seal::util::exponentiate_uint_mod(root, t, prim_coeff);
                if(exp == matrix_ntt_manual[i][j]){
                    matrix_ntt_manual_index[i][j] = t;
                }
            }
        }
    }

    std::cout << "NTT matrix is: " << std::endl;
    for (size_t i = 0; i < step; i=i+1) {
        for (size_t j = 0; j < step; j=j+1) {
            std::cout << matrix_ntt[i][j] << " ";
        }
            std::cout << std::endl;
    }

    std::cout << "index ntt matrix is: " << std::endl;
    for (size_t i = 0; i < step; i=i+1) {
        for (size_t j = 0; j < step; j=j+1) {
            std::cout << matrix_ntt_index[i][j];
            if (j == 1){
                std::cout << "(" << seal::util::reverse_bits(matrix_ntt_index[i][j]-j, 12) <<")";
            }
            std::cout << " ";
        }
            std::cout << std::endl;
    }

    std::cout << "manual NTT matrix is: " << std::endl;
    for (size_t i = 0; i < step; i=i+1) {
        for (size_t j = 0; j < step; j=j+1) {
            std::cout << matrix_ntt_manual[i][j] << " ";
        }
            std::cout << std::endl;
    }

    std::cout << "index manual ntt matrix is: " << std::endl;
    for (size_t i = 0; i < step; i=i+1) {
        for (size_t j = 0; j < step; j=j+1) {
            std::cout << matrix_ntt_manual_index[i][j];
            // if (j == 1){
            //     std::cout << "(" << seal::util::reverse_bits(matrix_ntt_manual_index[i][j]-j, 12) <<")";
            // }
            std::cout << " ";
        }
            std::cout << std::endl;
    }

    seal::MatrixData matrix_intt;
    cryptor.GeniNttMatrix(matrix_intt);
    // cryptor.GeniNttRevMatrix(matrix_intt);



    // generate N*intt_matrix index
    seal::MatrixData matrix_N_intt;
    matrix_N_intt.resize(step, seal::VecData(step));
    // #pragma omp parallel for
    for (int i = 0; i<step; i++){
        #pragma omp parallel for
        for (int j = 0; j<step; j++){
            matrix_N_intt[i][j] = seal::util::multiply_uint_mod(matrix_intt[i][j], seal::RLWEParams::poly_modulus_degree, prim_coeff);
        }
    }

    // generate N*intt index matrix
    seal::MatrixData matrix_N_intt_index;
    matrix_N_intt_index.resize(step, seal::VecData(step));
    // #pragma omp parallel for
    for (int i = 0; i<step; i++){
        #pragma omp parallel for
        for (int j = 0; j<step; j++){
            for(int t=0; t < 2*N; t++){
                uint64_t exp = seal::util::exponentiate_uint_mod(root, t, prim_coeff);
                if(exp == matrix_N_intt[i][j]){
                    matrix_N_intt_index[i][j] = t;
                }
            }
        }
    }

    std::cout << "iNTT matrix is: " << std::endl;
    for (size_t i = 0; i < step; i=i+1) {
        for (size_t j = 0; j < step; j=j+1) {
            std::cout << matrix_intt[i][j] << " ";
        }
            std::cout << std::endl;
    }


    std::cout << "N*iNTT matrix is: " << std::endl;
    for (size_t i = 0; i < step; i=i+1) {
        for (size_t j = 0; j < step; j=j+1) {
            std::cout << matrix_N_intt[i][j] << " ";
        }
            std::cout << std::endl;
    }

    std::cout << "index N*intt matrix is: " << std::endl;
    for (size_t i = 0; i < step; i=i+1) {
        for (size_t j = 0; j < step; j=j+1) {
            std::cout << matrix_N_intt_index[i][j];
            if (i==1){
                std::cout << "(" << seal::util::reverse_bits(matrix_N_intt_index[i][j]+i, 12) <<")";
            }
            std::cout  << " ";
        }
            std::cout << std::endl;
    }



    // for(int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
    //     if(ptxt_intt.data()[i] != ptxt_test.data()[i]){
    //         std::cout << i << "-th miss match" << std::endl;
    //     }
    // }

    return;


}

void NWCTest(seal::Cryptor cryptor)
{
    seal::Modulus mod = cryptor.get_first_modulus();

    seal::VecData poly_1(seal::RLWEParams::poly_modulus_degree, 1ULL);
    // poly_1[0] = 1;
    seal::VecData poly_2(seal::RLWEParams::poly_modulus_degree, 0ULL);
    poly_2[0] = 1;

    // Manual NWC
    seal::VecData result_manual(seal::RLWEParams::poly_modulus_degree, 0ULL);
    std::cout << "Doing Manual NWC" << std::endl;
    seal::util::NWC_Manual(poly_1, poly_2, seal::RLWEParams::poly_modulus_degree, 1, mod, {mod}, result_manual);
    // print result
    // std::cout << "Manual Result Poly: " << std::endl;
    // for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
    //     std::cout << result_manual[i] << " ";
    // }
    // std::cout << std::endl;

    // Manual NTT NWC
    seal::VecData poly_1_NTT_manual(seal::RLWEParams::poly_modulus_degree, 0ULL);
    seal::VecData poly_2_NTT_manual(seal::RLWEParams::poly_modulus_degree, 0ULL);
    seal::VecData result_NTT_manual(seal::RLWEParams::poly_modulus_degree, 0ULL);
    seal::VecData result_iNTT_manual(seal::RLWEParams::poly_modulus_degree, 0ULL);
    // Manual NTT 1
    cryptor.NTT_manual_trans(poly_1, poly_1_NTT_manual);
    // print NTT result
    std::cout << "NTT Poly1: " << std::endl;
    for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        std::cout << poly_1_NTT_manual[i] << " ";
    }
    std::cout << std::endl;

    // Manual NTT 2
    cryptor.NTT_manual_trans(poly_2, poly_2_NTT_manual);
    // print NTT result
    std::cout << "NTT Poly2: " << std::endl;
    for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        std::cout << poly_2_NTT_manual[i] << " ";
    }
    std::cout << std::endl;

    // Component wise product
    #pragma omp parallel for
    for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        result_NTT_manual[i] = seal::util::multiply_uint_mod(poly_1_NTT_manual[i], poly_2_NTT_manual[i], mod);
    }
    // print NTT result
    std::cout << "Product NTT: " << std::endl;
    for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        std::cout << result_NTT_manual[i] << " ";
    }
    std::cout << std::endl;
    

    // Manual INTT 1
    cryptor.iNTT_manual_trans(result_NTT_manual, result_iNTT_manual);
    // print result
    std::cout << "INTT Result Poly: " << std::endl;
    for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        std::cout << result_iNTT_manual[i] << " ";
    }
    std::cout << std::endl;
    uint64_t N_inv;
    seal::util::try_invert_uint_mod(seal::RLWEParams::poly_modulus_degree, mod, N_inv);
    #pragma omp parallel for
    for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        result_iNTT_manual[i] = seal::util::multiply_uint_mod(result_iNTT_manual[i], N_inv, mod);
    }
    // print result
    std::cout << "NTT Manual Result Poly: " << std::endl;
    for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        std::cout << result_iNTT_manual[i] << " ";
    }
    std::cout << std::endl;


    // TODO: change order to bitreverse before seal matrix extraction
    // SEAL NTT NWC
    seal::VecData poly_1_NTT_seal(seal::RLWEParams::poly_modulus_degree, 0ULL);
    seal::VecData poly_2_NTT_seal(seal::RLWEParams::poly_modulus_degree, 0ULL);
    seal::VecData result_NTT_seal(seal::RLWEParams::poly_modulus_degree, 0ULL);
    seal::VecData result_iNTT_seal(seal::RLWEParams::poly_modulus_degree, 0ULL);
    // Manual NTT 1
    cryptor.NTT_manual_seal(poly_1, poly_1_NTT_seal);
    // Manual NTT 2
    cryptor.NTT_manual_seal(poly_2, poly_2_NTT_seal);
    // Component wise product
    #pragma omp parallel for
    for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        result_NTT_seal[i] = seal::util::multiply_uint_mod(poly_1_NTT_seal[i], poly_2_NTT_seal[i], mod);
    }
    // Manual INTT 1
    cryptor.iNTT_manual_seal(result_NTT_seal, result_iNTT_seal);
    seal::util::try_invert_uint_mod(seal::RLWEParams::poly_modulus_degree, mod, N_inv);
    #pragma omp parallel for
    for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
        result_iNTT_seal[i] = seal::util::multiply_uint_mod(result_iNTT_seal[i], N_inv, mod);
    }
    // print result
    // std::cout << "NTT SEAL Result Poly: " << std::endl;
    // for (int i=0; i<seal::RLWEParams::poly_modulus_degree; i++){
    //     std::cout << result_iNTT_seal[i] << " ";
    // }
    // std::cout << std::endl;


    return;
}

void LWExtractDecryptTest(seal::Cryptor cryptor)
{

    // we make a new test vector
    seal::VecData vec_test(seal::RLWEParams::poly_modulus_degree,127ULL);
    vec_test[0] = 1;

    // we specify the index of which we extract from RLWE
    int index = 0;

    // we encode for golden and encrypt for test
    seal::RLWECipher rlwe_ctxt_test;
    seal::Plaintext ptxt_test;
    cryptor.encrypt(vec_test, rlwe_ctxt_test);
    cryptor.encode(vec_test, ptxt_test);
    
    // we extrcat the index-th lwe from RLWE
    seal::LWECipher lwe_ctxt_extract;
    cryptor.SampleExtract(rlwe_ctxt_test, lwe_ctxt_extract, index, 0, seal::ParamSet::RLWE);
    seal::RLWECipher rlwe_ctxt_extract;
    cryptor.encrypt(vec_test, rlwe_ctxt_extract); // remember to initialize

    // for decryption simplicity we make a trivial rlwe from lwe
    cryptor.LWEtoRLWE(lwe_ctxt_extract, rlwe_ctxt_extract);
    seal::Plaintext ptxt_extract;
    cryptor.decrypt(rlwe_ctxt_extract, ptxt_extract);
    seal::VecData vec_extract;
    cryptor.decode(ptxt_extract, vec_extract);

    // lwe encrypt the index-th coefficient of plaintext, we can see here
    std::cout << "golden: " << ptxt_test.data()[index]  
        << " extract lwe result: " << ptxt_extract.data()[0] << " vector result: " << vec_extract[0] << std::endl;

    return;
}

void LWEKeySwitchTest(seal::Cryptor cryptor)
{
    // we make a new test vector
    seal::VecData vec_test(seal::RLWEParams::poly_modulus_degree,127ULL);
    vec_test[0] = 1;

    // we specify the index of which we extract from RLWE
    int index = 0;

    // we encode for golden and encrypt for test
    seal::RLWECipher rlwe_ctxt_test;
    seal::Plaintext ptxt_test;
    cryptor.encrypt(vec_test, rlwe_ctxt_test);
    cryptor.encode(vec_test, ptxt_test);
    
    // we extrcat the index-th lwe from RLWE
    cryptor.mod_to_last(rlwe_ctxt_test);
    seal::LWECipher lwe_ctxt_extract;
    cryptor.SampleExtract(rlwe_ctxt_test, lwe_ctxt_extract, index, true, seal::ParamSet::RLWE);
    // uint64_t uint_extract = cryptor.decrypt(lwe_ctxt_extract, seal::ParamSet::RLWE); // we can not decrypt here for decrypt logic

    // we test lwe keyswitch
    seal::LWECipher lwe_keyswitch;
    cryptor.lwekeyswitch(lwe_ctxt_extract, lwe_keyswitch);
    uint64_t uint_keyswitch = cryptor.decrypt(lwe_keyswitch, seal::ParamSet::LWE);

    // lwe encrypt the index-th coefficient of plaintext, we can see here
    std::cout << "golden: " << ptxt_test.data()[index]  
              << " keyswitch decrypt result: " << uint_keyswitch << std::endl;

    return;
}

void NTT_NWC_Compare()
{
    // Test NTT and INTT
    size_t n = 8;
    seal::Modulus mod(17);
    seal::VecData poly_1(n, 0ULL);
    seal::VecData poly_2(n, 0ULL);
    for(int i=0; i<n; i++){
        poly_1[i] = seal::random_uint64() % mod.value();
        poly_2[i] = seal::random_uint64() % mod.value();
    }
    seal::VecData result1(n, 0ULL);
    seal::VecData result2(n, 0ULL);

    seal::util::poly_mul_use_matrix_ntt(poly_1, poly_2, n, mod, result1);
    seal::util::NWC_Manual(poly_1, poly_2, n, 1, mod, {mod}, result2);

    std::cout << "NTT result: ";
    seal::util::Display(result1);

    std::cout << "NWC result: ";
    seal::util::Display(result2);
}

void Manual_NWC_auto_NTT_Compare(seal::Cryptor cryptor)
{
    cryptor.NWC_NTT_Compare();

    return;
}

void RLWEKeySwitchTest(seal::Cryptor cryptor)
{

    // seal::util::RLWEKeySwitchVerify();
    // seal::util::Extract_NWC_test();

    // cryptor.rlwe_context_mod_check();

    // cryptor.rns_add_test();
    
    seal::VecData long_rlwe_noise(seal::RLWEParams::poly_modulus_degree, 0ULL);
    seal::VecData short_rlwe_noise(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    seal::RLWECipher long_rlwe, short_rlwe;
    cryptor.encrypt(long_rlwe_noise, long_rlwe);
    cryptor.encrypt(short_rlwe_noise, short_rlwe, seal::ParamSet::RLWELittle);
    cryptor.print_noise(long_rlwe, seal::ParamSet::RLWE);
    cryptor.print_noise(short_rlwe, seal::ParamSet::RLWELittle);


    size_t l_N = seal::RLWEParamsLittle::poly_modulus_degree;
    size_t N = seal::RLWEParams::poly_modulus_degree;
    size_t npoly = N / l_N;
    std::cout << "npoly: " << npoly << std::endl;

    // cryptor.generate_rlwe_switchkeys();
    cryptor.generate_rlwe_switchkeys_arbitary();
    
    seal::VecData vec (N, 0ULL);
    seal::Plaintext ptxt(N);
    cryptor.encode(vec, ptxt);
    for(int i=0; i<N; i++){
        ptxt.data()[i] = i;
    }
    seal::RLWECipher ctxt;
    cryptor.encrypt(ptxt, ctxt);
    std::vector<seal::RLWECipher> vec_rlwe_l;

    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    time_start = std::chrono::high_resolution_clock::now();
    // cryptor.rlwekeyswitch(ctxt, vec_rlwe_l);
    cryptor.rlwekeyswitch_arbitary(ctxt, vec_rlwe_l);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
    std::cout << "Keyswitch during: " << time_diff.count() << " microseconds" << std::endl;

    // cryptor.rlwekeyswitch_arbitary(ctxt, vec_rlwe_l);

    seal::VecData vec_dec(l_N, 0ULL);
    seal::Plaintext ptxt_dec(l_N);
    // cryptor.decrypt(vec_rlwe_l[2], vec_dec, seal::ParamSet::RLWELittle);
    cryptor.decrypt(vec_rlwe_l[0], ptxt_dec, seal::ParamSet::RLWELittle);
    std::cout << "Decryption result: " << std::endl;
    for(int i=0; i<seal::RLWEParamsLittle::poly_modulus_degree; i++){
        std::cout << ptxt_dec.data()[i] << " ";
    }
    std::cout << std::endl;

    return;
}

void RLWEKeySwitchTest_SEAL(seal::Cryptor cryptor)
{
    
    // // DEBUG:Mannually rotate
    // size_t N = seal::RLWEParams::poly_modulus_degree;
    // seal::VecData vec (N, 0ULL);
    // seal::Plaintext ptxt(N);
    // cryptor.encode(vec, ptxt);
    // for(int i=0; i<N; i++){
    //     vec.data()[i] = i;
    // }
    // seal::RLWECipher ctxt;
    // seal::RLWECipher out_ctxt;
    // cryptor.encrypt(vec, ctxt, seal::ParamSet::RLWELittle);

    // cryptor.gen_rt_key_little();
    // cryptor.rotation_little(ctxt, 0, out_ctxt);

    // cryptor.decrypt(out_ctxt, vec, seal::ParamSet::RLWELittle);
    // seal::util::print_example_banner("Mannual rotation Decryption Result:");
    // for(int i=0; i<N; i++){
    //     std::cout << vec.data()[i] << std::endl;
    // }
    

    size_t N = seal::RLWEParams::poly_modulus_degree;
    size_t n = seal::RLWEParamsLittle::poly_modulus_degree;
    seal::VecData vec (N, 0ULL);
    seal::VecData vec_n (n, 0ULL);
    seal::Plaintext ptxt(N);
    seal::Plaintext ptxt_n(n);
    cryptor.encode(vec, ptxt);
    for(int i=0; i<N; i++){
        ptxt.data()[i] = i;
    }
    cryptor.encode(vec_n, ptxt_n, seal::ParamSet::RLWELittle);
    for(int i=0; i<n; i++){
        ptxt_n.data()[i] = i;
    }
    seal::RLWECipher ctxt, octxt, ctxt_n;
    cryptor.encrypt(ptxt, ctxt);
    cryptor.encrypt(ptxt_n, ctxt_n);
    std::cout << "Original Noise: ";
    cryptor.print_noise(ctxt, seal::ParamSet::RLWE);
    std::vector<seal::RLWECipher> vec_rlwe_l;
    cryptor.decrypt(ctxt_n, ptxt_n, seal::ParamSet::RLWELittle);
    std::cout << "Decryption result: " << std::endl;
    for(int i=0; i<n; i++){
        std::cout << ptxt_n.data()[i] << " ";
    }
    std::cout << std::endl;
    for(int i=0; i<1; i++){
        // cryptor.generate_rlwe_switchkeys_seal();
        // cryptor.rlwekeyswitch_seal(ctxt, vec_rlwe_l);
        cryptor.generate_rlwe_little_kswitchkey();
        cryptor.kswitch_little(ctxt_n, octxt);
    }
    cryptor.decrypt(octxt, ptxt_n, seal::ParamSet::RLWELittle);
    std::cout << "Decryption result: " << std::endl;
    for(int i=0; i<n; i++){
        std::cout << ptxt_n.data()[i] << " ";
    }
    std::cout << std::endl;

    // std::cout << "Original Noise: ";
    // seal::VecData noise_vec(seal::RLWEParamsLittle::poly_modulus_degree, 0ULL);
    // cryptor.encrypt(noise_vec, ctxt, seal::ParamSet::RLWELittle);
    // cryptor.print_noise(ctxt, seal::ParamSet::RLWELittle);
    // std::cout << "Keyswitch Noise: ";
    // cryptor.print_noise(vec_rlwe_l[0], seal::ParamSet::RLWELittle);
    // cryptor.decrypt(vec_rlwe_l[0], ptxt, seal::ParamSet::RLWELittle);
    // std::cout << "Decryption result: " << std::endl;
    // for(int i=0; i<seal::RLWEParamsLittle::poly_modulus_degree; i++){
    //     std::cout << ptxt.data()[i] << " ";
    // }
    // std::cout << std::endl;

    return;
}

// Not correct
void LWEMulScalarTest(seal::Cryptor cryptor)
{
    seal::VecData vec_test(seal::RLWEParams::poly_modulus_degree,127ULL);
    int index = 0;
    vec_test[index] = 1;
    seal::RLWECipher rlwe_ctxt_test;
    cryptor.encrypt(vec_test, rlwe_ctxt_test);
    seal::LWECipher lwe_ctxt_test;
    cryptor.SampleExtract(rlwe_ctxt_test, lwe_ctxt_test, index, 0, seal::ParamSet::RLWE);
    uint64_t scalar = 10;
    seal::LWECipher lwe_ctxt_result;
    cryptor.LWEMultScalar(lwe_ctxt_test, 10, lwe_ctxt_result);
    seal::RLWECipher rlwe_ctxt_result;
    cryptor.encrypt(vec_test, rlwe_ctxt_result);
    cryptor.LWEtoRLWE(lwe_ctxt_result, rlwe_ctxt_result);
    seal::VecData vec_result(seal::RLWEParams::poly_modulus_degree,0ULL);
    cryptor.decrypt(rlwe_ctxt_result, vec_result);
    seal::Modulus mod_plain(seal::RLWEParams::plain_modulus);
    uint64_t golden = seal::util::multiply_uint_mod(vec_test[index], scalar, mod_plain);
    std::cout << "golden: " << golden << " LWE result: " << vec_result[0] << std::endl;
    
    return;
}

// Test S2C_no_add
void S2C_no_add_Test(seal::Cryptor cryptor)
{   
    // seal::Plaintext ptxt_gen_test;
    // auto poly_degree = seal::RLWEParams::poly_modulus_degree;
    // cryptor.GenS2CPtxt(0, ptxt_gen_test);
    // for (int i=0; i<16; i++){
    //     std::cout << "i: " << i << " ";
    //     std::cout << ptxt_gen_test.data()[i] << " ";
    // }
    // std::cout << std::endl;

    // auto poly_degree = seal::RLWEParams::poly_modulus_degree;
    // seal::VecData vec_test(poly_degree, 10ULL);
    // seal::RLWECipher ctxt_test;
    // cryptor.encrypt(vec_test, ctxt_test);
    // // seal::Plaintext ptxt_gen_test;
    // // cryptor.GenS2CPtxt(1, ptxt_gen_test);
    // std::vector<seal::LWECipher> lwe_zero;
    // cryptor.S2C_no_Add(ctxt_test, lwe_zero);

    seal::Plaintext ptxt_gen_test;
    auto poly_degree = seal::RLWEParams::poly_modulus_degree;
    cryptor.GenS2CPtxt(0, ptxt_gen_test);
    seal::VecData vec_2(poly_degree, 0ULL);
    for (int i=0; i<poly_degree; i++){
        vec_2[i] = ptxt_gen_test.data()[i];
    }
    seal::VecData vec_1(poly_degree, 0ULL);
    for (int i=0; i<poly_degree; i++){
        vec_1[i] = 1;
    }
    seal::Plaintext ptxt_1;
    cryptor.encode(vec_1, ptxt_1);
    for (int i=0; i<poly_degree; i++){
        vec_1[i] = ptxt_1.data()[i];
    }
    seal::VecData vec_3(poly_degree, 0ULL);
    seal::Modulus mod_plain(seal::RLWEParams::plain_modulus);
    seal::util::NWC_Manual(vec_1, vec_2, poly_degree, 1, mod_plain, {mod_plain}, vec_3);

    // uint64_t neg_degree;
    // seal::util::try_invert_uint_mod(2*poly_degree, mod_plain, neg_degree);
    // std::cout << "neg_degree: " << neg_degree << std::endl;

    std::cout << "vec_1: " << std::endl;
    for (int i=0; i<4; i++){
        std::cout << vec_1[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "vec_2: " << std::endl;
    for (int i=0; i<4; i++){
        std::cout << vec_2[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "vec_3: " << std::endl;
    for (int i=0; i<4; i++){
        std::cout << seal::util::multiply_uint_mod(vec_3[i], poly_degree, mod_plain) << " ";
    }
    std::cout << std::endl;

    

    return;
}

// Nothing
void try_to_find_poly_Test()
{
    size_t n = 4;
    seal::Modulus mod_plain(17);

    seal::util::try_to_find_poly(n, mod_plain);
}

// Find out execution flow of NTT/INTT
void try_to_learn_NTT(seal::Cryptor cryptor)
{
    // seal::VecData vec_test(seal::RLWEParams::poly_modulus_degree, 1ULL);
    // seal::Plaintext ptxt_test;
    // cryptor.encode_manual(vec_test, ptxt_test);
    // cryptor.show_encode_step();    
    // cryptor.intt_extract_matrix_compare();


    

    // NTT
    uint64_t slot = 64;
    seal::Modulus mod_plain(257);
    std::vector<uint64_t> values_matrix(slot, 1ULL);
    std::vector<uint64_t> ptxt_encode_scale(slot, 0ULL);
    for (int i=0; i<slot; i++){
        values_matrix[i] = i;
    }

    cryptor.ntt_intt_mirror(values_matrix, slot, mod_plain);

    // cryptor.ntt_extract(values_matrix, slot, mod_plain, ptxt_encode_scale);
    // std::cout << "NTT result is: ";
    // for (int i=0; i<slot; i++){
    //     std::cout << ptxt_encode_scale[i] << " ";
    // }
    // std::cout << std::endl;

    // // INTT
    // cryptor.intt_extract(ptxt_encode_scale, slot, mod_plain, values_matrix);
    // std::cout << "INTT result is: ";
    // for (int i=0; i<slot; i++){
    //     std::cout << values_matrix[i] << " ";
    // }
    // std::cout << std::endl;

    // seal::VecData operand1(slot, 0ULL);
    // operand1[0] = 10;
    // operand1[1] = 5;
    // operand1[2] = 6;
    // operand1[3] = 10;

    // seal::VecData operand2(slot, 0ULL);
    // operand2[0] = 4;
    // operand2[1] = 12;
    // operand2[2] = 7;
    // operand2[3] = 15;

    // seal::VecData result(slot, 0ULL);

    // seal::util::NWC_Manual(operand1, operand2, slot, mod_plain, result);
    // std::cout << "NWC result is: ";
    // for (int i=0; i<slot; i++){
    //     std::cout << result[i] << " ";
    // }
    // std::cout << std::endl;

}

// Try to test decryption prcedure
void decrypt_test(seal::Cryptor cryptor)
{
    cryptor.decrypt_manual_test();
    return;
}

