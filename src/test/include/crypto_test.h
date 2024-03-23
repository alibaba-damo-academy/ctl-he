#pragma once
#include "cryptor.h"
#include <fstream>
#include <streambuf>

void HomoGFMulTest(seal::Cryptor cryptor);

void HomoXORTest(seal::Cryptor cryptor);

void BatchPBStest(seal::Cryptor cryptor);

void HomoReLUTest(seal::Cryptor cryptor, const uint64_t &message);

void HomoFloorTest(seal::Cryptor cryptor);

void HomoSignTest(seal::Cryptor cryptor);

void HomoAESTest(seal::Cryptor cryptor);

void ReLUtest(seal::Cryptor cryptor);

void BSGSTest(seal::Cryptor cryptor);

void DoubleLTest(seal::Cryptor cryptor);

void LTtest(seal::Cryptor cryptor);

void AmortizedTest(seal::Cryptor cryptor);

void ModSwitchTest(seal::Cryptor cryptor);

void iNttNttTest(seal::Cryptor cryptor);

void NWCTest(seal::Cryptor cryptor);

void LWExtractDecryptTest(seal::Cryptor cryptor);

void LWEMulScalarTest(seal::Cryptor cryptor);

void LWEKeySwitchTest(seal::Cryptor cryptor);

void RLWEKeySwitchTest(seal::Cryptor cryptor);

void RLWEKeySwitchTest_SEAL(seal::Cryptor cryptor);

void Manual_NWC_auto_NTT_Compare(seal::Cryptor cryptor);

// Test S2C_no_add
void S2C_no_add_Test(seal::Cryptor cryptor);

void try_to_find_poly_Test();

void try_to_learn_NTT(seal::Cryptor cryptor);

// test decryption procedure
void decrypt_test(seal::Cryptor cryptor);