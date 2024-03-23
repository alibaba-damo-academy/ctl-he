#include "test_all.h"
#include <fstream>
#include <streambuf>
using namespace std;
using namespace seal;

// Implement Amortized Scheme
int main(void)
{

    // seal::util::RLWEKeySwitchVerify();

    Cryptor cryptor;

    // for(int i=0; i<1; i=i+10000){
    //     HomoReLUTest(cryptor, i);
    // }

    // HomoXORTest(cryptor);

    // HomoGFMulTest(cryptor);
    
    // HomoAESTest(cryptor);
    
    // util::DRaM_H4(255, 65537);

    // HomoFloorTest(cryptor);

    HomoSignTest(cryptor);

    // BatchPBStest(cryptor);

    // ReLUtest(cryptor);

    // LTtest(cryptor);

    // decrypt_test(cryptor);

    // for(int i=0; i<10; i++){
    //     AmortizedTest(cryptor);
    // }


    // for (int i=0; i<10; i++){
    //     std::cout << "=================" << std::endl;
    //     std::cout << i << "-th round " << std::endl;
    //     Cryptor cryptor;
    //     ModSwitchTest(cryptor);
    // }

    // EnDecodeTest(cryptor);

    // iNttNttTest(cryptor);

    // NWCTest(cryptor);

    // LWExtractDecryptTest(cryptor);

    // LWEKeySwitchTest(cryptor);

    // LWEMulScalarTest(cryptor);

    // S2C_DFT_Test(cryptor);

    // S2C_no_add_Test(cryptor);

    // try_to_find_poly_Test();

    // try_to_learn_NTT(cryptor);

    // RLWEKeySwitchTest(cryptor);

    // RLWEKeySwitchTest_SEAL(cryptor);

    // Manual_NWC_auto_NTT_Compare(cryptor);


    return 0;

}