/* ****************************************************************
 * Test hashing functions and their performance comparitively.
 *  - hashtest.c (22 April 2020)
 *
 * Current algos: MD2, MD5, SHA1, SHA256, SHA3, Keccak, Blake2b
 *
 * To add an algorithm;
 * - modify `MAX_ALGO`
 * - add known message digests to `digest` array
 * - add algorithm to `gethash()` switch statement
 * - add algorithm to `perfhash()` switch statement
 *
 * ****************************************************************/

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/md2.c"
#include "../src/md5.c"
#include "../src/sha1.c"
#include "../src/sha256.c"
#include "../src/sha3.c"
#include "../src/blake2b.c"

#define MAX_ALGO     18
#define MAX_TEST     7
#define MAX_HASH     64
#define MAX_HASHSTR  129

/****************************************************************/

/* Binary prefix scale */
char Bprefix[9][3] = { "", "K", "M", "G", "T", "P", "E", "Z", "Y" };

/* Hash function names */
char Hashname[MAX_ALGO][19] = {
   "MD2", "MD5", "SHA1", "SHA256",
   "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
   "Keccak-224", "Keccak-256", "Keccak-384", "Keccak-512",
   "Blake2b-256", "Blake2b-384", "Blake2b-512",
   "Blake2b-256(w/key)", "Blake2b-384(w/key)", "Blake2b-512(w/key)"
};

/* Test vectors used in RFC 1321 */
char Tvector[MAX_TEST][86] = {
   "",
   "a",
   "abc",
   "message digest",
   "abcdefghijklmnopqrstuvwxyz",
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
   "123456789012345678901234567890123456789012345678901234567890123"
   "45678901234567890"
};

/* Test vector message digests */
char Tdigest[MAX_ALGO][MAX_TEST][MAX_HASHSTR] = {
   {  /* md2 */
      "8350e5a3e24c153df2275c9f80692773",
      "32ec01ec4a6dac72c0ab96fb34c0b5d1",
      "da853b0d3f88d99b30283a69e6ded6bb",
      "ab4f496bfb2a530b219ff33031fe06b0",
      "4e8ddff3650292ab5a4108c3aa47940b",
      "da33def2a42df13975352846c30338cd",
      "d5976f79d83d3a0dc9806c3c66f3efd8"
   },
   {  /* md5 */
      "d41d8cd98f00b204e9800998ecf8427e",
      "0cc175b9c0f1b6a831c399e269772661",
      "900150983cd24fb0d6963f7d28e17f72",
      "f96b697d7cb7938d525a2f31aaf161d0",
      "c3fcd3d76192e4007dfb496cca67e13b",
      "d174ab98d277d9f5a5611c2c9f419d9f",
      "57edf4a22be3c955ac49da2e2107b67a"
   },
   {  /* sha1 */
      "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
      "a9993e364706816aba3e25717850c26c9cd0d89d",
      "c12252ceda8be8994d5fa0290a47231c1d16aae3",
      "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
      "761c457bf73b14d27e9e9265c46f4b4dda11f940",
      "50abf5706a150990a08b2c5ea40fa0e585554732"
   },
   {  /* sha256 */
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
      "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
      "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
      "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"
   },
   {  /* sha3-224 */
      "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
      "9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b",
      "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
      "18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8",
      "5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239",
      "a67c289b8250a6f437a20137985d605589a8c163d45261b15419556e",
      "0526898e185869f91b3e2a76dd72a15dc6940a67c8164a044cd25cc8"
   },
   {  /* sha3-256 */
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
      "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
      "edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd",
      "7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521",
      "a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f",
      "293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d"
   },
   {  /* sha3-384 */
      "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
      "c3713831264adb47fb6bd1e058d5f004",
      "1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7"
      "ea44f93ee1234aa88f61c91912a4ccd9",
      "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
      "98d88cea927ac7f539f1edf228376d25",
      "d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe6627515"
      "13f19ad57e17d4b93ba1e484fc1980d5",
      "fed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6"
      "ab65db2370077a5cadb53fc9280d278f",
      "d5b972302f5080d0830e0de7b6b2cf383665a008f4c4f386a61112652c742d20"
      "cb45aa51bd4f542fc733e2719e999291",
      "3c213a17f514638acb3bf17f109f3e24c16f9f14f085b52a2f2b81adc0db83df"
      "1a58db2ce013191b8ba72d8fae7e2a5e"
   },
   {  /* sha3-512 */
      "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
      "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
      "697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa80"
      "3f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a",
      "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
      "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
      "3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141"
      "ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59",
      "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384"
      "eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68",
      "d1db17b4745b255e5eb159f66593cc9c143850979fc7a3951796aba80165aab5"
      "36b46174ce19e3f707f0e5c6487f5f03084bc0ec9461691ef20113e42ad28163",
      "9524b9a5536b91069526b4f6196b7e9475b4da69e01f0c855797f224cd7335dd"
      "b286fd99b9b32ffe33b59ad424cc1744f6eb59137f5fb8601932e8a8af0ae930"
   },
   {  /* keccak-224 */
      "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd",
      "7cf87d912ee7088d30ec23f8e7100d9319bff090618b439d3fe91308",
      "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8",
      "b53b2cd638f440fa49916036acdb22245673992fb1b1963b96fb9e93",
      "162bab64dc3ba594bd3b43fd8abec4aa03b36c2784cac53a58f9b076",
      "4fb72d7b6b24bd1f5d4b8ef559fd9188eb66caa01bce34c621a05412",
      "744c1765a53043e186bc30bab07fa379b421cf0bca8224cb83e5d45b"
   },
   {  /* keccak-256 */
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
      "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb",
      "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
      "856ab8a3ad0f6168a4d0ba8d77487243f3655db6fc5b0e1669bc05b1287e0147",
      "9230175b13981da14d2f3334f321eb78fa0473133f6da3de896feb22fb258936",
      "6e61c013aef4c6765389ffcd406dd72e7e061991f4a3a8018190db86bd21ebb4",
      "1523a0cd0e7e1faaba17e1c12210fabc49fa99a7abc061e3d6c978eef4f748c4"
   },
   {  /* keccak-384 */
      "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b"
      "2dd2b21362337441ac12b515911957ff",
      "85e964c0843a7ee32e6b5889d50e130e6485cffc826a30167d1dc2b3a0cc79cb"
      "a303501a1eeaba39915f13baab5abacf",
      "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99"
      "f8c681e4afaf31a34db29fb763e3c28e",
      "8a377db088c43e44040a2bfb26676704999d90527913cabff0a3484825daa54d"
      "3061e67da7d836a0805356962af310e8",
      "c5a708ec2178d8c398461547435e482cee0d85de3d75ddbff54e6606a7e9f994"
      "f023a6033b2bf4c516a5f71fc7470d1a",
      "7377c5707506575c26937f3df0d44a773f8c7452c074ee1725c1ab62f741f950"
      "59459d64caebf35a7c247fe28616cab6",
      "fd6e89cbe3271545f94c3e6786803260f929c1589e3091afd58cf32ef53a4f29"
      "b69c1166cb2982e2cb65cf5eb903e669"
   },
   {  /* keccak-512 */
      "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
      "c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
      "9c46dbec5d03f74352cc4a4da354b4e9796887eeb66ac292617692e765dbe400"
      "352559b16229f97b27614b51dbfbbb14613f2c10350435a8feaf53f73ba01c7c",
      "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5"
      "d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
      "cccc49fa63822b00004cf6c889b28a035440ffb3ef50e790599935518e2aefb0"
      "e2f1839170797f7763a5c43b2dcf02abf579950e36358d6d04dfddc2abac7545",
      "e55bdca64dfe33f36ae3153c727833f9947d92958073f4dd02e38a82d8acb282"
      "b1ee1330a68252a54c6d3d27306508ca765acd45606caeaf51d6bdc459f551f1",
      "d5fa6b93d54a87bbde52dbb44daf96a3455daef9d60cdb922bc4b72a5bbba97c"
      "5bf8c59816fede302fc64e98ce1b864df7be671c968e43d1bae23ad76a3e702d",
      "bc08a9a245e99f62753166a3226e874896de0914565bee0f8be29d678e0da66c"
      "508cc9948e8ad7be78eaa4edced482253f8ab2e6768c9c8f2a2f0afff083d51c"
   },
   {  /* blake2b-256 */
      "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
      "8928aae63c84d87ea098564d1e03ad813f107add474e56aedd286349c0c03ea4",
      "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
      "31a65b562925c6ffefdafa0ad830f4e33eff148856c2b4754de273814adf8b85",
      "117ad6b940f5e8292c007d9c7e7350cd33cf85b5887e8da71c7957830f536e7c",
      "63f74bf0df57c4fd10f949edbe1cb7f6e374ecab882616381d6d999fda748b93",
      "a4705bbca1ae2e7a5d184a403a15f36c31c7e567adeae33f0f3e2f3ca9958198"
   },
   {  /* blake2b-384 */
      "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd324"
      "4a6caf0498812673c5e05ef583825100",
      "7d40de16ff771d4595bf70cbda0c4ea0a066a6046fa73d34471cd4d93d827d7c"
      "94c29399c50de86983af1ec61d5dcef0",
      "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6"
      "c66ba83be64b302d7cba6ce15bb556f4",
      "44c3965bd8f02ed299ad52ffb5bba7c448df242073c5520dc091a0cc55d024cd"
      "d51569c339d0bf2b6cd746708683a0ef",
      "5cad60ce23b9dc62eabdd149a16307ef916e0637506fa10cf8c688430da6c978"
      "a0cb7857fd138977bd281e8cfd5bfd1f",
      "b4975ee19a4f559e3d3497df0db1e5c6b79988b7d7e85c1f064ceaa72a418c48"
      "4e4418b775c77af8d2651872547c8e9f",
      "1ce12d72189f06f1b95c16f4bf7e0685519bc1065eae2efd015a31db13bd123e"
      "a8f8bf83a8682ad29e3828a0a0af299c"
   },
   {  /* blake2b-512 */
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
      "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
      "333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34"
      "d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c",
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
      "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
      "3c26ce487b1c0f062363afa3c675ebdbf5f4ef9bdc022cfbef91e3111cdc2838"
      "40d8331fc30a8a0906cff4bcdbcd230c61aaec60fdfad457ed96b709a382359a",
      "c68ede143e416eb7b4aaae0d8e48e55dd529eafed10b1df1a61416953a2b0a56"
      "66c761e7d412e6709e31ffe221b7a7a73908cb95a4d120b8b090a87d1fbedb4c",
      "99964802e5c25e703722905d3fb80046b6bca698ca9e2cc7e49b4fe1fa087c2e"
      "df0312dfbb275cf250a1e542fd5dc2edd313f9c491127c2e8c0c9b24168e2d50",
      "686f41ec5afff6e87e1f076f542aa466466ff5fbde162c48481ba48a748d8427"
      "99f5b30f5b67fc684771b33b994206d05cc310f31914edd7b97e41860d77d282"
   },
   {  /* blake2b-256 (w/key) */
      "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
      "f5ae00102c0fc6fd2ca53a0c9b6a7f7ccddec83de24473609ac0c30af6a4b5f2",
      "171481ca8152739bf45bdadea9de4a4f5509d54ea8d77470f4999999f312d591",
      "8f97741b09e4bc1768a5fbf7120a8086e86b3582ac1783cde2440cd71bcfc748",
      "afa61777b189c1452c9efbce1805d437fd28e4bb960d4feae13b41d89e6acd92",
      "6340de0c02b0de3fc6b6fde4f6a971d0a2d35b30378c6581855993fb479d7f61",
      "0000000000000000000000000000000000000000000000000000000000000000"
   },
   {  /* blake2b-384 (w/key) */
      "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd324"
      "4a6caf0498812673c5e05ef583825100",
      "a340aaff16b65ded203e4410216086161ac5d54fa08f2fc71414315df4b76e4b"
      "4e9ab2c5a87f79d07dd3328e8a16268f",
      "e3c90280c534a46f7dd230cbe7f4fa62ee3e47a3f0ade5b732aedbeeeaee7b7b"
      "a4af1a3a3fe63726cd23bee5e36496b1",
      "9ba17065ebe1bf6323c230148309556c01718c068227d4b6b4b2d17f8102b69a"
      "1fc456c7e130c0112acb34b93bd7103b",
      "8fb50610eb28616cd21d51fac1cd1b3dbbf9887a5d77fdcab71712abb3210731"
      "13bef56a2ece02a1ec56d38a7ad24aaa",
      "a6f86d87afd57d947335d4fecc786113641ccdc2a0ece2ad67cac958b7d59e5b"
      "72dec073375266ab7ff1a7640f5f6bb1",
      "0000000000000000000000000000000000000000000000000000000000000000"
      "00000000000000000000000000000000"
   },
   {  /* blake2b-512 (w/key) */
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
      "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
      "bf829aab39c6e3d4bc98a1d6dc467d46ec16ea28979629d915ed2574d5fff0a9"
      "3db5042fc5ea3eaae572b02bee6e6ab1faa44b07c9fe6709b9985f51d043c7a1",
      "17de517e1278d00ac7a6bcf048881aa9a972e6b5cef843d3c61d3e252068a2f5"
      "26c999f45cd96b172509d085b59170e388f845750c812781df582be3fc4a1972",
      "8f6de0600e70979094ab83af161c60a7fff7729e489e398cc3e9074e3dd33f0a"
      "c91a24dab30491262c87019534653a63b1ccbf0d5d468e83b12b6fc7a3b6dd98",
      "ca43505c2ea6e708ef22dd66ac069fd0497d11f823897e18ed516095bd493e70"
      "f0b6008ecf70ee0c10830575fe326280721a7af707fdaa11b0bc9ffba5925845",
      "2a0cdf013a4c81bfb2d43318ceb5080383ed631f067793539b478a7b7ca2d846"
      "288da45f9830024c2cd7f243eec677138e204b4baf751f15bf490e3d8e6d6806",
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
   },
};

/****************************************************************/

char *gethash(int algo, void *msg, size_t msglen)
            /* algorithm ID   ^   message length
                        message data */ 
{
   static char hash[MAX_HASHSTR] = {0};
   uint8_t md[MAX_HASH] = {0};
   int i, digestlen;

   digestlen = 0;
   switch(algo) {
      case 0:
         digestlen = MD2_LENGTH;
         md2(msg, msglen, md);
         break;
      case 1:
         digestlen = MD5_LENGTH;
         md5(msg, msglen, md);
         break;
      case 2:
         digestlen = SHA1_LENGTH;
         sha1(msg, msglen, md);
         break;
      case 3:
         digestlen = SHA256_LENGTH;
         sha256(msg, msglen, md);
         break;
      case 4:
         digestlen = SHA3_224_LENGTH;
         sha3(msg, msglen, md, SHA3_224_LENGTH);
         break;
      case 5:
         digestlen = SHA3_256_LENGTH;
         sha3(msg, msglen, md, SHA3_256_LENGTH);
         break;
      case 6:
         digestlen = SHA3_384_LENGTH;
         sha3(msg, msglen, md, SHA3_384_LENGTH);
         break;
      case 7:
         digestlen = SHA3_512_LENGTH;
         sha3(msg, msglen, md, SHA3_512_LENGTH);
         break;
      case 8:
         digestlen = SHA3_224_LENGTH;
         keccak(msg, msglen, md, SHA3_224_LENGTH);
         break;
      case 9:
         digestlen = SHA3_256_LENGTH;
         keccak(msg, msglen, md, SHA3_256_LENGTH);
         break;
      case 10:
         digestlen = SHA3_384_LENGTH;
         keccak(msg, msglen, md, SHA3_384_LENGTH);
         break;
      case 11:
         digestlen = SHA3_512_LENGTH;
         keccak(msg, msglen, md, SHA3_512_LENGTH);
         break;
      case 12:
         digestlen = BLAKE2B_256_LENGTH;
         blake2b(msg, msglen, NULL, 0, md, BLAKE2B_256_LENGTH);
         break;
      case 13:
         digestlen = BLAKE2B_384_LENGTH;
         blake2b(msg, msglen, NULL, 0, md, BLAKE2B_384_LENGTH);
         break;
      case 14:
         digestlen = BLAKE2B_512_LENGTH;
         blake2b(msg, msglen, NULL, 0, md, BLAKE2B_512_LENGTH);
         break;
      case 15:
         digestlen = BLAKE2B_256_LENGTH;
         blake2b(msg, msglen, msg, (int) msglen, md, BLAKE2B_256_LENGTH);
         break;
      case 16:
         digestlen = BLAKE2B_384_LENGTH;
         blake2b(msg, msglen, msg, (int) msglen, md, BLAKE2B_384_LENGTH);
         break;
      case 17:
         digestlen = BLAKE2B_512_LENGTH;
         blake2b(msg, msglen, msg, (int) msglen, md, BLAKE2B_512_LENGTH);
         break;
      default:
         printf("\n\nUnknown hash function in gethash()\n\nExiting...\n\n");
         exit(1);
   }
   *hash = '\0';
   for(i = 0; i < digestlen; i++)
      sprintf(hash + (i << 1), "%.02x", md[i]);

   return hash;
}


void perfhash(int algo, void *msg, int msglen)
{
   uint8_t md[MAX_HASH];

   switch(algo) {
      case 0:
         md2(msg, msglen, md);
         break;
      case 1:
         md5(msg, msglen, md);
         break;
      case 2:
         sha1(msg, msglen, md);
         break;
      case 3:
         sha256(msg, msglen, md);
         break;
      case 4:
         sha3(msg, msglen, md, SHA3_224_LENGTH);
         break;
      case 5:
         sha3(msg, msglen, md, SHA3_256_LENGTH);
         break;
      case 6:
         sha3(msg, msglen, md, SHA3_384_LENGTH);
         break;
      case 7:
         sha3(msg, msglen, md, SHA3_512_LENGTH);
         break;
      case 8:
         keccak(msg, msglen, md, SHA3_224_LENGTH);
         break;
      case 9:
         keccak(msg, msglen, md, SHA3_256_LENGTH);
         break;
      case 10:
         keccak(msg, msglen, md, SHA3_384_LENGTH);
         break;
      case 11:
         keccak(msg, msglen, md, SHA3_512_LENGTH);
         break;
      case 12:
         blake2b(msg, msglen, NULL, 0, md, BLAKE2B_256_LENGTH);
         break;
      case 13:
         blake2b(msg, msglen, NULL, 0, md, BLAKE2B_384_LENGTH);
         break;
      case 14:
         blake2b(msg, msglen, NULL, 0, md, BLAKE2B_512_LENGTH);
         break;
      case 15:
         blake2b(msg, msglen, msg, 64, md, BLAKE2B_256_LENGTH);
         break;
      case 16:
         blake2b(msg, msglen, msg, 64, md, BLAKE2B_384_LENGTH);
         break;
      case 17:
         blake2b(msg, msglen, msg, 64, md, BLAKE2B_512_LENGTH);
         break;
      default:
         printf("\n\nUnknown hash function in perfhash\n\nExiting...\n\n");
         exit(1);
   }
}

/****************************************************************/

int main()
{
   clock_t start, us;
   uint64_t n;
   double p;
   int fail, algo, i, j;
   uint8_t perfmsg[1000];
   char *md;

   memset(perfmsg, 'a', 1000);

   printf("\n___________________\n");
   printf("Begin Hash Function Tests...\n\n");
   for(algo = 0; algo < MAX_ALGO; algo++) {
      printf("%19s; Vector test... ", Hashname[algo]);
      for(fail = i = 0; i < MAX_TEST; i++) {
         md = gethash(algo, Tvector[i], strlen(Tvector[i]));
         if(strcmp(md, Tdigest[algo][i])) {
            if(!fail++)
               printf("Hash comparison failure\n");
            printf(" ~Test#%d/ %s\n", i, md);
         }
      }
      if(!fail)
         printf("Pass! ");

      printf("1Kperf= ");
      n = 0;
      j = 1;
      start = clock();
      do {
         for(i = 0; i < j; i++)
            perfhash(algo, perfmsg, 1000);
         n += i * 1000;
         j += i;
      } while((us = clock() - start) < CLOCKS_PER_SEC);
      p = ((double) n * CLOCKS_PER_SEC) / (double) us;
      j = 0;
      while(j < 8 && p > 999) {
         p /= 1000;
         j++;
      }
      printf("%.2f %sB/s\n", p, Bprefix[j]);
   }

   return 0;
}
