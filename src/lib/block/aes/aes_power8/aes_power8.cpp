/*
* AES using POWER8 crypto extensions
*
* Contributed by Jack Lloyd and Jeffrey Walton
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/aes.h>
#include <botan/cpuid.h>

#include <altivec.h>
#undef vector
#undef bool

namespace Botan {

namespace {

__vector unsigned long long LoadKey(const uint32_t* src)
   {
   __vector unsigned int vec = vec_vsx_ld(0, src);

   if(CPUID::is_little_endian())
      {
      const __vector unsigned char mask = {12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3};
      const __vector unsigned char zero = {0};
      return (__vector unsigned long long)vec_perm((__vector unsigned char)vec, zero, mask);
      }
   else
      {
      return (__vector unsigned long long)vec;
      }
   }

__vector unsigned char Reverse8x16(const __vector unsigned char src)
   {
   if(CPUID::is_little_endian())
      {
      const __vector unsigned char mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
      const __vector unsigned char zero = {0};
      return vec_perm(src, zero, mask);
      }
   else
      {
      return src;
      }
   }

__vector unsigned long long LoadBlock(const uint8_t* src)
   {
   // Note: cast away const-ness, profit 100 MiB/s.
   return (__vector unsigned long long)Reverse8x16(vec_vsx_ld(0, (uint8_t*)src));
   }

void StoreBlock(const __vector unsigned long long src, uint8_t* dest)
   {
   vec_vsx_st(Reverse8x16((__vector unsigned char)src), 0, dest);
   }

}

#define AES_XOR_6_ROUNDS(K)      \
   do                            \
      {                          \
      B0 = vec_xor(B0, K);       \
      B1 = vec_xor(B1, K);       \
      B2 = vec_xor(B2, K);       \
      B3 = vec_xor(B3, K);       \
      B4 = vec_xor(B4, K);       \
      B5 = vec_xor(B5, K);       \
      } while(0)

#define AES_ENC_6_ROUNDS(K)                       \
   do                                             \
      {                                           \
      B0 = __builtin_crypto_vcipher(B0, K);       \
      B1 = __builtin_crypto_vcipher(B1, K);       \
      B2 = __builtin_crypto_vcipher(B2, K);       \
      B3 = __builtin_crypto_vcipher(B3, K);       \
      B4 = __builtin_crypto_vcipher(B4, K);       \
      B5 = __builtin_crypto_vcipher(B5, K);       \
      } while(0)

#define AES_ENC_6_LAST_ROUNDS(K)                  \
   do                                             \
      {                                           \
      B0 = __builtin_crypto_vcipherlast(B0, K);   \
      B1 = __builtin_crypto_vcipherlast(B1, K);   \
      B2 = __builtin_crypto_vcipherlast(B2, K);   \
      B3 = __builtin_crypto_vcipherlast(B3, K);   \
      B4 = __builtin_crypto_vcipherlast(B4, K);   \
      B5 = __builtin_crypto_vcipherlast(B5, K);   \
      } while(0)

#define AES_DEC_6_ROUNDS(K)                       \
   do                                             \
      {                                           \
      B0 = __builtin_crypto_vncipher(B0, K);      \
      B1 = __builtin_crypto_vncipher(B1, K);      \
      B2 = __builtin_crypto_vncipher(B2, K);      \
      B3 = __builtin_crypto_vncipher(B3, K);      \
      B4 = __builtin_crypto_vncipher(B4, K);      \
      B5 = __builtin_crypto_vncipher(B5, K);      \
      } while(0)

#define AES_DEC_6_LAST_ROUNDS(K)                  \
   do                                             \
      {                                           \
      B0 = __builtin_crypto_vncipherlast(B0, K);  \
      B1 = __builtin_crypto_vncipherlast(B1, K);  \
      B2 = __builtin_crypto_vncipherlast(B2, K);  \
      B3 = __builtin_crypto_vncipherlast(B3, K);  \
      B4 = __builtin_crypto_vncipherlast(B4, K);  \
      B5 = __builtin_crypto_vncipherlast(B5, K);  \
      } while(0)

BOTAN_FUNC_ISA("crypto")
void AES_128::power8_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const __vector unsigned long long K0  = LoadKey(&m_EK[0]);
   const __vector unsigned long long K1  = LoadKey(&m_EK[4]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[8]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[12]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[16]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K10 = LoadBlock(m_ME.data());

   while(blocks >= 6)
      {
      __vector unsigned long long B0 = LoadBlock(in+ 0);
      __vector unsigned long long B1 = LoadBlock(in+16);
      __vector unsigned long long B2 = LoadBlock(in+32);
      __vector unsigned long long B3 = LoadBlock(in+48);
      __vector unsigned long long B4 = LoadBlock(in+64);
      __vector unsigned long long B5 = LoadBlock(in+80);

      AES_XOR_6_ROUNDS(K0);

      AES_ENC_6_ROUNDS(K1);
      AES_ENC_6_ROUNDS(K2);
      AES_ENC_6_ROUNDS(K3);
      AES_ENC_6_ROUNDS(K4);
      AES_ENC_6_ROUNDS(K5);
      AES_ENC_6_ROUNDS(K6);
      AES_ENC_6_ROUNDS(K7);
      AES_ENC_6_ROUNDS(K8);
      AES_ENC_6_ROUNDS(K9);
      AES_ENC_6_LAST_ROUNDS(K10);

      StoreBlock(B0, out+ 0);
      StoreBlock(B1, out+16);
      StoreBlock(B2, out+32);
      StoreBlock(B3, out+48);
      StoreBlock(B4, out+64);
      StoreBlock(B5, out+80);

      blocks -= 6;
      in  += 6*16;
      out += 6*16;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vcipher(B, K1);
      B = __builtin_crypto_vcipher(B, K2);
      B = __builtin_crypto_vcipher(B, K3);
      B = __builtin_crypto_vcipher(B, K4);
      B = __builtin_crypto_vcipher(B, K5);
      B = __builtin_crypto_vcipher(B, K6);
      B = __builtin_crypto_vcipher(B, K7);
      B = __builtin_crypto_vcipher(B, K8);
      B = __builtin_crypto_vcipher(B, K9);
      B = __builtin_crypto_vcipherlast(B, K10);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

BOTAN_FUNC_ISA("crypto")
void AES_128::power8_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const __vector unsigned long long K0  = LoadBlock(m_ME.data());
   const __vector unsigned long long K1  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[16]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[12]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[8]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[4]);
   const __vector unsigned long long K10 = LoadKey(&m_EK[0]);

   while(blocks >= 6)
      {
      __vector unsigned long long B0 = LoadBlock(in+ 0);
      __vector unsigned long long B1 = LoadBlock(in+16);
      __vector unsigned long long B2 = LoadBlock(in+32);
      __vector unsigned long long B3 = LoadBlock(in+48);
      __vector unsigned long long B4 = LoadBlock(in+64);
      __vector unsigned long long B5 = LoadBlock(in+80);

      AES_XOR_6_ROUNDS(K0);

      AES_DEC_6_ROUNDS(K1);
      AES_DEC_6_ROUNDS(K2);
      AES_DEC_6_ROUNDS(K3);
      AES_DEC_6_ROUNDS(K4);
      AES_DEC_6_ROUNDS(K5);
      AES_DEC_6_ROUNDS(K6);
      AES_DEC_6_ROUNDS(K7);
      AES_DEC_6_ROUNDS(K8);
      AES_DEC_6_ROUNDS(K9);
      AES_DEC_6_LAST_ROUNDS(K10);

      StoreBlock(B0, out+ 0);
      StoreBlock(B1, out+16);
      StoreBlock(B2, out+32);
      StoreBlock(B3, out+48);
      StoreBlock(B4, out+64);
      StoreBlock(B5, out+80);

      blocks -= 6;
      in  += 6*16;
      out += 6*16;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vncipher(B, K1);
      B = __builtin_crypto_vncipher(B, K2);
      B = __builtin_crypto_vncipher(B, K3);
      B = __builtin_crypto_vncipher(B, K4);
      B = __builtin_crypto_vncipher(B, K5);
      B = __builtin_crypto_vncipher(B, K6);
      B = __builtin_crypto_vncipher(B, K7);
      B = __builtin_crypto_vncipher(B, K8);
      B = __builtin_crypto_vncipher(B, K9);
      B = __builtin_crypto_vncipherlast(B, K10);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

BOTAN_FUNC_ISA("crypto")
void AES_192::power8_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const __vector unsigned long long K0  = LoadKey(&m_EK[0]);
   const __vector unsigned long long K1  = LoadKey(&m_EK[4]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[8]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[12]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[16]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K10 = LoadKey(&m_EK[40]);
   const __vector unsigned long long K11 = LoadKey(&m_EK[44]);
   const __vector unsigned long long K12 = LoadBlock(m_ME.data());

   while(blocks >= 6)
      {
      __vector unsigned long long B0 = LoadBlock(in+ 0);
      __vector unsigned long long B1 = LoadBlock(in+16);
      __vector unsigned long long B2 = LoadBlock(in+32);
      __vector unsigned long long B3 = LoadBlock(in+48);
      __vector unsigned long long B4 = LoadBlock(in+64);
      __vector unsigned long long B5 = LoadBlock(in+80);

      AES_XOR_6_ROUNDS(K0);

      AES_ENC_6_ROUNDS(K1);
      AES_ENC_6_ROUNDS(K2);
      AES_ENC_6_ROUNDS(K3);
      AES_ENC_6_ROUNDS(K4);
      AES_ENC_6_ROUNDS(K5);
      AES_ENC_6_ROUNDS(K6);
      AES_ENC_6_ROUNDS(K7);
      AES_ENC_6_ROUNDS(K8);
      AES_ENC_6_ROUNDS(K9);
      AES_ENC_6_ROUNDS(K10);
      AES_ENC_6_ROUNDS(K11);
      AES_ENC_6_LAST_ROUNDS(K12);

      StoreBlock(B0, out+ 0);
      StoreBlock(B1, out+16);
      StoreBlock(B2, out+32);
      StoreBlock(B3, out+48);
      StoreBlock(B4, out+64);
      StoreBlock(B5, out+80);

      blocks -= 6;
      in  += 6*16;
      out += 6*16;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vcipher(B, K1);
      B = __builtin_crypto_vcipher(B, K2);
      B = __builtin_crypto_vcipher(B, K3);
      B = __builtin_crypto_vcipher(B, K4);
      B = __builtin_crypto_vcipher(B, K5);
      B = __builtin_crypto_vcipher(B, K6);
      B = __builtin_crypto_vcipher(B, K7);
      B = __builtin_crypto_vcipher(B, K8);
      B = __builtin_crypto_vcipher(B, K9);
      B = __builtin_crypto_vcipher(B, K10);
      B = __builtin_crypto_vcipher(B, K11);
      B = __builtin_crypto_vcipherlast(B, K12);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

BOTAN_FUNC_ISA("crypto")
void AES_192::power8_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const __vector unsigned long long K0  = LoadBlock(m_ME.data());
   const __vector unsigned long long K1  = LoadKey(&m_EK[44]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[40]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[16]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[12]);
   const __vector unsigned long long K10 = LoadKey(&m_EK[8]);
   const __vector unsigned long long K11 = LoadKey(&m_EK[4]);
   const __vector unsigned long long K12 = LoadKey(&m_EK[0]);

   while(blocks >= 6)
      {
      __vector unsigned long long B0 = LoadBlock(in+ 0);
      __vector unsigned long long B1 = LoadBlock(in+16);
      __vector unsigned long long B2 = LoadBlock(in+32);
      __vector unsigned long long B3 = LoadBlock(in+48);
      __vector unsigned long long B4 = LoadBlock(in+64);
      __vector unsigned long long B5 = LoadBlock(in+80);

      AES_XOR_6_ROUNDS(K0);

      AES_DEC_6_ROUNDS(K1);
      AES_DEC_6_ROUNDS(K2);
      AES_DEC_6_ROUNDS(K3);
      AES_DEC_6_ROUNDS(K4);
      AES_DEC_6_ROUNDS(K5);
      AES_DEC_6_ROUNDS(K6);
      AES_DEC_6_ROUNDS(K7);
      AES_DEC_6_ROUNDS(K8);
      AES_DEC_6_ROUNDS(K9);
      AES_DEC_6_ROUNDS(K10);
      AES_DEC_6_ROUNDS(K11);
      AES_DEC_6_LAST_ROUNDS(K12);

      StoreBlock(B0, out+ 0);
      StoreBlock(B1, out+16);
      StoreBlock(B2, out+32);
      StoreBlock(B3, out+48);
      StoreBlock(B4, out+64);
      StoreBlock(B5, out+80);

      blocks -= 6;
      in  += 6*16;
      out += 6*16;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vncipher(B, K1);
      B = __builtin_crypto_vncipher(B, K2);
      B = __builtin_crypto_vncipher(B, K3);
      B = __builtin_crypto_vncipher(B, K4);
      B = __builtin_crypto_vncipher(B, K5);
      B = __builtin_crypto_vncipher(B, K6);
      B = __builtin_crypto_vncipher(B, K7);
      B = __builtin_crypto_vncipher(B, K8);
      B = __builtin_crypto_vncipher(B, K9);
      B = __builtin_crypto_vncipher(B, K10);
      B = __builtin_crypto_vncipher(B, K11);
      B = __builtin_crypto_vncipherlast(B, K12);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

BOTAN_FUNC_ISA("crypto")
void AES_256::power8_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");
   const __vector unsigned long long K0  = LoadKey(&m_EK[0]);
   const __vector unsigned long long K1  = LoadKey(&m_EK[4]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[8]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[12]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[16]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K10 = LoadKey(&m_EK[40]);
   const __vector unsigned long long K11 = LoadKey(&m_EK[44]);
   const __vector unsigned long long K12 = LoadKey(&m_EK[48]);
   const __vector unsigned long long K13 = LoadKey(&m_EK[52]);
   const __vector unsigned long long K14 = LoadBlock(m_ME.data());

   while(blocks >= 6)
      {
      __vector unsigned long long B0 = LoadBlock(in+ 0);
      __vector unsigned long long B1 = LoadBlock(in+16);
      __vector unsigned long long B2 = LoadBlock(in+32);
      __vector unsigned long long B3 = LoadBlock(in+48);
      __vector unsigned long long B4 = LoadBlock(in+64);
      __vector unsigned long long B5 = LoadBlock(in+80);

      AES_XOR_6_ROUNDS(K0);

      AES_ENC_6_ROUNDS(K1);
      AES_ENC_6_ROUNDS(K2);
      AES_ENC_6_ROUNDS(K3);
      AES_ENC_6_ROUNDS(K4);
      AES_ENC_6_ROUNDS(K5);
      AES_ENC_6_ROUNDS(K6);
      AES_ENC_6_ROUNDS(K7);
      AES_ENC_6_ROUNDS(K8);
      AES_ENC_6_ROUNDS(K9);
      AES_ENC_6_ROUNDS(K10);
      AES_ENC_6_ROUNDS(K11);
      AES_ENC_6_ROUNDS(K12);
      AES_ENC_6_ROUNDS(K13);
      AES_ENC_6_LAST_ROUNDS(K14);

      StoreBlock(B0, out+ 0);
      StoreBlock(B1, out+16);
      StoreBlock(B2, out+32);
      StoreBlock(B3, out+48);
      StoreBlock(B4, out+64);
      StoreBlock(B5, out+80);

      blocks -= 6;
      in  += 6*16;
      out += 6*16;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vcipher(B, K1);
      B = __builtin_crypto_vcipher(B, K2);
      B = __builtin_crypto_vcipher(B, K3);
      B = __builtin_crypto_vcipher(B, K4);
      B = __builtin_crypto_vcipher(B, K5);
      B = __builtin_crypto_vcipher(B, K6);
      B = __builtin_crypto_vcipher(B, K7);
      B = __builtin_crypto_vcipher(B, K8);
      B = __builtin_crypto_vcipher(B, K9);
      B = __builtin_crypto_vcipher(B, K10);
      B = __builtin_crypto_vcipher(B, K11);
      B = __builtin_crypto_vcipher(B, K12);
      B = __builtin_crypto_vcipher(B, K13);
      B = __builtin_crypto_vcipherlast(B, K14);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

BOTAN_FUNC_ISA("crypto")
void AES_256::power8_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_EK.empty() == false, "Key was set");

   const __vector unsigned long long K0  = LoadBlock(m_ME.data());
   const __vector unsigned long long K1  = LoadKey(&m_EK[52]);
   const __vector unsigned long long K2  = LoadKey(&m_EK[48]);
   const __vector unsigned long long K3  = LoadKey(&m_EK[44]);
   const __vector unsigned long long K4  = LoadKey(&m_EK[40]);
   const __vector unsigned long long K5  = LoadKey(&m_EK[36]);
   const __vector unsigned long long K6  = LoadKey(&m_EK[32]);
   const __vector unsigned long long K7  = LoadKey(&m_EK[28]);
   const __vector unsigned long long K8  = LoadKey(&m_EK[24]);
   const __vector unsigned long long K9  = LoadKey(&m_EK[20]);
   const __vector unsigned long long K10 = LoadKey(&m_EK[16]);
   const __vector unsigned long long K11 = LoadKey(&m_EK[12]);
   const __vector unsigned long long K12 = LoadKey(&m_EK[8]);
   const __vector unsigned long long K13 = LoadKey(&m_EK[4]);
   const __vector unsigned long long K14 = LoadKey(&m_EK[0]);

   while(blocks >= 6)
      {
      __vector unsigned long long B0 = LoadBlock(in+ 0);
      __vector unsigned long long B1 = LoadBlock(in+16);
      __vector unsigned long long B2 = LoadBlock(in+32);
      __vector unsigned long long B3 = LoadBlock(in+48);
      __vector unsigned long long B4 = LoadBlock(in+64);
      __vector unsigned long long B5 = LoadBlock(in+80);

      AES_XOR_6_ROUNDS(K0);

      AES_DEC_6_ROUNDS(K1);
      AES_DEC_6_ROUNDS(K2);
      AES_DEC_6_ROUNDS(K3);
      AES_DEC_6_ROUNDS(K4);
      AES_DEC_6_ROUNDS(K5);
      AES_DEC_6_ROUNDS(K6);
      AES_DEC_6_ROUNDS(K7);
      AES_DEC_6_ROUNDS(K8);
      AES_DEC_6_ROUNDS(K9);
      AES_DEC_6_ROUNDS(K10);
      AES_DEC_6_ROUNDS(K11);
      AES_DEC_6_ROUNDS(K12);
      AES_DEC_6_ROUNDS(K13);
      AES_DEC_6_LAST_ROUNDS(K14);

      StoreBlock(B0, out+ 0);
      StoreBlock(B1, out+16);
      StoreBlock(B2, out+32);
      StoreBlock(B3, out+48);
      StoreBlock(B4, out+64);
      StoreBlock(B5, out+80);

      blocks -= 6;
      in  += 6*16;
      out += 6*16;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      __vector unsigned long long B = LoadBlock(in);

      B = vec_xor(B, K0);
      B = __builtin_crypto_vncipher(B, K1);
      B = __builtin_crypto_vncipher(B, K2);
      B = __builtin_crypto_vncipher(B, K3);
      B = __builtin_crypto_vncipher(B, K4);
      B = __builtin_crypto_vncipher(B, K5);
      B = __builtin_crypto_vncipher(B, K6);
      B = __builtin_crypto_vncipher(B, K7);
      B = __builtin_crypto_vncipher(B, K8);
      B = __builtin_crypto_vncipher(B, K9);
      B = __builtin_crypto_vncipher(B, K10);
      B = __builtin_crypto_vncipher(B, K11);
      B = __builtin_crypto_vncipher(B, K12);
      B = __builtin_crypto_vncipher(B, K13);
      B = __builtin_crypto_vncipherlast(B, K14);

      StoreBlock(B, out);

      out += 16;
      in += 16;
      }
   }

}
