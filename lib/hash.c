/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-05 20:38:00 macan>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/* BEGIN OF General Hash Functions */
static inline unsigned int RSHash(char* str, unsigned int len)
{
   unsigned int b    = 378551;
   unsigned int a    = 63689;
   unsigned int hash = 0;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = hash * a + (*str);
      a    = a * b;
   }

   return hash;
}
/* End Of RS Hash Function */


static inline unsigned int JSHash(char* str, unsigned int len)
{
   unsigned int hash = 1315423911;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash ^= ((hash << 5) + (*str) + (hash >> 2));
   }

   return hash;
}
/* End Of JS Hash Function */


static inline unsigned int PJWHash(char* str, unsigned int len)
{
   const unsigned int BitsInUnsignedInt = (unsigned int)(sizeof(unsigned int) * 8);
   const unsigned int ThreeQuarters     = (unsigned int)((BitsInUnsignedInt  * 3) / 4);
   const unsigned int OneEighth         = (unsigned int)(BitsInUnsignedInt / 8);
   const unsigned int HighBits          = (unsigned int)(0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
   unsigned int hash              = 0;
   unsigned int test              = 0;
   unsigned int i                 = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (hash << OneEighth) + (*str);

      if((test = hash & HighBits)  != 0)
      {
         hash = (( hash ^ (test >> ThreeQuarters)) & (~HighBits));
      }
   }

   return hash;
}
/* End Of  P. J. Weinberger Hash Function */


static inline unsigned int ELFHash(char* str, unsigned int len)
{
   unsigned int hash = 0;
   unsigned int x    = 0;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (hash << 4) + (*str);
      if((x = hash & 0xF0000000L) != 0)
      {
         hash ^= (x >> 24);
      }
      hash &= ~x;
   }

   return hash;
}
/* End Of ELF Hash Function */


static inline unsigned int BKDRHash(char* str, unsigned int len)
{
   unsigned int seed = 131; /* 31 131 1313 13131 131313 etc.. */
   unsigned int hash = 0;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (hash * seed) + (*str);
   }

   return hash;
}
/* End Of BKDR Hash Function */


static inline unsigned int SDBMHash(char* str, unsigned int len)
{
   unsigned int hash = 0;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (*str) + (hash << 6) + (hash << 16) - hash;
   }

   return hash;
}
/* End Of SDBM Hash Function */


static inline unsigned int DJBHash(char* str, unsigned int len)
{
   unsigned int hash = 5381;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = ((hash << 5) + hash) + (*str);
   }

   return hash;
}
/* End Of DJB Hash Function */


static inline unsigned int DEKHash(char* str, unsigned int len)
{
   unsigned int hash = len;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = ((hash << 5) ^ (hash >> 27)) ^ (*str);
   }
   return hash;
}
/* End Of DEK Hash Function */


static inline unsigned int BPHash(char* str, unsigned int len)
{
   unsigned int hash = 0;
   unsigned int i    = 0;
   for(i = 0; i < len; str++, i++)
   {
      hash = hash << 7 ^ (*str);
   }

   return hash;
}
/* End Of BP Hash Function */


static inline unsigned int FNVHash(char* str, unsigned int len)
{
   const unsigned int fnv_prime = 0x811C9DC5;
   unsigned int hash      = 0;
   unsigned int i         = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash *= fnv_prime;
      hash ^= (*str);
   }

   return hash;
}
/* End Of FNV Hash Function */


static inline unsigned int APHash(char* str, unsigned int len)
{
   unsigned int hash = 0xAAAAAAAA;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
       hash ^= ((i & 1) == 0) ? (  (hash <<  7) ^ ((*str) * (hash >> 3))) :
           (~(((hash << 11) + (*str)) ^ (hash >> 5)));
   }

   return hash;
}
/* End Of AP Hash Function */
/* END OF General Hash Functions */

static inline u64 hvfs_hash_eh(u64 key1, u64 key2, u64 key2len)
{
#if 1
    u64 hash;

    hash = hash_64(key1, 64);
    hash ^= RSHash((char *)key2, key2len);
    return hash;
#else
    return 0;
#endif
}

static inline u64 hvfs_hash_cbht(u64 key1, u64 key2, u64 key2len)
{
#if 1
    u64 hash;

    hash = hash_64(key1, 64);
    hash ^= APHash((char *)&key2, sizeof(u64));
    return hash;
#else
    u64 val1, val2;
    
    val1 = hash_64(key2, 64);
    val2 = hash_64(key1, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1;
#endif
}

static inline u64 hvfs_hash_ring(u64 key1, u64 key2, u64 key2len)
{
    u64 val1, val2;
    
    val1 = hash_64(key2, 64);
    val2 = hash_64(key1, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1;
}

static inline u32 hvfs_hash_dh(u64 key)
{
    return RSHash((char *)(&key), sizeof(u64));
}

static inline u64 hvfs_hash_gdt(u64 key1, u64 key2)
{
    u64 val1, val2;
    
    val1 = hash_64(key2, 64);
    val2 = hash_64(key1, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1;
}

static inline u64 hvfs_hash_vsite(u64 key1, u64 key2, u64 key2len)
{
    u64 val1;

    val1 = APHash((char *)key2, key2len);
    val1 <<= 32;
    val1 |= RSHash((char *)&key1, sizeof(u64));
    val1 ^= hash_64(key1, 64);
    return val1;
}

static inline u32 hvfs_hash_tws(u64 key)
{
    return APHash((char *)(&key), sizeof(key));
}

/* for storage fd hash table */
static inline u32 hvfs_hash_fdht(u64 key1, u64 key2)
{
    u64 val1, val2;

    val1 = hash_64(key2, 64);
    val2 = hash_64(key1, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1;
}

static inline u32 hvfs_hash_ddht(u64 key1, u64 key2)
{
    u64 val1, val2;

    val1 = hash_64(key2, 64);
    val2 = hash_64(key1, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1;
}

static inline u32 hvfs_hash_site_mgr(u64 key1, u64 key2)
{
    u64 val1, val2;

    val1 = hash_64(key2, 64);
    val2 = hash_64(key1, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1;
}

static inline
u64 hvfs_hash(u64 key1, u64 key2, u64 key2len, u32 sel)
{
    switch (sel) {
    case HASH_SEL_EH:
        return hvfs_hash_eh(key1, key2, key2len);
        break;
    case HASH_SEL_CBHT:
        return hvfs_hash_cbht(key1, key2, key2len);
        break;
    case HASH_SEL_RING:
        return hvfs_hash_ring(key1, key2, key2len);
    case HASH_SEL_DH:
        return hvfs_hash_dh(key1);
        break;
    case HASH_SEL_GDT:
        return hvfs_hash_gdt(key1, key2);
        break;
    case HASH_SEL_VSITE:
        return hvfs_hash_vsite(key1, key2, key2len);
        break;
    default:
        /* we just fall through to zero */
        HVFS_VV("Invalid hash selector %d\n", sel);
        ;
    }
    return 0;
}
