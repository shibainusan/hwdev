/* large_prime.h */
/*
 * Copyright (C) 1998-2002
 * Akira Iwata & Takuto Okuno
 * Akira Iwata Laboratory,
 * Nagoya Institute of Technology in Japan.
 *
 * All rights reserved.
 *
 * This software is written by Takuto Okuno(usapato@anet.ne.jp)
 * And if you want to contact us, send an email to Kimitake Wakayama
 * (wakayama@elcom.nitech.ac.jp)
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgment:
 *    "This product includes software developed by Akira Iwata Laboratory,
 *    Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Akira Iwata Laboratory,
 *     Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 *   THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT EXPRESS OR IMPLIED WARRANTY.
 *   AKIRA IWATA LABORATORY DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 *   SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 *   IN NO EVENT SHALL AKIRA IWATA LABORATORY BE LIABLE FOR ANY SPECIAL,
 *   INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 *   FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 *   NEGLIGENCE OR OTHER TORTUOUS ACTION, ARISING OUT OF OR IN CONNECTION
 *   WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#ifndef __LARGE_PRIME_H__
#define __LARGE_PRIME_H__

#define PRIME_MAX	2000

const unsigned int prime[]={
	0x0003,0x0005,0x0007,0x000b,0x000d,0x0011,0x0013,0x0017,
	0x001d,0x001f,0x0025,0x0029,0x002b,0x002f,0x0035,0x003b,
	0x003d,0x0043,0x0047,0x0049,0x004f,0x0053,0x0059,0x0061,
	0x0065,0x0067,0x006b,0x006d,0x0071,0x007f,0x0083,0x0089,
	0x008b,0x0095,0x0097,0x009d,0x00a3,0x00a7,0x00ad,0x00b3,
	0x00b5,0x00bf,0x00c1,0x00c5,0x00c7,0x00d3,0x00df,0x00e3,
	0x00e5,0x00e9,0x00ef,0x00f1,0x00fb,0x0101,0x0107,0x010d,
	0x010f,0x0115,0x0119,0x011b,0x0125,0x0133,0x0137,0x0139,
	0x013d,0x014b,0x0151,0x015b,0x015d,0x0161,0x0167,0x016f,
	0x0175,0x017b,0x017f,0x0185,0x018d,0x0191,0x0199,0x01a3,
	0x01a5,0x01af,0x01b1,0x01b7,0x01bb,0x01c1,0x01c9,0x01cd,
	0x01cf,0x01d3,0x01df,0x01e7,0x01eb,0x01f3,0x01f7,0x01fd,
	0x0209,0x020b,0x021d,0x0223,0x022d,0x0233,0x0239,0x023b,
	0x0241,0x024b,0x0251,0x0257,0x0259,0x025f,0x0265,0x0269,
	0x026b,0x0277,0x0281,0x0283,0x0287,0x028d,0x0293,0x0295,
	0x02a1,0x02a5,0x02ab,0x02b3,0x02bd,0x02c5,0x02cf,0x02d7,
	0x02dd,0x02e3,0x02e7,0x02ef,0x02f5,0x02f9,0x0301,0x0305,
	0x0313,0x031d,0x0329,0x032b,0x0335,0x0337,0x033b,0x033d,
	0x0347,0x0355,0x0359,0x035b,0x035f,0x036d,0x0371,0x0373,
	0x0377,0x038b,0x038f,0x0397,0x03a1,0x03a9,0x03ad,0x03b3,
	0x03b9,0x03c7,0x03cb,0x03d1,0x03d7,0x03df,0x03e5,0x03f1,
	0x03f5,0x03fb,0x03fd,0x0407,0x0409,0x040f,0x0419,0x041b,
	0x0425,0x0427,0x042d,0x043f,0x0443,0x0445,0x0449,0x044f,
	0x0455,0x045d,0x0463,0x0469,0x047f,0x0481,0x048b,0x0493,
	0x049d,0x04a3,0x04a9,0x04b1,0x04bd,0x04c1,0x04c7,0x04cd,
	0x04cf,0x04d5,0x04e1,0x04eb,0x04fd,0x04ff,0x0503,0x0509,
	0x050b,0x0511,0x0515,0x0517,0x051b,0x0527,0x0529,0x052f,
	0x0551,0x0557,0x055d,0x0565,0x0577,0x0581,0x058f,0x0593,
	0x0595,0x0599,0x059f,0x05a7,0x05ab,0x05ad,0x05b3,0x05bf,
	0x05c9,0x05cb,0x05cf,0x05d1,0x05d5,0x05db,0x05e7,0x05f3,
	0x05fb,0x0607,0x060d,0x0611,0x0617,0x061f,0x0623,0x062b,
	0x062f,0x063d,0x0641,0x0647,0x0649,0x064d,0x0653,0x0655,
	0x065b,0x0665,0x0679,0x067f,0x0683,0x0685,0x069d,0x06a1,
	0x06a3,0x06ad,0x06b9,0x06bb,0x06c5,0x06cd,0x06d3,0x06d9,
	0x06df,0x06f1,0x06f7,0x06fb,0x06fd,0x0709,0x0713,0x071f,
	0x0727,0x0737,0x0745,0x074b,0x074f,0x0751,0x0755,0x0757,
	0x0761,0x076d,0x0773,0x0779,0x078b,0x078d,0x079d,0x079f,
	0x07b5,0x07bb,0x07c3,0x07c9,0x07cd,0x07cf,0x07d3,0x07db,
	0x07e1,0x07eb,0x07ed,0x07f7,0x0805,0x080f,0x0815,0x0821,
	0x0823,0x0827,0x0829,0x0833,0x083f,0x0841,0x0851,0x0853,
	0x0859,0x085d,0x085f,0x0869,0x0871,0x0883,0x089b,0x089f,
	0x08a5,0x08ad,0x08bd,0x08bf,0x08c3,0x08cb,0x08db,0x08dd,
	0x08e1,0x08e9,0x08ef,0x08f5,0x08f9,0x0905,0x0907,0x091d,
	0x0923,0x0925,0x092b,0x092f,0x0935,0x0943,0x0949,0x094d,
	0x094f,0x0955,0x0959,0x095f,0x096b,0x0971,0x0977,0x0985,
	0x0989,0x098f,0x099b,0x09a3,0x09a9,0x09ad,0x09c7,0x09d9,
	0x09e3,0x09eb,0x09ef,0x09f5,0x09f7,0x09fd,0x0a13,0x0a1f,
	0x0a21,0x0a31,0x0a39,0x0a3d,0x0a49,0x0a57,0x0a61,0x0a63,
	0x0a67,0x0a6f,0x0a75,0x0a7b,0x0a7f,0x0a81,0x0a85,0x0a8b,
	0x0a93,0x0a97,0x0a99,0x0a9f,0x0aa9,0x0aab,0x0ab5,0x0abd,
	0x0ac1,0x0acf,0x0ad9,0x0ae5,0x0ae7,0x0aed,0x0af1,0x0af3,
	0x0b03,0x0b11,0x0b15,0x0b1b,0x0b23,0x0b29,0x0b2d,0x0b3f,
	0x0b47,0x0b51,0x0b57,0x0b5d,0x0b65,0x0b6f,0x0b7b,0x0b89,
	0x0b8d,0x0b93,0x0b99,0x0b9b,0x0bb7,0x0bb9,0x0bc3,0x0bcb,
	0x0bcf,0x0bdd,0x0be1,0x0be9,0x0bf5,0x0bfb,0x0c07,0x0c0b,
	0x0c11,0x0c25,0x0c2f,0x0c31,0x0c41,0x0c5b,0x0c5f,0x0c61,
	0x0c6d,0x0c73,0x0c77,0x0c83,0x0c89,0x0c91,0x0c95,0x0c9d,
	0x0cb3,0x0cb5,0x0cb9,0x0cbb,0x0cc7,0x0ce3,0x0ce5,0x0ceb,
	0x0cf1,0x0cf7,0x0cfb,0x0d01,0x0d03,0x0d0f,0x0d13,0x0d1f,
	0x0d21,0x0d2b,0x0d2d,0x0d3d,0x0d3f,0x0d4f,0x0d55,0x0d69,
	0x0d79,0x0d81,0x0d85,0x0d87,0x0d8b,0x0d8d,0x0da3,0x0dab,
	0x0db7,0x0dbd,0x0dc7,0x0dc9,0x0dcd,0x0dd3,0x0dd5,0x0ddb,
	0x0de5,0x0de7,0x0df3,0x0dfd,0x0dff,0x0e09,0x0e17,0x0e1d,
	0x0e21,0x0e27,0x0e2f,0x0e35,0x0e3b,0x0e4b,0x0e57,0x0e59,
	0x0e5d,0x0e6b,0x0e71,0x0e75,0x0e7d,0x0e87,0x0e8f,0x0e95,
	0x0e9b,0x0eb1,0x0eb7,0x0eb9,0x0ec3,0x0ed1,0x0ed5,0x0edb,
	0x0eed,0x0eef,0x0ef9,0x0f07,0x0f0b,0x0f0d,0x0f17,0x0f25,
	0x0f29,0x0f31,0x0f43,0x0f47,0x0f4d,0x0f4f,0x0f53,0x0f59,
	0x0f5b,0x0f67,0x0f6b,0x0f7f,0x0f95,0x0fa1,0x0fa3,0x0fa7,
	0x0fad,0x0fb3,0x0fb5,0x0fbb,0x0fd1,0x0fd3,0x0fd9,0x0fe9,
	0x0fef,0x0ffb,0x0ffd,0x1003,0x100f,0x101f,0x1021,0x1025,
	0x102b,0x1039,0x103d,0x103f,0x1051,0x1069,0x1073,0x1079,
	0x107b,0x1085,0x1087,0x1091,0x1093,0x109d,0x10a3,0x10a5,
	0x10af,0x10b1,0x10bb,0x10c1,0x10c9,0x10e7,0x10f1,0x10f3,
	0x10fd,0x1105,0x110b,0x1115,0x1127,0x112d,0x1139,0x1145,
	0x1147,0x1159,0x115f,0x1163,0x1169,0x116f,0x1181,0x1183,
	0x118d,0x119b,0x11a1,0x11a5,0x11a7,0x11ab,0x11c3,0x11c5,
	0x11d1,0x11d7,0x11e7,0x11ef,0x11f5,0x11fb,0x120d,0x121d,
	0x121f,0x1223,0x1229,0x122b,0x1231,0x1237,0x1241,0x1247,
	0x1253,0x125f,0x1271,0x1273,0x1279,0x127d,0x128f,0x1297,
	0x12af,0x12b3,0x12b5,0x12b9,0x12bf,0x12c1,0x12cd,0x12d1,
	0x12df,0x12fd,0x1307,0x130d,0x1319,0x1327,0x132d,0x1337,
	0x1343,0x1345,0x1349,0x134f,0x1357,0x135d,0x1367,0x1369,
	0x136d,0x137b,0x1381,0x1387,0x138b,0x1391,0x1393,0x139d,
	0x139f,0x13af,0x13bb,0x13c3,0x13d5,0x13d9,0x13df,0x13eb,
	0x13ed,0x13f3,0x13f9,0x13ff,0x141b,0x1421,0x142f,0x1433,
	0x143b,0x1445,0x144d,0x1459,0x146b,0x146f,0x1471,0x1475,
	0x148d,0x1499,0x149f,0x14a1,0x14b1,0x14b7,0x14bd,0x14cb,
	0x14d5,0x14e3,0x14e7,0x1505,0x150b,0x1511,0x1517,0x151f,
	0x1525,0x1529,0x152b,0x1537,0x153d,0x1541,0x1543,0x1549,
	0x155f,0x1565,0x1567,0x156b,0x157d,0x157f,0x1583,0x158f,
	0x1591,0x1597,0x159b,0x15b5,0x15bb,0x15c1,0x15c5,0x15cd,
	0x15d7,0x15f7,0x1607,0x1609,0x160f,0x1613,0x1615,0x1619,
	0x161b,0x1625,0x1633,0x1639,0x163d,0x1645,0x164f,0x1655,
	0x1669,0x166d,0x166f,0x1675,0x1693,0x1697,0x169f,0x16a9,
	0x16af,0x16b5,0x16bd,0x16c3,0x16cf,0x16d3,0x16d9,0x16db,
	0x16e1,0x16e5,0x16eb,0x16ed,0x16f7,0x16f9,0x1709,0x170f,
	0x1723,0x1727,0x1733,0x1741,0x175d,0x1763,0x1777,0x177b,
	0x178d,0x1795,0x179b,0x179f,0x17a5,0x17b3,0x17b9,0x17bf,
	0x17c9,0x17cb,0x17d5,0x17e1,0x17e9,0x17f3,0x17f5,0x17ff,
	0x1807,0x1813,0x181d,0x1835,0x1837,0x183b,0x1843,0x1849,
	0x184d,0x1855,0x1867,0x1871,0x1877,0x187d,0x187f,0x1885,
	0x188f,0x189b,0x189d,0x18a7,0x18ad,0x18b3,0x18b9,0x18c1,
	0x18c7,0x18d1,0x18d7,0x18d9,0x18df,0x18e5,0x18eb,0x18f5,
	0x18fd,0x1915,0x191b,0x1931,0x1933,0x1945,0x1949,0x1951,
	0x195b,0x1979,0x1981,0x1993,0x1997,0x1999,0x19a3,0x19a9,
	0x19ab,0x19b1,0x19b5,0x19c7,0x19cf,0x19db,0x19ed,0x19fd,
	0x1a03,0x1a05,0x1a11,0x1a17,0x1a21,0x1a23,0x1a2d,0x1a2f,
	0x1a35,0x1a3f,0x1a4d,0x1a51,0x1a69,0x1a6b,0x1a7b,0x1a7d,
	0x1a87,0x1a89,0x1a93,0x1aa7,0x1aab,0x1aad,0x1ab1,0x1ab9,
	0x1ac9,0x1acf,0x1ad5,0x1ad7,0x1ae3,0x1af3,0x1afb,0x1aff,
	0x1b05,0x1b23,0x1b25,0x1b2f,0x1b31,0x1b37,0x1b3b,0x1b41,
	0x1b47,0x1b4f,0x1b55,0x1b59,0x1b65,0x1b6b,0x1b73,0x1b7f,
	0x1b83,0x1b91,0x1b9d,0x1ba7,0x1bbf,0x1bc5,0x1bd1,0x1bd7,
	0x1bd9,0x1bef,0x1bf7,0x1c09,0x1c13,0x1c19,0x1c27,0x1c2b,
	0x1c2d,0x1c33,0x1c3d,0x1c45,0x1c4b,0x1c4f,0x1c55,0x1c73,
	0x1c81,0x1c8b,0x1c8d,0x1c99,0x1ca3,0x1ca5,0x1cb5,0x1cb7,
	0x1cc9,0x1ce1,0x1cf3,0x1cf9,0x1d09,0x1d1b,0x1d21,0x1d23,
	0x1d35,0x1d39,0x1d3f,0x1d41,0x1d4b,0x1d53,0x1d5d,0x1d63,
	0x1d69,0x1d71,0x1d75,0x1d7b,0x1d7d,0x1d87,0x1d89,0x1d95,
	0x1d99,0x1d9f,0x1da5,0x1da7,0x1db3,0x1db7,0x1dc5,0x1dd7,
	0x1ddb,0x1de1,0x1df5,0x1df9,0x1e01,0x1e07,0x1e0b,0x1e13,
	0x1e17,0x1e25,0x1e2b,0x1e2f,0x1e3d,0x1e49,0x1e4d,0x1e4f,
	0x1e6d,0x1e71,0x1e89,0x1e8f,0x1e95,0x1ea1,0x1ead,0x1ebb,
	0x1ec1,0x1ec5,0x1ec7,0x1ecb,0x1edd,0x1ee3,0x1eef,0x1ef7,
	0x1efd,0x1f01,0x1f0d,0x1f0f,0x1f1b,0x1f39,0x1f49,0x1f4b,
	0x1f51,0x1f67,0x1f75,0x1f7b,0x1f85,0x1f91,0x1f97,0x1f99,
	0x1f9d,0x1fa5,0x1faf,0x1fb5,0x1fbb,0x1fd3,0x1fe1,0x1fe7,
	0x1feb,0x1ff3,0x1fff,0x2011,0x201b,0x201d,0x2027,0x2029,
	0x202d,0x2033,0x2047,0x204d,0x2051,0x205f,0x2063,0x2065,
	0x2069,0x2077,0x207d,0x2089,0x20a1,0x20ab,0x20b1,0x20b9,
	0x20c3,0x20c5,0x20e3,0x20e7,0x20ed,0x20ef,0x20fb,0x20ff,
	0x210d,0x2113,0x2135,0x2141,0x2149,0x214f,0x2159,0x215b,
	0x215f,0x2173,0x217d,0x2185,0x2195,0x2197,0x21a1,0x21af,
	0x21b3,0x21b5,0x21c1,0x21c7,0x21d7,0x21dd,0x21e5,0x21e9,
	0x21f1,0x21f5,0x21fb,0x2203,0x2209,0x220f,0x221b,0x2221,
	0x2225,0x222b,0x2231,0x2239,0x224b,0x224f,0x2263,0x2267,
	0x2273,0x2275,0x227f,0x2285,0x2287,0x2291,0x229d,0x229f,
	0x22a3,0x22b7,0x22bd,0x22db,0x22e1,0x22e5,0x22ed,0x22f7,
	0x2303,0x2309,0x230b,0x2327,0x2329,0x232f,0x2333,0x2335,
	0x2345,0x2351,0x2353,0x2359,0x2363,0x236b,0x2383,0x238f,
	0x2395,0x23a7,0x23ad,0x23b1,0x23bf,0x23c5,0x23c9,0x23d5,
	0x23dd,0x23e3,0x23ef,0x23f3,0x23f9,0x2405,0x240b,0x2417,
	0x2419,0x2429,0x243d,0x2441,0x2443,0x244d,0x245f,0x2467,
	0x246b,0x2479,0x247d,0x247f,0x2485,0x249b,0x24a1,0x24af,
	0x24b5,0x24bb,0x24c5,0x24cb,0x24cd,0x24d7,0x24d9,0x24dd,
	0x24df,0x24f5,0x24f7,0x24fb,0x2501,0x2507,0x2513,0x2519,
	0x2527,0x2531,0x253d,0x2543,0x254b,0x254f,0x2573,0x2581,
	0x258d,0x2593,0x2597,0x259d,0x259f,0x25ab,0x25b1,0x25bd,
	0x25cd,0x25cf,0x25d9,0x25e1,0x25f7,0x25f9,0x2605,0x260b,
	0x260f,0x2615,0x2627,0x2629,0x2635,0x263b,0x263f,0x264b,
	0x2653,0x2659,0x2665,0x2669,0x266f,0x267b,0x2681,0x2683,
	0x268f,0x269b,0x269f,0x26ad,0x26b3,0x26c3,0x26c9,0x26cb,
	0x26d5,0x26dd,0x26ef,0x26f5,0x2717,0x2719,0x2735,0x2737,
	0x274d,0x2753,0x2755,0x275f,0x276b,0x276d,0x2773,0x2777,
	0x277f,0x2795,0x279b,0x279d,0x27a7,0x27af,0x27b3,0x27b9,
	0x27c1,0x27c5,0x27d1,0x27e3,0x27ef,0x2803,0x2807,0x280d,
	0x2813,0x281b,0x281f,0x2821,0x2831,0x283d,0x283f,0x2849,
	0x2851,0x285b,0x285d,0x2861,0x2867,0x2875,0x2881,0x2897,
	0x289f,0x28bb,0x28bd,0x28c1,0x28d5,0x28d9,0x28db,0x28df,
	0x28ed,0x28f7,0x2903,0x2905,0x2911,0x2921,0x2923,0x293f,
	0x2947,0x295d,0x2965,0x2969,0x296f,0x2975,0x2983,0x2987,
	0x298f,0x299b,0x29a1,0x29a7,0x29ab,0x29bf,0x29c3,0x29d5,
	0x29d7,0x29e3,0x29e9,0x29ed,0x29f3,0x2a01,0x2a13,0x2a1d,
	0x2a25,0x2a2f,0x2a4f,0x2a55,0x2a5f,0x2a65,0x2a6b,0x2a6d,
	0x2a73,0x2a83,0x2a89,0x2a8b,0x2a97,0x2a9d,0x2ab9,0x2abb,
	0x2ac5,0x2acd,0x2add,0x2ae3,0x2aeb,0x2af1,0x2afb,0x2b13,
	0x2b27,0x2b31,0x2b33,0x2b3d,0x2b3f,0x2b4b,0x2b4f,0x2b55,
	0x2b69,0x2b6d,0x2b6f,0x2b7b,0x2b8d,0x2b97,0x2b99,0x2ba3,
	0x2ba5,0x2ba9,0x2bbd,0x2bcd,0x2be7,0x2beb,0x2bf3,0x2bf9,
	0x2bfd,0x2c09,0x2c0f,0x2c17,0x2c23,0x2c2f,0x2c35,0x2c39,
	0x2c41,0x2c57,0x2c59,0x2c69,0x2c77,0x2c81,0x2c87,0x2c93,
	0x2c9f,0x2cad,0x2cb3,0x2cb7,0x2ccb,0x2ccf,0x2cdb,0x2ce1,
	0x2ce3,0x2ce9,0x2cef,0x2cff,0x2d07,0x2d1d,0x2d1f,0x2d3b,
	0x2d43,0x2d49,0x2d4d,0x2d61,0x2d65,0x2d71,0x2d89,0x2d9d,
	0x2da1,0x2da9,0x2db3,0x2db5,0x2dc5,0x2dc7,0x2dd3,0x2ddf,
	0x2e01,0x2e03,0x2e07,0x2e0d,0x2e19,0x2e1f,0x2e25,0x2e2d,
	0x2e33,0x2e37,0x2e39,0x2e3f,0x2e57,0x2e5b,0x2e6f,0x2e79,
	0x2e7f,0x2e85,0x2e93,0x2e97,0x2e9d,0x2ea3,0x2ea5,0x2eb1,
	0x2eb7,0x2ec1,0x2ec3,0x2ecd,0x2ed3,0x2ee7,0x2eeb,0x2f05,
	0x2f09,0x2f0b,0x2f11,0x2f27,0x2f29,0x2f41,0x2f45,0x2f4b,
	0x2f4d,0x2f51,0x2f57,0x2f6f,0x2f75,0x2f7d,0x2f81,0x2f83,
	0x2fa5,0x2fab,0x2fb3,0x2fc3,0x2fcf,0x2fd1,0x2fdb,0x2fdd,
	0x2fe7,0x2fed,0x2ff5,0x2ff9,0x3001,0x300d,0x3023,0x3029,
	0x3037,0x303b,0x3055,0x3059,0x305b,0x3067,0x3071,0x3079,
	0x307d,0x3085,0x3091,0x3095,0x30a3,0x30a9,0x30b9,0x30bf,
	0x30c7,0x30cb,0x30d1,0x30d7,0x30df,0x30e5,0x30ef,0x30fb,
	0x30fd,0x3103,0x3109,0x3119,0x3121,0x3127,0x312d,0x3139,
	0x3143,0x3145,0x314b,0x315d,0x3161,0x3167,0x316d,0x3173,
	0x317f,0x3191,0x3199,0x319f,0x31a9,0x31b1,0x31c3,0x31c7,
	0x31d5,0x31db,0x31ed,0x31f7,0x31ff,0x3209,0x3215,0x3217,
	0x321d,0x3229,0x3235,0x3259,0x325d,0x3263,0x326b,0x326f,
	0x3275,0x3277,0x327b,0x328d,0x3299,0x329f,0x32a7,0x32ad,
	0x32b3,0x32b7,0x32c9,0x32cb,0x32cf,0x32d1,0x32e9,0x32ed,
	0x32f3,0x32f9,0x3307,0x3325,0x332b,0x332f,0x3335,0x3341,
	0x3347,0x335b,0x335f,0x3367,0x336b,0x3373,0x3379,0x337f,
	0x3383,0x33a1,0x33a3,0x33ad,0x33b9,0x33c1,0x33cb,0x33d3,
	0x33eb,0x33f1,0x33fd,0x3401,0x340f,0x3413,0x3419,0x341b,
	0x3437,0x3445,0x3455,0x3457,0x3463,0x3469,0x346d,0x3481,
	0x348b,0x3491,0x3497,0x349d,0x34a5,0x34af,0x34bb,0x34c9,
	0x34d3,0x34e1,0x34f1,0x34ff,0x3509,0x3517,0x351d,0x352d,
	0x3533,0x353b,0x3541,0x3551,0x3565,0x356f,0x3571,0x3577,
	0x357b,0x357d,0x3581,0x358d,0x358f,0x3599,0x359b,0x35a1,
	0x35b7,0x35bd,0x35bf,0x35c3,0x35d5,0x35dd,0x35e7,0x35ef,
	0x3605,0x3607,0x3611,0x3623,0x3631,0x3635,0x3637,0x363b,
	0x364d,0x364f,0x3653,0x3659,0x3661,0x366b,0x366d,0x368b,
	0x368f,0x36ad,0x36af,0x36b9,0x36bb,0x36cd,0x36d1,0x36e3,
	0x36e9,0x36f7,0x3701,0x3703,0x3707,0x371b,0x373f,0x3745,
	0x3749,0x374f,0x375d,0x3761,0x3775,0x377f,0x378d,0x37a3,
	0x37a9,0x37ab,0x37c9,0x37d5,0x37df,0x37f1,0x37f3,0x37f7,
	0x3805,0x380b,0x3821,0x3833,0x3835,0x3841,0x3847,0x384b,
	0x3853,0x3857,0x385f,0x3865,0x386f,0x3871,0x387d,0x388f,
	0x3899,0x38a7,0x38b7,0x38c5,0x38c9,0x38cf,0x38d5,0x38d7,
	0x38dd,0x38e1,0x38e3,0x38ff,0x3901,0x391d,0x3923,0x3925,
	0x3929,0x392f,0x393d,0x3941,0x394d,0x395b,0x396b,0x3979,
	0x397d,0x3983,0x398b,0x3991,0x3995,0x399b,0x39a1,0x39a7,
	0x39af,0x39b3,0x39bb,0x39bf,0x39cd,0x39dd,0x39e5,0x39eb,
	0x39ef,0x39fb,0x3a03,0x3a13,0x3a15,0x3a1f,0x3a27,0x3a2b,
	0x3a31,0x3a4b,0x3a51,0x3a5b,0x3a63,0x3a67,0x3a6d,0x3a79,
	0x3a87,0x3aa5,0x3aa9,0x3ab7,0x3acd,0x3ad5,0x3ae1,0x3ae5,
	0x3aeb,0x3af3,0x3afd,0x3b03,0x3b11,0x3b1b,0x3b21,0x3b23,
	0x3b2d,0x3b39,0x3b45,0x3b53,0x3b59,0x3b5f,0x3b71,0x3b7b,
	0x3b81,0x3b89,0x3b9b,0x3b9f,0x3ba5,0x3ba7,0x3bad,0x3bb7,
	0x3bb9,0x3bc3,0x3bcb,0x3bd1,0x3bd7,0x3be1,0x3be3,0x3bf5,
	0x3bff,0x3c01,0x3c0d,0x3c11,0x3c17,0x3c1f,0x3c29,0x3c35,
	0x3c43,0x3c4f,0x3c53,0x3c5b,0x3c65,0x3c6b,0x3c71,0x3c85,
	0x3c89,0x3c97,0x3ca7,0x3cb5,0x3cbf,0x3cc7,0x3cd1,0x3cdd,
	0x3cdf,0x3cf1,0x3cf7,0x3d03,0x3d0d,0x3d19,0x3d1b,0x3d1f,
	0x3d21,0x3d2d,0x3d33,0x3d37,0x3d3f,0x3d43,0x3d6f,0x3d73,
	0x3d75,0x3d79,0x3d7b,0x3d85,0x3d91,0x3d97,0x3d9d,0x3dab,
	0x3daf,0x3db5,0x3dbb,0x3dc1,0x3dc9,0x3dcf,0x3df3,0x3e05,
	0x3e09,0x3e0f,0x3e11,0x3e1d,0x3e23,0x3e29,0x3e2f,0x3e33,
	0x3e41,0x3e57,0x3e63,0x3e65,0x3e77,0x3e81,0x3e87,0x3ea1,
	0x3eb9,0x3ebd,0x3ebf,0x3ec3,0x3ec5,0x3ec9,0x3ed7,0x3edb,
	0x3ee1,0x3ee7,0x3eef,0x3eff,0x3f0b,0x3f0d,0x3f37,0x3f3b,
	0x3f3d,0x3f41,0x3f59,0x3f5f,0x3f65,0x3f67,0x3f79,0x3f7d,
	0x3f8b,0x3f91,0x3fad,0x3fbf,0x3fcd,0x3fd3,0x3fdd,0x3fe9,
	0x3feb,0x3ff1,0x3ffd,0x401b,0x4021,0x4025,0x402b,0x4031,
	0x403f,0x4043,0x4045,0x405d,0x4061,0x4067,0x406d,0x4087,
	0x4091,0x40a3,0x40a9,0x40b1,0x40b7,0x40bd,0x40db,0x40df,
	0x40eb,0x40f7,0x40f9,0x4109,0x410b,0x4111,0x4115,0x4121,
	0x4133,0x4135,0x413b,0x413f,0x4159,0x4165,0x416b,0x4177,
	0x417b,0x4193,0x41ab,0x41b7,0x41bd,0x41bf,0x41cb,0x41e7,
	0x41ef,0x41f3,0x41f9,0x4205,0x4207,0x4219,0x421f,0x4223,
	0x4229,0x422f,0x4243,0x4253,0x4255,0x425b,0x4261,0x4273,
	0x427d,0x4283,0x4285,0x4289,0x4291,0x4297,0x429d,0x42b5,
	0x42c5,0x42cb,0x42d3,0x42dd,0x42e3,0x42f1,0x4307,0x430f,
	0x431f,0x4325,0x4327,0x4333,0x4337,0x4339,0x434f,0x4357,
	0x4369,0x438b,0x438d,0x4393,0x43a5,0x43a9,0x43af,0x43b5,
	0x43bd,0x43c7,0x43cf,0x43e1,0x43e7,0x43eb,0x43ed,0x43f1,
	0x43f9,0x4409,0x440b,0x4417,0x4423,0x4429,0x443b,0x443f,
	0x4445,0x444b,0x4451,0x4453,0x4459,0x4465,0x446f,0x4483,
	0x448f,0x44a1,0x44a5,0x44ab,0x44ad,0x44bd,0x44bf,0x44c9,
	0x44d7,0x44db,0x44f9,0x44fb,0x4505,0x4511,0x4513,0x452b,
	0x4531,0x4541,0x4549,0x4553,0x4555,0x4561,0x4577,0x457d,
	0x457f,0x458f,0x45a3,0x45ad,0x45af,0x45bb,0x45c7,0x45d9,
	0x45e3,0x45ef,0x45f5,0x45f7,0x4601,0x4603,0x4609,0x4613,
	0x4625,0x4627,0x4633,0x4639,0x463d,0x4643,0x4645,0x465d,
	0x4679,0x467b,0x467f,0x4681,0x468b,0x468d,0x469d,0x46a9,
	0x46b1,0x46c7,0x46c9,0x46cf,0x46d3,0x46d5,0x46df,0x46e5,
	0x46f9,0x4705,0x470f,0x4717,0x4723,0x4729,0x472f,0x4735,
	0x4739,0x474b,0x474d,0x4751,0x475d,0x476f,0x4771,0x477d,
	0x4783,0x4787,0x4789,0x4799,0x47a5,0x47b1,0x47bf,0x47c3,
	0x47cb,0x47dd,0x47e1,0x47ed,0x47fb,0x4801,0x4807,0x480b,
	0x4813,0x4819,0x481d,0x4831,0x483d,0x4847,0x4855,0x4859,
	0x485b,0x486b,0x486d,0x4879,0x4897,0x489b,0x48a1,0x48b9,
	0x48cd,0x48e5,0x48ef,0x48f7,0x4903,0x490d,0x4919,0x491f,
	0x492b,0x4937,0x493d,0x4945,0x4955,0x4963,0x4969,0x496d,
	0x4973,0x4997,0x49ab,0x49b5,0x49d3,0x49df,0x49e1,0x49e5,
	0x49e7,0x4a03,0x4a0f,0x4a1d,0x4a23,0x4a39,0x4a41,0x4a45,
	0x4a57,0x4a5d,0x4a6b,0x4a7d,0x4a81,0x4a87,0x4a89,0x4a8f,
	0x4ab1,0x4ac3,0x4ac5,0x4ad5,0x4adb,0x4aed,0x4aef,0x4b07,
	0x4b0b,0x4b0d,0x4b13,0x4b1f,0x4b25,0x4b31,0x4b3b,0x4b43,
	0x4b49,0x4b59,0x4b65,0x4b6d,0x4b77,0x4b85,0x4bad,0x4bb3,
	0x4bb5,0x4bbb,0x4bbf,0x4bcb,0x4bd9,0x4bdd,0x4bdf,0x4be3,
	0x4be5,0x4be9,0x4bf1,0x4bf7,0x4c01,0x4c07,0x4c0d,0x4c0f,
	0x4c15,0x4c1b,0x4c21,0x4c2d,0x4c33,0x4c4b,0x4c55,0x4c57,
	0x4c61,0x4c67,0x4c73,0x4c79,0x4c7f,0x4c8d,0x4c93,0x4c99,
	0x4ccd,0x4ce1,0x4ce7,0x4cf1,0x4cf3,0x4cfd,0x4d05,0x4d0f,
	0x4d1b,0x4d27,0x4d29,0x4d2f,0x4d33,0x4d41,0x4d51,0x4d59,
	0x4d65,0x4d6b,0x4d81,0x4d83,0x4d8d,0x4d95,0x4d9b,0x4db1,
	0x4db3,0x4dc9,0x4dcf,0x4dd7,0x4de1,0x4ded,0x4df9,0x4dfb,
	0x4e05,0x4e0b,0x4e17,0x4e19,0x4e1d,0x4e2b,0x4e35,0x4e37,
	0x4e3d,0x4e4f,0x4e53,0x4e5f,0x4e67,0x4e79,0x4e85,0x4e8b,
	0x4e91,0x4e95,0x4e9b,0x4ea1,0x4eaf,0x4eb3,0x4eb5,0x4ec1,
	0x4ecd,0x4ed1,0x4ed7,0x4ee9,0x4efb,0x4f07,0x4f09,0x4f19,
	0x4f25,0x4f2d,0x4f3f,0x4f49,0x4f63,0x4f67,0x4f6d,0x4f75,
	0x4f7b,0x4f81,0x4f85,0x4f87,0x4f91,0x4fa5,0x4fa9,0x4faf,
	0x4fb7,0x4fbb,0x4fcf,0x4fd9,0x4fdb,0x4ffd,0x4fff,0x5003,
	0x501b,0x501d,0x5029,0x5035,0x503f,0x5045,0x5047,0x5053,
	0x5071,0x5077,0x5083,0x5093,0x509f,0x50a1,0x50b7,0x50c9,
	0x50d5,0x50e3,0x50ed,0x50ef,0x50fb,0x5107,0x510b,0x510d,
	0x5111,0x5117,0x5123,0x5125,0x5135,0x5147,0x5149,0x5171,
	0x5179,0x5189,0x518f,0x5197,0x51a1,0x51a3,0x51a7,0x51b9,
	0x51c1,0x51cb,0x51d3,0x51df,0x51e3,0x51f5,0x51f7,0x5209,
	0x5213,0x5215,0x5219,0x521b,0x521f,0x5227,0x5243,0x5245,
	0x524b,0x5261,0x526d,0x5273,0x5281,0x5293,0x5297,0x529d,
	0x52a5,0x52ab,0x52b1,0x52bb,0x52c3,0x52c7,0x52c9,0x52db,
	0x52e5,0x52eb,0x52ff,0x5315,0x531d,0x5323,0x5341,0x5345,
	0x5347,0x534b,0x535d,0x5363,0x5381,0x5383,0x5387,0x538f,
	0x5395,0x5399,0x539f,0x53ab,0x53b9,0x53db,0x53e9,0x53ef,
	0x53f3,0x53f5,0x53fb,0x53ff,0x540d,0x5411,0x5413,0x5419,
	0x5435,0x5437,0x543b,0x5441,0x5449,0x5453,0x5455,0x545f,
	0x5461,0x546b,0x546d,0x5471,0x548f,0x5491,0x549d,0x54a9,
	0x54b3,0x54c5,0x54d1,0x54df,0x54e9,0x54eb,0x54f7,0x54fd,
	0x5507,0x550d,0x551b,0x5527,0x552b,0x5539,0x553d,0x554f,
	0x5551,0x555b,0x5563,0x5567,0x556f,0x5579,0x5585,0x5597,
	0x55a9,0x55b1,0x55b7,0x55c9,0x55d9,0x55e7,0x55ed,0x55f3,
	0x55fd,0x560b,0x560f,0x5615,0x5617,0x5623,0x562f,0x5633,
	0x5639,0x563f,0x564b,0x564d,0x565d,0x565f,0x566b,0x5671,
	0x5675,0x5683,0x5689,0x568d,0x568f,0x569b,0x56ad,0x56b1,
	0x56d5,0x56e7,0x56f3,0x56ff,0x5701,0x5705,0x5707,0x570b,
	0x5713,0x571f,0x5723,0x5747,0x574d,0x575f,0x5761,0x576d,
	0x5777,0x577d,0x5789,0x57a1,0x57a9,0x57af,0x57b5,0x57c5,
	0x57d1,0x57d3,0x57e5,0x57ef,0x5803,0x580d,0x580f,0x5815,
	0x5827,0x582b,0x582d,0x5855,0x585b,0x585d,0x586d,0x586f,
	0x5873,0x587b,0x588d,0x5897,0x58a3,0x58a9,0x58ab,0x58b5,
	0x58bd,0x58c1,0x58c7,0x58d3,0x58d5,0x58df,0x58f1,0x58f9,
	0x58ff,0x5903,0x5917,0x591b,0x5921,0x5945,0x594b,0x594d,
	0x5957,0x595d,0x5975,0x597b,0x5989,0x5999,0x599f,0x59b1,
	0x59b3,0x59bd,0x59d1,0x59db,0x59e3,0x59e9,0x59ed,0x59f3,
	0x59f5,0x59ff,0x5a01,0x5a0d,0x5a11,0x5a13,0x5a17,0x5a1f,
	0x5a29,0x5a2f,0x5a3b,0x5a4d,0x5a5b,0x5a67,0x5a77,0x5a7f,
	0x5a85,0x5a95,0x5a9d,0x5aa1,0x5aa3,0x5aa9,0x5abb,0x5ad3,
	0x5ae5,0x5aef,0x5afb,0x5afd,0x5b01,0x5b0f,0x5b19,0x5b1f,
	0x5b25,0x5b2b,0x5b3d,0x5b49,0x5b4b,0x5b67,0x5b79,0x5b87,
	0x5b97,0x5ba3,0x5bb1,0x5bc9,0x5bd5,0x5beb,0x5bf1,0x5bf3,
	0x5bfd,0x5c05,0x5c09,0x5c0b,0x5c0f,0x5c1d,0x5c29,0x5c2f,
	0x5c33,0x5c39,0x5c47,0x5c4b,0x5c4d,0x5c51,0x5c6f,0x5c75,
	0x5c77,0x5c7d,0x5c87,0x5c89,0x5ca7,0x5cbd,0x5cbf,0x5cc3,
	0x5cc9,0x5cd1,0x5cd7,0x5cdd,0x5ced,0x5cf9,0x5d05,0x5d0b,
	0x5d13,0x5d17,0x5d19,0x5d31,0x5d3d,0x5d41,0x5d47,0x5d4f,
	0x5d55,0x5d5b,0x5d65,0x5d67,0x5d6d,0x5d79,0x5d95,0x5da3,
	0x5da9,0x5dad,0x5db9,0x5dc1,0x5dc7,0x5dd3,0x5dd7,0x5ddd,
	0x5deb,0x5df1,0x5dfd,0x5e07,0x5e0d,0x5e13,0x5e1b,0x5e21,
	0x5e27,0x5e2b,0x5e2d,0x5e31,0x5e39,0x5e45,0x5e49,0x5e57,
	0x5e69,0x5e73,0x5e75,0x5e85,0x5e8b,0x5e9f,0x5ea5,0x5eaf,
	0x5eb7,0x5ebb,0x5ed9,0x5efd,0x5f09,0x5f11,0x5f27,0x5f33,
	0x5f35,0x5f3b,0x5f47,0x5f57,0x5f5d,0x5f63,0x5f65,0x5f77,
	0x5f7b,0x5f95,0x5f99,0x5fa1,0x5fb3,0x5fbd,0x5fc5,0x5fcf,
	0x5fd5,0x5fe3,0x5fe7,0x5ffb,0x6011,0x6023,0x602f,0x6037,
	0x6053,0x605f,0x6065,0x606b,0x6073,0x6079,0x6085,0x609d,
	0x60ad,0x60bb,0x60bf,0x60cd,0x60d9,0x60df,0x60e9,0x60f5,
	0x6109,0x610f,0x6113,0x611b,0x612d,0x6139,0x614b,0x6155,
	0x6157,0x615b,0x616f,0x6179,0x6187,0x618b,0x6191,0x6193,
	0x619d,0x61b5,0x61c7,0x61c9,0x61cd,0x61e1,0x61f1,0x61ff,
	0x6209,0x6217,0x621d,0x6221,0x6227,0x623b,0x6241,0x624b,
	0x6251,0x6253,0x625f,0x6265,0x6283,0x628d,0x6295,0x629b,
	0x629f,0x62a5,0x62ad,0x62d5,0x62d7,0x62db,0x62dd,0x62e9,
	0x62fb,0x62ff,0x6305,0x630d,0x6317,0x631d,0x632f,0x6341,
	0x6343,0x634f,0x635f,0x6367,0x636d,0x6371,0x6377,0x637d,
	0x637f,0x63b3,0x63c1,0x63c5,0x63d9,0x63e9,0x63eb,0x63ef,
	0x63f5,0x6401,0x6403,0x6409,0x6415,0x6421,0x6427,0x642b,
	0x6439,0x6443,0x6449,0x644f,0x645d,0x6467,0x6475,0x6485,
	0x648d,0x6493,0x649f,0x64a3,0x64ab,0x64c1,0x64c7,0x64c9,
	0x64db,0x64f1,0x64f7,0x64f9,0x650b,0x6511,0x6521,0x652f,
	0x6539,0x653f,0x654b,0x654d,0x6553,0x6557,0x655f,0x6571,
	0x657d,0x658d,0x658f,0x6593,0x65a1,0x65a5,0x65ad,0x65b9,
	0x65c5,0x65e3,0x65f3,0x65fb,0x65ff,0x6601,0x6607,0x661d,
	0x6629,0x6631,0x663b,0x6641,0x6647,0x664d,0x665b,0x6661,
	0x6673,0x667d,0x6689,0x668b,0x6695,0x6697,0x669b,0x66b5,
	0x66b9,0x66c5,0x66cd,0x66d1,0x66e3,0x66eb,0x66f5,0x6703,
	0x6713,0x6719,0x671f,0x6727,0x6731,0x6737,0x673f,0x6745,
	0x6751,0x675b,0x676f,0x6779,0x6781,0x6785,0x6791,0x67ab,
	0x67bd,0x67c1,0x67cd,0x67df,0x67e5,0x6803,0x6809,0x6811,
	0x6817,0x682d,0x6839,0x683b,0x683f,0x6845,0x684b,0x684d,
	0x6857,0x6859,0x685d,0x6863,0x6869,0x686b,0x6871,0x6887,
	0x6899,0x689f,0x68b1,0x68bd,0x68c5,0x68d1,0x68d7,0x68e1,
	0x68ed,0x68ef,0x68ff,0x6901,0x690b,0x690d,0x6917,0x6929,
	0x692f,0x6943,0x6947,0x6949,0x694f,0x6965,0x696b,0x6971,
	0x6983,0x6989,0x6997,0x69a3,0x69b3,0x69b5,0x69bb,0x69c1,
	0x69c5,0x69d3,0x69df,0x69e3,0x69e5,0x69f7,0x6a07,0x6a2b,
	0x6a37,0x6a3d,0x6a4b,0x6a67,0x6a69,0x6a75,0x6a7b,0x6a87,
	0x6a8d,0x6a91,0x6a93,0x6aa3,0x6ac1,0x6ac9,0x6ae1,0x6ae7,
	0x6b05,0x6b0f,0x6b11,0x6b23,0x6b27,0x6b2d,0x6b39,0x6b41,
};

#endif /* __LARGE_PRIME_H__ */
