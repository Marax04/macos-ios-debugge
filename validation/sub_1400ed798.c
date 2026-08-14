__int64 sub_1400ED816();

__int64 __fastcall sub_1400ED798(__int64 a1, __int64 a2, __int64 a3, __int64 a4) {
    __int64 v5;
    __int64 v7;
    __int64 v3;
    __int64 v1;
    __int64 v2;
    __int64 *src;
    __int64 v4;
    __int64 v6;
    __int64 v9;

    a1 ^= *(__int64 *)v2;
    v5 = *(src + 8);
    v7 = 0xA4093822299F31D0;
    v5 ^= v7;
    v5 *= a4; /* unsigned; high half in v7 */;
    v3 = v4;
    v1 = v7;
    v1 ^= v5;
    v3 ^= *(__int64 *)(v6 + v9 - 16);
    v1 ^= *(__int64 *)(v6 + v9 - 8);
    return sub_1400ED816();
}