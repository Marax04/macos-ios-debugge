// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `result`
struct Struct_2_t {
    char _pad_start[8];
    char field_8; // offset 8
    __int16 field_9; // offset 9
    __int64 field_B; // offset 11
};

__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F2D20();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14008A830(int *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int v_20;
    int v_28;
    __int64 v_2a;
    int v_2c;
    int v_2e;
    int v_30;
    int v_38;
    __int64 v_40;
    int v_48;
    int v_50;
    int v_58;
    __int64 v5;
    struct Struct_2_t *result;
    __int64 v12;
    __int64 v6;
    __m128i xmm0;
    __int64 v10;
    __int64 *src;
    __int64 i;
    __int64 v11;
    __int64 v13;
    __int64 v4;
    __int64 v9;
    __int64 v8;
    __int64 v7;

    v5 = ((__int64 *)a2)[7];
    if (v5 != 0) {
        result = ((__int64 *)a2)[6];
        v12 = ((__int64 *)a2)[3];
        if (result == 0) {
            v6 = ((__int64 *)a2)[4];
            do {
                xmm0 = _mm_load_si128((__m128i *)v6);
                result = _mm_movemask_epi8(xmm0);
                v12 -= 256;
                v6 += 16;
            } while (result == 0xFFFF);
            result = (struct Struct_2_t *)(~(__int64)result);
            ((__int64 *)a2)[4] = (__int64)(v6);
            ((__int64 *)a2)[3] = (__int64)(v12);
        }
        v10 = result - 1;
        v6 = __builtin_ctz(result);
        v10 &= (__int64)result;
        ((__int64 *)a2)[6] = (__int64)(v10);
        v6 <<= 4;
        result = (struct Struct_2_t *)v12;
        result -= v6;
        src = v5 - 1;
        ((__int64 *)a2)[7] = (__int64)(src);
        i = *(__int64 *)(result - 4);
        if (i == 3) {
            *a1 = 0;
            *(a1 + 8) = 4;
            a1[2] = 0;
            result = a2->field_0;
            if (result != 0) {
                if (a2->field_8 != 0) {
                    src = ((__int64 *)a2)[2];
                    if (result >= 17) {
                        src = *(src - 8);
                    }
                    off_140108030(a1, a2, v5, v6);
                    JUMPOUT(off_140108038);
                    v11 = *(__int64 *)(result - 12);
                    v6 = *(__int64 *)(result - 3);
                    result = *(__int64 *)(result - 1);
                    v_2a = (__int64)result;
                    v_28 = v6;
                    result = 4;
                    v13 = 4;
                    if (v5 >= 5) v13 = v5;
                    if (v5 >= v6) {
                        sub_1400F3360(result, 0, src, 0xAAAAAAAAAAAAAAB);
                    }
                    v5 =  + v13*4;
                    v4 = v5 + v5*2;
                    v_30 = (int)a1;
                    if (v4 != 0) {
                        v9 = (__int64)a2;
                        sub_14002EDF0(0, v4, v5);
                        a2 = (struct Struct_1_t *)v9;
                        a1 = (int *)v_30;
                        if (result == 0) {
                            sub_1400F3326(4, v4);
                            v13 = 0;
                        }
                        *(__int64 *)result = (__int64)(v11);
                        result->field_8 = i;
                        v5 = v_28;
                        result->field_9 = v5;
                        v5 = v_2a;
                        result->field_B = v5;
                        v_38 = v13;
                        v_40 = (__int64)result;
                        v_48 = 1;
                        v8 = a2->field_0;
                        v7 = a2->field_8;
                        v5 = ((__int64 *)a2)[2];
                        v_50 = v5;
                        if (src != 0) {
                            v11 = ((__int64 *)a2)[4];
                            i = 1;
                            v13 = rsp + 56;
                            do {
                                v5 = __builtin_ctz(v10);
                                v5 <<= 4;
                                a2 = (struct Struct_1_t *)v12;
                                a2 -= v5;
                                v4 = *(__int64 *)(a2 - 4);
                                if (v4 != 3) {
                                    v9 = *(__int64 *)(a2 - 12);
                                    v5 = *(__int64 *)(a2 - 1);
                                    a2 = *(__int64 *)(a2 - 3);
                                    v_2c = (int)a2;
                                    v_2e = v5;
                                    if (i == v_38) {
                                        v_20 = 12;
                                        v13 = v7;
                                        v_58 = v8;
                                        sub_1400F2D20(v13, i, src, 4);
                                        v8 = v_58;
                                        v7 = v13;
                                        v13 = rsp + 56;
                                        a1 = (int *)v_30;
                                        result = (struct Struct_2_t *)v_40;
                                    }
                                    a2 = v10 - 1;
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 & v10);
                                    --src;
                                    v5 = i + i*2;
                                    *(__int64 *)(result + v5*4) = (__int64)(v9);
                                    *(__int64 *)(result + v5*4 + 8) = (__int64)(v4);
                                    v6 = v_2c;
                                    *(__int64 *)(result + v5*4 + 9) = (__int64)(v6);
                                    v6 = v_2e;
                                    *(__int64 *)(result + v5*4 + 11) = (__int64)(v6);
                                    ++i;
                                    v_48 = i;
                                    v10 = (__int64)a2;
                                }
                                if (v8 != 0) {
                                    if (v7 != 0) {
                                        if (v8 >= 17) {
                                            src = (__int64 *)v_50;
                                            src = *(src - 8);
                                        } else {
                                            src = (__int64 *)v_50;
                                        }
                                        off_140108030(a1);
                                        ((__int64 (*)())off_140108038)(result, 0, src);
                                        a1 = (int *)v_30;
                                    }
                                }
                                result = (struct Struct_2_t *)v_48;
                                a1[2] = result;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_38);
                                _mm_storeu_si128((__m128i *)a1, xmm0);
                                return _mm_cvtsi128_si64(xmm0);
                            } while (src != 0);
                            return _mm_cvtsi128_si64(xmm0);
                        }
                        return _mm_cvtsi128_si64(xmm0);
                    }
                    return _mm_cvtsi128_si64(xmm0);
                }
            }
            return _mm_cvtsi128_si64(xmm0);
        }
        return _mm_cvtsi128_si64(xmm0);
    }
    return (__int64)result;
}