// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[88];
    __int64 field_60; // offset 96
};

__int64 sub_140034D00();
__int64 sub_1400F6B10();
__int64 sub_1400F70CB();
__int64 sub_1400F35E0();
__int64 off_140108258();
extern __int64 off_14012D060;
extern __int64 off_14012D270;
extern __int64 off_14012D230;
extern __int64 off_14012D028;
extern __int64 off_14012D030;
extern __int64 off_14012D038;
extern __int64 off_14012D040;
extern __int64 off_14012D050;
extern __int64 off_14012D034;
extern __int64 off_140113B88;

__int64 __fastcall sub_140034A90(int *a1) {
    int v_13;
    int v_17;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_8;
    int v_9;
    char *str;
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 *v4;
    __int64 v5;
    __int64 *dst;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v7;
    __int64 v9;
    __int64 v8;

    v_8 = -2;
    ptr = *a1;
    a1 = ptr->field_0;
    *(__int64 *)ptr = (__int64)(0);
    if (a1 == 1) {
        v_9 = 0;
        result = off_14012D060;
        if (result == 0) {
            if (v_9 == 0) {
                result = off_14012D270;
                v4 = __readgsqword(88);
                ptr = v4[(__int64)ptr];
                v5 = ptr->field_60;
                if (v5 == 0) {
                    dst = ptr + 96;
                    ptr = off_14012D230;
                    while (ptr != -1) {
                        v5 = ptr + 1;
                        /* cmpxchg %v5, off_14012D230 */;
                        *dst = v5;
                        ptr = off_14012D028;
                        if (v5 == ptr) {
                            result = off_14012D030;
                            if (result != 0xFFFFFFFF) {
                                ++result;
                                off_14012D030 = result;
                                v_30 = 0;
                                v_28 = 1;
                                v_20 = 0;
                                v_18 = 0;
                                v_13 = 0;
                                v_17 = 0;
                                if (off_14012D038 != 0) JUMPOUT(0x140034c34);
                                off_14012D038 = -1;
                                v6 = &off_14012D040;
                                sub_140034D00(v6, 1);
                                xmm0 = _mm_loadu_si128((__m128i *)&v_30);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_20);
                                _mm_storeu_si128((__m128i *)&off_14012D050, xmm1);
                                _mm_storeu_si128((__m128i *)&off_14012D040, xmm0);
                                ++off_14012D038;
                                --off_14012D030;
                                if ((off_14012D030 == 0)) {
                                    off_14012D028 = 0;
                                    result = 0;
                                    result = _InterlockedExchange64(&off_14012D034, result);
                                    if (result == 2) {
                                        v7 = &off_14012D034;
                                        off_140108258(v7);
                                        return v7;
                                    }
                                }
                            }
                        } else {
                            result = 0;
                            /* cmpxchg %(__int64)dst, off_14012D034 */;
                            if (!((0 /* unresolved: flags != */))) {
                                off_14012D028 = v5;
                                result = 1;
                                return result;
                            }
                        }
                        return result;
                    }
                    sub_1400F6B10();
                }
                ptr = off_14012D028;
                if (v5 != ptr) {
                    return (__int64)ptr;
                } else {
                    return (__int64)ptr;
                }
            }
            return (__int64)ptr;
        }
        v9 = str - 9;
        sub_1400F70CB(v9);
        if (v_9 == 0) {
            return v9;
        }
        return v9;
    }
    do {
        v8 = &off_140113B88;
        sub_1400F35E0(v8);
        return result;
    } while (true);
}