// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F5F90();
__int64 sub_1400F27F0();
__int64 sub_14006BD50();
__int64 sub_14006BFD0();
__int64 sub_1400F37D0();
__int64 off_140108030();
extern __int64 off_140117085;
extern __int64 off_140117220;
extern __int64 off_1401172B0;
extern __int64 off_140108038;

__int64 __fastcall sub_14006C940(int *a1, int *a2, int a3, __int64 str) {
    __int64 rsp;
    int v_20;
    int v_28;
    int v_29;
    int v_2a;
    int v_2b;
    int v_2c;
    int v_2d;
    int v_2e;
    int v_2f;
    int v_30;
    int v_31;
    int v_32;
    int v_33;
    int v_34;
    int v_35;
    int v_36;
    int v_37;
    int v_38;
    int v_39;
    int v_3a;
    int v_3b;
    int v_3c;
    int v_3d;
    int v_3e;
    int v_3f;
    int v_40;
    int v_41;
    int v_42;
    int v_43;
    int v_44;
    int v_45;
    int v_46;
    int v_47;
    int v_48;
    int v_50;
    int v_58;
    int v_68;
    int v_70;
    __int64 v2;
    __int64 v8;
    struct Struct_1_t *ptr;
    __int64 *dst;
    __m128i xmm0;
    __m128i xmm1;
    __int64 *dst2;
    __int64 result;
    __int64 v6;
    __int64 v7;
    __int64 v5;

    v2 = str;
    v8 = a3;
    ptr = (struct Struct_1_t *)a2;
    dst = (__int64 *)a1;
    sub_14002EDF0(0, 72);
    if (result == 0) {
        sub_1400F3326(1, 72);
        xmm0 = _mm_loadu_si128((__m128i *)a2);
        xmm1 = _mm_loadu_si128((__m128i *)a3);
        xmm1 = _mm_xor_si128(xmm1, xmm0);
        _mm_storeu_si128((__m128i *)a1, xmm1);
        xmm0 = _mm_loadu_si128((__m128i *)(a2 + 16));
        xmm1 = _mm_loadu_si128((__m128i *)(a3 + 16));
        xmm1 = _mm_xor_si128(xmm1, xmm0);
        _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
        return 0;
    } else {
        dst2 = (__int64 *)result;
        v_48 = 72;
        v_50 = result;
        result = ptr->field_30;
        *dst2 = result;
        v_58 = 8;
        v6 = 8;
        result = 0;
        if (!(__OFSUB(result, ptr->field_18))) {
            *(dst2 + 8) = 124;
            v_58 = 9;
            a2 = ptr->field_20;
            ptr = ptr->field_28;
            v6 = 9;
            if (ptr >= 64) {
                a1 = rsp + 72;
                dst2 = (__int64 *)a2;
                sub_1400F5F90(a1, 9, ptr);
                a2 = (int *)dst2;
                dst2 = (__int64 *)v_50;
                v6 = v_58;
            }
            a1 = dst2 + v6;
            sub_1400F27F0(a1, a2, ptr);
            v6 += (__int64)ptr;
            v_58 = v6;
        }
        do {
            xmm0 = _mm_setzero_si128();
            _mm_store_si128((__m128i *)&v_70, xmm0);
            _mm_store_si128((__m128i *)&str, xmm0);
            v_20 = v6;
            a1 = rsp + 40;
            a2 = rsp + 96;
            sub_14006BD50(a1, a2, 32, dst2);
            v_68 = 0;
            str = 0;
            v_20 = 12;
            a2 = &off_140117085;
            a1 = rsp + 40;
            sub_14006BFD0(a1, a2, 23, str);
            if (v6 < 0) {
                a1 = &off_140117220;
                v7 = &off_1401172B0;
                sub_1400F37D0(a1, 51, v7);
                return v7;
            }
            if (v6 != 0) {
                result = v6;
                result &= 7;
                if (v6 >= 8) {
                    a1 = 0x7FFFFFFFFFFFFFF8;
                    v6 &= (__int64)a1;
                    a1 = 0;
                    do {
                        *(__int64 *)((__int64)dst2 + (__int64)a1) = 0;
                        *(__int64 *)((__int64)dst2 + (__int64)a1 + 1) = 0;
                        *(__int64 *)((__int64)dst2 + (__int64)a1 + 2) = 0;
                        *(__int64 *)((__int64)dst2 + (__int64)a1 + 3) = 0;
                        *(__int64 *)((__int64)dst2 + (__int64)a1 + 4) = 0;
                        *(__int64 *)((__int64)dst2 + (__int64)a1 + 5) = 0;
                        *(__int64 *)((__int64)dst2 + (__int64)a1 + 6) = 0;
                        *(__int64 *)((__int64)dst2 + (__int64)a1 + 7) = 0;
                        a1 += 8;
                    } while (v6 != a1);
                } else {
                    a1 = 0;
                }
                if (result != 0) {
                    dst2 = (__int64 *)((__int64)dst2 + (__int64)a1);
                    a1 = 0;
                    do {
                        *(__int64 *)((__int64)dst2 + (__int64)a1) = 0;
                        ++a1;
                    } while (result != a1);
                }
            }
            v_28 = 0;
            v_29 = 0;
            v_2a = 0;
            v_2b = 0;
            v_2c = 0;
            v_2d = 0;
            v_2e = 0;
            v_2f = 0;
            v_30 = 0;
            v_31 = 0;
            v_32 = 0;
            v_33 = 0;
            v_34 = 0;
            v_35 = 0;
            v_36 = 0;
            v_37 = 0;
            v_38 = 0;
            v_39 = 0;
            v_3a = 0;
            v_3b = 0;
            v_3c = 0;
            v_3d = 0;
            v_3e = 0;
            v_3f = 0;
            v_40 = 0;
            v_41 = 0;
            v_42 = 0;
            v_43 = 0;
            v_44 = 0;
            v_45 = 0;
            v_46 = 0;
            v_47 = 0;
            result = v_68;
            *(dst + 8) = result;
            result = str;
            *dst = result;
            if (v_48 != 0) {
                dst = (__int64 *)v_50;
                off_140108030(a1);
                a1 = (int *)result;
                a2 = 0;
                v5 = (__int64)dst;
                JUMPOUT(off_140108038);
            }
            return result;
        } while (true);
    }
}