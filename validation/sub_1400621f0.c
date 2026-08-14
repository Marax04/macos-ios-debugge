// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_140062AF8();
__int64 sub_140062447();
__int64 sub_14006261E();
__int64 sub_14004F470();
__int64 sub_140055430();
__int64 sub_140062B04();

__int64 __fastcall sub_1400621F0(__int64 *a1, size_t *a2, int a3) {
    __int64 rsp;
    int arg_8;
    int v_28;
    int v_30;
    int v_40;
    int v_48;
    int v_58;
    int v_80;
    int v_88;
    int v_90;
    int v_b8;
    int v_c0;
    int v_c8;
    int v_e0;
    char *str;
    char *str2;
    struct Struct_1_t *ptr;
    __int64 v9;
    __int64 result;
    __int64 *src;
    __int64 v2;
    __int64 v6;
    __int64 v7;
    __m128i xmm6;
    struct Struct_2_t *ptr2;
    __m128i xmm0;
    __int64 v5;

    _mm_store_si128((__m128i *)&v_e0, xmm6);
    ptr = (struct Struct_1_t *)a3;
    v9 = a2[3];
    a3 = *a2;
    result = arg_8;
    v_28 = (int)a1;
    if (v9 == 0) {
        if (a3 == 0) JUMPOUT(0x140062512);
        if (result != 0) JUMPOUT(0x14006261e);
        return sub_140062AF8();
    } else {
        if (v9 != 1) {
            a2 = (v9 == result) ? 1 : 0;
            if ((a3 & (__int64)a2) == 0) JUMPOUT(0x140062612);
        } else {
            if (a3 == 0) {
                src = ptr->field_10;
                v2 = ptr->field_18;
                if (v2 == 0) JUMPOUT(0x140062877);
                result = *src;
                v6 = v2 - 1;
                v7 = src + 1;
                ptr->field_10 = v7;
                ptr->field_18 = v6;
                a2 = a1 - 32;
                if (a2 >= 7) JUMPOUT(0x140062858);
                src = rsp + 152;
                xmm6 = _mm_setzero_si128();
                v2 = rsp + 128;
                return sub_140062447();
            } else {
                if (result != 1) {
                    return sub_14006261E();
                }
            }
        }
        ptr2 = ptr->field_10;
        src = ptr->field_18;
        xmm6 = _mm_setzero_si128();
        v2 = rsp + 128;
        do {
            _mm_storeu_si128((__m128i *)str, xmm6);
            v_80 = 1;
            v_88 = 0;
            v_90 = 8;
            ptr->field_10 = ptr2;
            ptr->field_18 = src;
            if (src != 0) {
                a2 = ptr2->field_0;
                result = src - 1;
                a1 = ptr2 + 1;
                ptr->field_10 = a1;
                ptr->field_18 = result;
                if (a2 == 10) {
                    src = (__int64 *)result;
                    ptr2 = (struct Struct_2_t *)a1;
                    sub_14004F470(v2, a2, a3);
                    result = (__int64)src;
                    a1 = (__int64 *)ptr2;
                    src = (__int64 *)result;
                    ptr2 = (struct Struct_2_t *)a1;
                    --v9;
                    if ((v9 == 0)) JUMPOUT(0x140062af8);
                }
                if (a2 == 13) {
                    if (result != 0) {
                        a2 = ptr2->field_1;
                        src -= 2;
                        ptr2 += 2;
                        ptr->field_10 = ptr2;
                        ptr->field_18 = src;
                        if (a2 == 10) {
                            return result;
                        }
                        ptr->field_10 = a1;
                        ptr->field_18 = result;
                    }
                }
            }
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)&v_c8, xmm0);
            str2 = 1;
            v_b8 = 0;
            v_c0 = 8;
            a1 = rsp + 48;
            a2 = rsp + 128;
            sub_140055430(a1, a2, str2, v5);
            result = v_40;
            a1 = (__int64 *)v_58;
            a2 = (size_t *)v_28;
            a2[5] = a1;
            xmm0 = _mm_loadu_si128((__m128i *)&v_48);
            _mm_storeu_si128((__m128i *)(a2 + 24), xmm0);
            xmm0 = _mm_load_si128((__m128i *)&v_30);
            _mm_storeu_si128((__m128i *)a2, xmm0);
            a2[2] = result;
            return sub_140062B04();
        } while (true);
    }
}