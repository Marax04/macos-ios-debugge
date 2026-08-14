// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    int field_0; // offset 0
    char _pad_0[3];
    __int64 field_7; // offset 7
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140011760();
__int64 sub_14000ECF0();
__int64 sub_1400F37A0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140112600;
extern __int64 off_140112578;
extern __int64 off_140112588;

__int64 __fastcall sub_140028050(int a1, __int64 *a2) {
    __int64 rsp;
    __int64 v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_8;
    __int64 v8;
    __int64 v3;
    struct Struct_2_t *ptr;
    struct Struct_3_t *ptr2;
    struct Struct_1_t *result;
    __int64 v7;
    __m128i xmm0;

    v8 = rsp + 128;
    v_8 = -2;
    v3 = *(a2 + 8);
    if (v3 != 1) {
    }
    v_30 = a1;
    v_28 = 0;
    a2 = &off_140112600;
    a1 = v8 - 48;
    sub_140011760(a1, a2, a2);
    a1 = (int)result;
    ptr = (struct Struct_2_t *)v_28;
    if (a1 == 0) {
        a1 = (int)result;
        a1 &= 3;
        if (a1 == 1) {
            a1 = ptr - 1;
            v_20 = a1;
            a1 = *(__int64 *)(ptr - 1);
            v_18 = a1;
            ptr = ptr->field_7;
            v_10 = (__int64)ptr;
            ptr = ptr->field_0;
            if (ptr != 0) {
                a1 = v_18;
                ((__int64 (*)())ptr)(a1);
            }
            a1 = v_18;
            ptr2 = (struct Struct_3_t *)v_10;
            if (ptr2->field_8 != 0) {
                a2 = ptr2->field_10;
                sub_14000ECF0(a1, a2);
            }
            off_140108030();
            off_140108038(ptr2, 0, v_20);
            result = 0;
            return (__int64)result;
        } else {
            result = 0;
            return (__int64)result;
        }
    } else {
        if (ptr == 0) {
            v7 = &off_140112578;
            v_60 = v7;
            v_58 = 1;
            v_50 = 8;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)&v_48, xmm0);
            a2 = &off_140112588;
            a1 = v8 - 96;
            sub_1400F37A0(a1, a2);
            v_10 = (__int64)a2;
            v8 = a2 + 128;
            a1 = v_18;
            result = (struct Struct_1_t *)v_10;
            if (result->field_8 != 0) {
                result = (struct Struct_1_t *)v_10;
                a2 = result->field_10;
                sub_14000ECF0(a1, a2);
            }
            off_140108030();
            return off_140108038(result, 0, v_20);
        } else {
            return (__int64)result;
        }
    }
}