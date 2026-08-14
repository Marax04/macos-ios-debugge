// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 off_140108378();
__int64 off_140108380();
__int64 off_140108390();
__int64 off_140108048();
extern __int64 off_140113068;

__int64 __fastcall sub_140040B50(int *a1, int a2) {
    int arg_10;
    int arg_18;
    int arg_20;
    int arg_28;
    int arg_30;
    int arg_40;
    int arg_58;
    int arg_60;
    int arg_8;
    int v_10;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    char *str;
    __int64 v2;
    struct Struct_1_t *ptr;
    __m128i xmm6;
    __m128i xmm0;
    __int64 v11;
    __int64 v10;
    __int64 v5;
    __int64 v6;
    __int64 result;
    __int64 v4;
    __int64 v8;
    __int64 v7;
    __int64 v9;

    _mm_store_si128((__m128i *)&arg_60, xmm6);
    v2 = a2;
    ptr = (struct Struct_1_t *)a1;
    xmm6 = _mm_setzero_si128();
    _mm_store_si128((__m128i *)&arg_40, xmm6);
    _mm_store_si128((__m128i *)&arg_10, xmm6);
    _mm_store_si128((__m128i *)&arg_30, xmm6);
    _mm_store_si128((__m128i *)&arg_20, xmm6);
    arg_10 = 48;
    xmm0 = _mm_loadu_si128((__m128i *)&off_140113068);
    _mm_store_si128((__m128i *)&v_10, xmm0);
    v11 = str - 16;
    arg_20 = v11;
    arg_58 = 0;
    v_28 = 32;
    v_20 = 3;
    a1 = str + 88;
    v10 = 0x80100000;
    v5 = str + 16;
    v6 = str + 64;
    off_140108378(a1, 0x80100000, v5, v6);
    if (result < 0) {
        off_140108380(result);
        result <<= 32;
        result |= 2;
        ptr->field_8 = result;
        *(__int64 *)ptr = (__int64)(1);
    } else {
        v4 = arg_58;
        _mm_store_si128((__m128i *)&v_10, xmm6);
        arg_20 = v11;
        arg_18 = v4;
        arg_8 = -500000;
        arg_58 = 0;
        result = v2;
        a1 = result + 1;
        if (result != 0) a2 = v10;
        result = str + 8;
        v_68 = result;
        v_20 = (int)a1;
        v_60 = 0x10000;
        v_58 = 0x10000;
        v_50 = 1;
        v_48 = 0;
        v_40 = 0;
        v_38 = 0;
        v_30 = 0;
        v_28 = 2;
        a1 = str + 88;
        v2 = str + 16;
        v8 = str + 64;
        off_140108390(a1, 0x40100000, v2, v8);
        if (result < 0) {
            off_140108380(result);
            result <<= 32;
            result |= 2;
            ptr->field_8 = result;
            *(__int64 *)ptr = (__int64)(1);
        } else {
            v10 = arg_58;
            arg_18 = v10;
            arg_28 |= 2;
            arg_58 = 0;
            result = 0x40100080;
            if (v2 != 0) a2 = result;
            v_28 = 96;
            v_20 = 0;
            a1 = str + 88;
            v7 = str + 16;
            v9 = str + 64;
            off_140108378(a1, 0x80100000, v7, v9);
            if (result < 0) {
                off_140108380(result);
                result <<= 32;
                result |= 2;
                ptr->field_8 = result;
                *(__int64 *)ptr = (__int64)(1);
                off_140108048(v10);
            } else {
                result = arg_58;
                ptr->field_8 = v10;
                ptr->field_10 = result;
                *(__int64 *)ptr = (__int64)(0);
            }
        }
        off_140108048(v4);
    }
    xmm6 = _mm_load_si128((__m128i *)&arg_60);
    return result;
}