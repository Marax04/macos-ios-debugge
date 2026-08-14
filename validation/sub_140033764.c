// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    int field_8; // offset 8
    __int64 field_C; // offset 12
};

__int64 sub_140011760();
__int64 sub_1400F37A0();
__int64 sub_1400338C7();
extern __int64 off_1401125D0;
extern __int64 off_140112578;
extern __int64 off_140112588;

__int64 __fastcall sub_140033764() {
    int arg_18;
    int v_18;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    __int64 v4;
    __int64 v5;
    __int64 v8;
    __int64 result;
    __int64 v6;
    __int64 v2;
    __m128i xmm0;
    __int64 v9;
    __int64 v3;
    struct Struct_1_t *ptr;
    __int64 v10;

    v4 = &off_1401125D0;
    v5 = v10 - 32;
    sub_140011760(v5, v4, v6);
    v8 = v_18;
    if (result == 0) {
        result = v6;
        result &= 3;
        if (result == 1) JUMPOUT(0x1400337f8);
        v6 = 0;
    } else {
        if (v8 == 0) {
            v2 = &off_140112578;
            v_50 = v2;
            v_48 = 1;
            v_40 = 8;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)&v_38, xmm0);
            v9 = &off_140112588;
            v3 = v10 - 80;
            sub_1400F37A0(v3, v9);
            return sub_1400338C7();
        }
    }
    ptr = (struct Struct_1_t *)arg_18;
    ptr->field_8 = ptr->field_8 - 1;
    if (!((ptr->field_8 != 0))) {
        *(__int64 *)ptr = (__int64)(0);
        result = 0;
        { __int64 __xchg_tmp = ptr->field_C; ptr->field_C = result; result = __xchg_tmp; };
        if (result == 2) JUMPOUT(0x1400338f2);
    }
    if (v8 != 0) JUMPOUT(0x14003386a);
    return result;
}