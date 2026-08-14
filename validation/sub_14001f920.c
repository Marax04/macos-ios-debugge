// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140011760();
__int64 sub_1400F37A0();
__int64 sub_14000ECF0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140110530;
extern __int64 off_140112578;
extern __int64 off_1401105D0;

__int64 __fastcall sub_14001F920(int a1, __int64 *a2) {
    int v_28;
    int v_38;
    int v_40;
    int v_48;
    char *str;
    char *str2;
    __int64 v5;
    __int64 v8;
    __int64 *src;
    __m128i xmm0;
    __int64 v3;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v7;
    __int64 result;

    v5 = *(a2 + 8);
    if (v5 != 1) {
    }
    str = (char *)a1;
    v_28 = 0;
    v8 = &off_140110530;
    sub_140011760(str, v8, v8);
    a1 = result;
    src = (__int64 *)v_28;
    if (a1 != 0) {
        if (src == 0) {
            src = &off_140112578;
            str2 = (char *)src;
            v_38 = 1;
            v_40 = 8;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)&v_48, xmm0);
            v8 = &off_1401105D0;
            sub_1400F37A0(str2, v8);
            a1 = result;
            a1 &= 3;
            if (a1 == 1) {
                v3 = *(src - 1);
                ptr = *(src + 7);
                v8 = ptr->field_0;
                if (v8 != 0) {
                    v4 = (__int64)src;
                    ((__int64 (*)())v8)(v3, v8);
                    src = (__int64 *)v4;
                }
                --src;
                v7 = (__int64)src;
                if (ptr->field_8 != 0) {
                    v8 = ptr->field_10;
                    sub_14000ECF0(v3, v8);
                }
                off_140108030();
                off_140108038(src, 0, v7);
            }
            result = 0;
        }
        return result;
    }
    return result;
}