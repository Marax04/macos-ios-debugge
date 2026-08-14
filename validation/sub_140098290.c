// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140098290(__int64 *a1,struct Struct_1_t *a2) {
    __int64 result;
    __m128i xmm0;
    __int64 v3;
    __int64 v2;

    result = a2->field_10;
    a1[2] = result;
    xmm0 = _mm_loadu_si128((__m128i *)a2);
    _mm_storeu_si128((__m128i *)a1, xmm0);
    if (a2->field_18 != 0) {
        v3 = a2->field_20;
        off_140108030();
        v2 = result;
        a2 = 0;
        JUMPOUT(off_140108038);
    }
    return result;
}