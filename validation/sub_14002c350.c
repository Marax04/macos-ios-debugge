// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[24];
    __int64 field_20; // offset 32
};

__int64 sub_14002C460();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14002C350(struct Struct_1_t *a1, __int64 a2, __int64 *a3, __int64 a4) {
    __int64 rsp;
    __int64 v_10;
    int v_18;
    int v_28;
    int v_30;
    int v_8;
    __int64 v10;
    __int64 v2;
    __int64 v3;
    struct Struct_2_t *ptr;
    __int64 result;
    __m128i xmm0;
    __int64 v8;
    __int64 v5;
    __int64 *src;
    __int64 v9;
    __int64 v7;

    v10 = rsp + 32;
    v2 = a1->field_0;
    v2 <<= 1;
    if (v2 != 0) {
        v3 = a1->field_8;
        off_140108030();
        ptr = (struct Struct_2_t *)v2;
        a2 = 0;
        a3 = (__int64 *)v3;
        JUMPOUT(off_140108038);
        v10 = rsp + 80;
        v_8 = -2;
        result = v7;
        v_30 = v7;
        a2 = v10 - 40;
        xmm0 = _mm_loadu_si128((__m128i *)a3);
        _mm_storeu_si128((__m128i *)&v_28, xmm0);
        a3 = a3[2];
        v_18 = (int)a3;
        a3 = ptr->field_20;
        v8 = ptr->field_0;
        v5 = v8;
        v5 = -v5;
        v_10 = (__int64)ptr;
        if (0 /* overflow check on (-v5) */) a4 = ptr;
        sub_14002C460(result, a2, a3, 0);
        v8 <<= 1;
        if (v8 != 0) {
            src = (__int64 *)v_10;
            v9 = *(src + 8);
            v2 = result;
            off_140108030(src);
            ((__int64 (*)())off_140108038)(result, 0, v9);
            result = v2;
        }
        return result;
    } else {
        return result;
    }
}