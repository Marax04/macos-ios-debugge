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

__int64 sub_14002DC40();
__int64 sub_14002C460();
__int64 sub_140045884();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400457B0(struct Struct_1_t *a1, __int64 a2, __int64 *a3, __int64 a4) {
    __int64 rsp;
    __int64 v_10;
    int v_18;
    int v_28;
    int v_30;
    int v_8;
    __int64 v9;
    __int64 v1;
    __int64 v2;
    struct Struct_2_t *ptr;
    __int64 v3;
    __int64 v7;
    __m128i xmm0;
    __int64 v8;
    __int64 v4;
    __int64 v6;

    v9 = rsp + 32;
    v1 = a1->field_0;
    v1 = -v1;
    if ((0 /* overflow check on (-v1) */)) {
        a1 += 8;
        return sub_14002DC40();
    } else {
        if ((0 /* unresolved: flags < */)) {
            v2 = a1->field_8;
            off_140108030(a1);
            ptr = (struct Struct_2_t *)v1;
            a2 = 0;
            a3 = (__int64 *)v2;
            JUMPOUT(off_140108038);
            v9 = rsp + 80;
            v_8 = -2;
            v3 = a2;
            v_30 = a2;
            v7 = v9 - 40;
            xmm0 = _mm_loadu_si128((__m128i *)a3);
            _mm_storeu_si128((__m128i *)&v_28, xmm0);
            a3 = a3[2];
            v_18 = (int)a3;
            a3 = ptr->field_20;
            v8 = ptr->field_0;
            v4 = v8;
            v4 = -v4;
            v_10 = (__int64)ptr;
            if (0 /* overflow check on (-v4) */) a4 = ptr;
            sub_14002C460(v3, v7, a3, 0);
            v8 = -v8;
            if ((0 /* overflow check on (-v8) */)) JUMPOUT(0x140045866);
            v6 = v_10;
            v6 += 8;
            sub_14002DC40(v6);
            return sub_140045884();
        } else {
            return v6;
        }
    }
}