// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3510();

__int64 __fastcall sub_1400D5BD0(struct Struct_1_t *a1, int a2, size_t a3, int a4) {
    int v_90;
    __int64 v4;
    __int64 result;
    int v11;
    __int64 v5;
    __int64 v2;
    __int64 *src;
    __int64 *src2;
    __int64 v7;
    __int64 *src3;
    __int64 *dst;
    __int64 v8;

    v4 = v_90;
    result = v4;
    result = (result != v4) ? 1 : 0;
    ++result;
    v11 = result;
    if (v4 == 0) v11 = v4;
    result = v11;
    result <<= 6;
    a2 <<= 3;
    a2 |= result;
    a2 |= 4;
    v5 = a1->field_0;
    v2 = ((__int64 *)a1)[2];
    if (v2 == v5) {
        src = (__int64 *)a1;
        src2 = (__int64 *)a3;
        v7 = a4;
        src3 = (__int64 *)a2;
        sub_1400F3510(a1, a2, a3, a4);
        v5 = *src;
    }
    dst = a1->field_8;
    *(dst + v2) = a2;
    v7 = v2 + 1;
    ((__int64 *)a1)[2] = (__int64)(v7);
    a4 <<= 6;
    a3 <<= 3;
    a3 |= a4;
    a3 |= 4;
    if (v7 == v5) {
        src3 = (__int64 *)a1;
        src3 = (__int64 *)a3;
        sub_1400F3510(src3, v7, src2);
        dst = *(src3 + 8);
    }
    *(dst + v2 + 1) = a3;
    v8 = v2 + 2;
    ((__int64 *)a1)[2] = (__int64)(v8);
    if (v11 != 0) {
        a3 = v11;
        if (v11 != 1) {
            v4 = a1->field_0;
            v4 -= v8;
            if (v4 <= 3) JUMPOUT(0x1400d5cdc);
            *(dst + v8) = v4;
            v8 += 4;
            v2 = v8;
        } else {
            if (v8 == a1->field_0) {
                src2 = (__int64 *)a1;
                sub_1400F3510(src2, v8, src3);
                a1 = (struct Struct_1_t *)src2;
                dst = *(src2 + 8);
            }
            *(dst + v2 + 2) = v4;
            v2 += 3;
        }
        ((__int64 *)a1)[2] = (__int64)(v2);
    }
    return result;
}