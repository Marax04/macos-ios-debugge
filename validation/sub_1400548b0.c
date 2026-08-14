// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[48];
    __int64 field_30; // offset 48
    char _pad_30[8];
    __int64 field_40; // offset 64
};

__int64 sub_1400549AD();
__int64 sub_140054A89();

__int64 __fastcall sub_1400548B0(struct Struct_1_t *a1, __int64 *a2, __int64 a3) {
    __int64 *dst;
    __int64 v6;
    __int64 v5;
    __int64 v3;
    __int64 v4;
    __int64 v2;
    __int64 v9;
    __int64 v1;
    __int64 v8;

    dst = (__int64 *)a1;
    a1->field_30 = a1->field_30 + a3;
    v6 = a1->field_40;
    if (v6 == 0) {
        v5 = 0;
        return sub_1400549AD();
    } else {
        v5 = 8;
        v5 -= v6;
        v3 = a3;
        if (v5 < a3) a3 = v5;
        if (a3 < 4) {
            v4 = 0;
            v2 = 0;
            v9 = v4;
            v9 |= 1;
            if (v9 < v3) {
                v1 = *(a2 + v4);
                a1 =  + v4*8;
                v1 <<= (__int64)a1;
                v2 |= v1;
                v4 |= 2;
            }
        } else {
            v2 = *a2;
            v4 = 4;
            v8 = v4;
            v8 |= 1;
            if (v8 < v3) {
                return v8;
            } else {
            }
        }
        if (v4 < v3) {
            v3 = *(a2 + v4);
            v4 <<= 3;
            a1 = (struct Struct_1_t *)v4;
            v3 <<= (__int64)a1;
            v2 |= v3;
        }
        a1 =  + v6*8;
        v2 <<= (__int64)a1;
        v2 |= *(dst + 56);
        *(dst + 56) = v2;
        if (a3 >= v5) JUMPOUT(0x140054959);
        v6 += a3;
        return sub_140054A89();
    }
}