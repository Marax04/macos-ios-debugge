// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F6940();
__int64 sub_1400F3326();
__int64 sub_1400F6E19();
extern __int64 off_140108260;
extern __int64 off_140108060;

__int64 __fastcall sub_1400F6D50(struct Struct_1_t *a1) {
    __int64 rsp;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_8;
    __int64 *dst;
    __int64 *dst2;
    __int64 v2;
    __int64 v7;
    __int64 v4;
    __int64 v5;
    __int64 v9;
    __int64 *src;
    __int64 result;
    __int64 v11;
    __int64 v12;
    __int64 v8;
    __int64 v6;

    dst = rsp + 80;
    dst2 = (__int64 *)a1;
    v2 = a1->field_0;
    v7 = v2 + v2;
    v4 = 4;
    if (v7 >= 5) v4 = v7;
    v5 = a1->field_8;
    v_28 = 56;
    v_20 = 8;
    v9 = dst - 24;
    sub_1400F6940(v9, v2, v5, v4);
    if (v_18 == 1) {
        src = (__int64 *)v_10;
        v2 = v_8;
        sub_1400F3326(src, v2);
        dst = rsp + 96;
        *dst = -2;
        dst2 = (__int64 *)v6;
        v4 = v5;
        result = *src;
        if (v2 == 0) JUMPOUT(0x1400f6ebc);
        v11 = off_140108260;
        v12 = off_140108060;
        return sub_1400F6E19();
    } else {
        v8 = v_10;
        *(dst2 + 8) = v8;
        *dst2 = v4;
        return result;
    }
}