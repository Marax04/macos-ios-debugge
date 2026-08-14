// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14006A301();

__int64 __fastcall sub_14006A240(int *a1,struct Struct_1_t *a2) {
    int v_24;
    int v_25;
    __int64 *src;
    int v1;
    __int64 v3;
    __int64 v4;

    src = *a1;
    v1 = *src;
    if ((((__int64 *)a2)[2] & 24) == 0) {
        v3 = a2->field_0;
        a2 = a2->field_8;
        v4 = ((__int64 *)a2)[4];
        JUMPOUT(v4);
    } else {
        v_24 = 0;
        if (v1 < 128) {
            v_24 = v1;
            v4 = 1;
            return sub_14006A301();
        }
    }
    a1 = (int *)v1;
    a1 = (int *)((__int64)(__int64)a1 & 63);
    a1 = (int *)((__int64)(__int64)a1 | 128);
    v4 = v1;
    v4 >>= 6;
    if (v1 >= 0x800) JUMPOUT(0x14006a2ac);
    v4 |= 192;
    v_24 = v4;
    v_25 = (int)a1;
    v4 = 2;
    return sub_14006A301();
}