// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14001364A();

int __fastcall sub_140013590(int *a1,struct Struct_1_t *a2) {
    int v_3;
    int v_4;
    int v1;
    __int64 v2;
    __int64 v3;

    v1 = *a1;
    if ((((__int64 *)a2)[2] & 24) == 0) {
        v2 = a2->field_0;
        a2 = a2->field_8;
        v3 = ((__int64 *)a2)[4];
        JUMPOUT(v3);
    } else {
        v_4 = 0;
        if (v1 < 128) {
            v_4 = v1;
            v3 = 1;
            return sub_14001364A();
        }
    }
    a1 = (int *)v1;
    a1 = (int *)((__int64)(__int64)a1 & 63);
    a1 = (int *)((__int64)(__int64)a1 | 128);
    v3 = v1;
    v3 >>= 6;
    if (v1 >= 0x800) JUMPOUT(0x1400135fc);
    v3 |= 192;
    v_4 = v3;
    v_3 = (int)a1;
    v3 = 2;
    return sub_14001364A();
}