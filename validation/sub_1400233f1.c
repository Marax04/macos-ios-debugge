// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140023483();
__int64 sub_140023456();

int __fastcall sub_1400233F1(__int64 *a1,struct Struct_1_t *a2) {
    __int64 *dst;
    __int64 *src;
    __int64 v7;
    __int64 i;
    int v1;
    int v2;
    int v3;

    dst = (__int64 *)a2;
    src = a2->field_0;
    v7 = a2->field_8;
    i = ((__int64 *)a2)[2];
    if (i < v7) {
        if (*(src + i) == 95) {
            ++i;
            *(dst + 16) = i;
            *(a1 + 8) = 0;
            return sub_140023483();
        }
    }
    v1 = 0;
    v2 = 62;
    if (i >= v7) JUMPOUT(0x140023487);
    a2 = *(src + i);
    if (a2 == 95) JUMPOUT(0x14002346f);
    v3 = a2 - 48;
    if (v3 < 10) JUMPOUT(0x140023458);
    v3 = a2 - 97;
    if (v3 >= 26) JUMPOUT(0x14002344a);
    a2 += 169;
    return sub_140023456();
}