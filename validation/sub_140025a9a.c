// inferred from 5 accesses on `a1`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[17];
    __int64 field_41; // offset 65
};

__int64 sub_140025B36();
__int64 sub_140025B96();

__int64 __fastcall sub_140025A9A(struct Struct_1_t *a1, __int64 a2) {
    int v_8;
    char *dst;
    __int64 *src;
    __int64 v8;
    __int64 v6;
    __int64 v2;
    int v1;
    __int64 v9;
    __int64 v7;
    __int64 v4;
    __int64 *v10;
    __int64 v5;
    __int64 v11;

    if (a1->field_41 == 0) {
        src = (__int64 *)a1;
        v8 = a1->field_10;
        v6 = a1->field_18;
        v2 = a1->field_28;
        v_8 = v6;
        v1 = (v2 > v6) ? 1 : 0;
        v9 = a1->field_20;
        a1 = (v2 < v9) ? 1 : 0;
        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 | v1);
        if ((a1 != 0)) JUMPOUT(0x140025b77);
        v7 = src + 48;
        *dst = v7;
        v4 = *(src + 56);
        v10 = *(src + v4 + 47);
        v5 = v2;
        v5 -= v9;
        v10 = v8 + v9;
        if (v5 > 15) JUMPOUT(0x140025b24);
        a2 = 0;
        if (v5 != 0) {
            do {
                if (*(v10 + a2) == v10) JUMPOUT(0x140025b31);
                ++a2;
            } while (v5 != a2);
            v11 = v5;
        }
        v1 = 0;
        return sub_140025B36();
    } else {
        v1 = 0;
        return sub_140025B96();
    }
}