// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140037818();

__int64 __fastcall sub_14003784E(int a1, __int64 a2) {
    int v_10;
    __int64 v_18;
    int v_20;
    int v_28;
    __int64 v4;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 v2;
    __int64 v1;
    __int64 v9;
    __int64 v8;
    __int64 *src;

    ((__int64 (*)())v1)(a1, 0);
    if (v9 == 0) {
        return 0;
    } else {
        v_10 = v9;
        v_20 = v8;
        v_28 = v8;
        v_18 = (__int64)src;
        v4 = *src;
        if (v4 != 0) {
            ((__int64 (*)())v4)(v_10);
        }
        ptr = (struct Struct_1_t *)v_18;
        v3 = v_20;
        if (ptr->field_8 == 0) JUMPOUT(0x140037824);
        if (ptr->field_10 >= 17) JUMPOUT(0x140037810);
        v2 = v_10;
        return sub_140037818();
    }
}