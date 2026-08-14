// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3326();
__int64 sub_1400F2C50();
__int64 sub_140044F10();
__int64 sub_1400F2E90();

__int64 __fastcall sub_1400F2D20(int *a1, __int64 a2, __int64 a3, __int64 a4) {
    int v_20;
    int v_38;
    int v_40;
    int v_80;
    char *str;
    char *str2;
    struct Struct_1_t *ptr;
    __int64 v6;
    __int64 v5;
    __int64 v4;
    __int64 v2;
    __int64 result;
    __int64 v7;

    a2 += a3;
    if ((a2 < 0)) {
        sub_1400F3326(0);
    } else {
        ptr = (struct Struct_1_t *)a1;
        v6 = v_80;
        v5 = ptr->field_0;
        v4 = v5 + v5;
        if (a2 > v4) v4 = a2;
        a2 = 0;
        a2 = (v6 == 1) ? 1 : 0;
        a2 =  + a2*4 + 4;
        if (v4 <= a2) v4 = a2;
        v2 = ptr->field_8;
        str = (char *)v6;
        v_20 = a4;
        sub_1400F2C50(str2, v5, v2);
        if (str2 != 1) {
            result = v_38;
            ptr->field_8 = result;
            *(__int64 *)ptr = (__int64)(v4);
            return result;
        }
    }
    v7 = v_38;
    sub_1400F3326(v7, v_40);
    ptr = (struct Struct_1_t *)v7;
    sub_140044F10(str);
    return sub_1400F2E90(ptr, str);
}