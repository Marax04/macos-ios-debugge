// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    char _pad_0[3];
    char field_7; // offset 7
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140030C50();
__int64 sub_140030980();
__int64 sub_140030FE0();
__int64 sub_1400317BB();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_140031620(int *a1, __int64 a2, __int64 a3, __int64 a4) {
    __int64 arg_10;
    int arg_18;
    int arg_20;
    int arg_8;
    int v_3d;
    int v_40;
    int v_44;
    int v_48;
    __int64 v_50;
    int v_58;
    char *dst;
    __int64 v7;
    __int64 *dst2;
    __int64 v5;
    __int64 v2;
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 v6;
    __int64 result;
    __int64 v10;
    __int64 v8;

    arg_20 = -2;
    v7 = a3;
    dst2 = (__int64 *)a1;
    v_58 = 0;
    v_50 = 0;
    v_48 = 7;
    v_44 = 0;
    v_3d = 0;
    v_40 = 1;
    v5 = dst - 88;
    sub_140030C50(a2, v7, v5);
    v2 = v7;
    if ((result & 1) == 0) {
        a1 = dst - 88;
        sub_140030980(a1, v2);
        if (v_58 != 2) JUMPOUT(0x140031797);
        ptr = (struct Struct_1_t *)v_50;
        a1 = (int *)result;
        a1 = (int *)((__int64)(__int64)a1 & 3);
        if (a1 == 1) {
            arg_18 = v2;
            a1 = ptr - 1;
            *dst = a1;
            a1 = *(__int64 *)(ptr - 1);
            arg_8 = (int)a1;
            ptr = ptr->field_7;
            arg_10 = (__int64)ptr;
            ptr = ptr->field_0;
            if (ptr != 0) {
                a1 = (int *)arg_8;
                ((__int64 (*)())ptr)(a1);
            }
            src = (__int64 *)arg_8;
            ptr = (struct Struct_1_t *)arg_10;
            v2 = arg_18;
            if (ptr->field_8 != 0) {
                if (ptr->field_10 >= 17) {
                    src = *(src - 8);
                }
                off_140108030();
                off_140108038(ptr, 0, src);
            }
            off_140108030();
            v6 = *dst;
            off_140108038(ptr, 0, v6);
        }
        result = 1;
        v_58 = a4;
        v_50 = (__int64)ptr;
        v_48 = 0;
        a2 = dst - 88;
        arg_18 = v2;
        sub_140030FE0(v2, a2, 0, 0);
        if ((result & 1) == 0) JUMPOUT(0x1400317c0);
        *(dst2 + 8) = a2;
        *dst2 = ptr;
        v10 = arg_18;
        if (v_58 == 0) JUMPOUT(0x1400317bb);
        dst2 = (__int64 *)v_50;
        off_140108030(0x8000000000000000);
        off_140108038(ptr, 0, dst2);
        return sub_1400317BB();
    } else {
        *(dst2 + 8) = v2;
        v8 = 0x8000000000000000;
        *dst2 = v8;
        return result;
    }
}