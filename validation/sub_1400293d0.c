// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400F2808();
__int64 sub_140011760();
__int64 sub_1400297DB();
__int64 off_1401080D0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140113F38;
extern __int64 off_14012D270;
extern __int64 off_14012D230;
extern __int64 off_140028030;
extern __int64 off_140018400;
extern __int64 off_140027F90;
extern __int64 off_140113F88;
extern __int64 off_140112630;

__int64 __fastcall sub_1400293D0(int *a1, __int64 *a2, int a3) {
    int arg_10;
    int arg_1a8;
    int arg_1b0;
    int arg_1b8;
    int arg_1c0;
    int arg_1c8;
    int arg_1d8;
    int arg_1e0;
    int arg_1e8;
    int arg_1f0;
    int arg_1f8;
    int arg_200;
    int arg_208;
    int arg_210;
    __int64 arg_220;
    int arg_228;
    __int64 arg_230;
    int arg_238;
    __int64 arg_240;
    __int64 arg_248;
    int arg_250;
    int arg_258;
    int arg_260;
    int arg_268;
    __int64 arg_270;
    int arg_278;
    int arg_280;
    __int64 arg_288;
    __int64 arg_290;
    __int64 arg_298;
    int arg_2a0;
    int arg_48;
    int arg_60;
    int arg_7;
    int arg_8;
    int v_1;
    int str;
    __int64 *v_0;
    char *str2;
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 v4;
    __int64 v2;
    __int64 v7;
    __int64 v8;
    __int64 v5;
    __int64 v6;

    arg_2a0 = -2;
    ptr = (struct Struct_1_t *)a1;
    src = &off_140113F38;
    if (a2 != 0) src = a2;
    if (a2 != 0) a1 = a3;
    arg_220 = (__int64)src;
    arg_228 = (int)a1;
    off_1401080D0(9);
    if (src == 0) {
        src = off_14012D270;
        a1 = __readgsqword(88);
        src = v_0[(__int64)src];
        a1 = (int *)arg_60;
        if (a1 == 0) {
            a2 = src + 96;
            src = off_14012D230;
            do {
                if (src == -1) JUMPOUT(0x140029897);
                a1 = src + 1;
                /* cmpxchg %(__int64)a1, off_14012D230 */;
            } while ((0 /* unresolved: flags != */));
            *a2 = a1;
        }
    } else {
        a1 = (int *)src;
    }
    arg_280 = (int)a1;
    v4 = str2 - 88;
    sub_1400F2808(v4, 0, 512);
    arg_1d8 = v4;
    arg_1e0 = 512;
    arg_1e8 = 0;
    v2 = ptr->field_0;
    v4 = ptr->field_8;
    src = str2 + 544;
    arg_230 = (__int64)src;
    v7 = &off_140028030;
    arg_238 = v7;
    src = str2 + 640;
    arg_240 = (__int64)src;
    src = &off_140018400;
    arg_248 = (__int64)src;
    arg_250 = v2;
    v8 = &off_140027F90;
    arg_258 = v8;
    arg_260 = v4;
    arg_268 = v7;
    v5 = &off_140113F88;
    arg_1a8 = v5;
    arg_1b0 = 5;
    arg_1c8 = 0;
    v6 = str2 + 560;
    arg_1b8 = v6;
    arg_1c0 = 4;
    src = str2 + 472;
    arg_270 = (__int64)src;
    arg_278 = 0;
    a2 = &off_140112630;
    a1 = str2 + 624;
    a3 = str2 + 424;
    sub_140011760(a1, a2, a3);
    a1 = (int *)arg_278;
    if (src == 0) JUMPOUT(0x14002974c);
    if (a1 == 0) JUMPOUT(0x14002989c);
    src = (__int64 *)a1;
    src = (__int64 *)((__int64)(__int64)src & 3);
    if (src == 1) {
        src = a1 - 1;
        arg_288 = (__int64)src;
        src = (__int64 *)v_1;
        arg_298 = (__int64)src;
        src = (__int64 *)arg_7;
        arg_290 = (__int64)src;
        src = *src;
        if (src != 0) {
            a1 = (int *)arg_298;
            ((__int64 (*)())src)(a1);
        }
        src = (__int64 *)arg_298;
        a1 = (int *)arg_290;
        if (arg_8 != 0) {
            if (a1[2] >= 17) {
                src = (__int64 *)str;
                arg_298 = (__int64)src;
            }
            off_140108030(a1);
            a3 = arg_298;
            off_140108038(src, 0, a3);
        }
        off_140108030();
        a3 = arg_288;
        off_140108038(src, 0, a3);
    }
    a1 = ptr->field_10;
    src = ptr->field_18;
    src = (__int64 *)arg_48;
    a2 = str2 + 544;
    arg_230 = (__int64)a2;
    arg_238 = v7;
    a2 = str2 + 640;
    arg_240 = (__int64)a2;
    a2 = &off_140018400;
    arg_248 = (__int64)a2;
    arg_250 = v2;
    arg_258 = v8;
    arg_260 = v4;
    arg_268 = v7;
    arg_1f0 = v5;
    arg_1f8 = 5;
    arg_210 = 0;
    arg_200 = v6;
    arg_208 = 4;
    a2 = str2 + 496;
    ((__int64 (*)())src)(a1, a2);
    a1 = (int *)src;
    a1 = (int *)((__int64)(__int64)a1 & 3);
    if (a1 != 1) JUMPOUT(0x1400297ef);
    a1 = (int *)src;
    --src;
    arg_290 = (__int64)src;
    src = (__int64 *)v_1;
    arg_298 = (__int64)src;
    src = (__int64 *)arg_7;
    arg_288 = (__int64)src;
    src = *src;
    if (src != 0) {
        a1 = (int *)arg_298;
        ((__int64 (*)())src)(a1);
    }
    v4 = arg_298;
    src = (__int64 *)arg_288;
    if (arg_8 == 0) JUMPOUT(0x1400297d4);
    ptr = (struct Struct_1_t *)arg_290;
    if (arg_10 >= 17) {
        v4 = str;
    }
    off_140108030();
    off_140108038(src, 0, v4);
    return sub_1400297DB();
}