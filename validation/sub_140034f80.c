__int64 sub_140028050();
__int64 off_1401080D0();
extern __int64 off_14011220E;
extern __int64 off_14012D270;
extern __int64 off_14012D230;
extern __int64 off_140028030;
extern __int64 off_140018400;
extern __int64 off_140112E58;

__int64 __fastcall sub_140034F80(int a1, __int64 *a2) {
    __int64 rsp;
    int arg_20;
    int arg_24;
    int arg_28;
    __int64 v_10;
    int v_18;
    __int64 v_20;
    int v_28;
    int v_30;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int str;
    char *dst;
    __int64 *src;
    __int64 result;
    __int64 *v9;
    __int64 v3;
    __int64 v4;
    __int64 v5;
    __int64 v7;
    __int64 v8;
    __int64 v10;

    arg_28 = -2;
    src = &off_14011220E;
    if (a1 != 0) src = a1;
    if (rsp != 0) a1 = a2;
    v_10 = (__int64)src;
    str = a1;
    off_1401080D0(9);
    if (result == 0) {
        result = off_14012D270;
        v9 = __readgsqword(88);
        src = v9[(__int64)src];
        a1 = *(src + 96);
        if (a1 == 0) {
            a2 = src + 96;
            v3 = off_14012D230;
            do {
                if (v3 == -1) JUMPOUT(0x14003510d);
                a1 = v3 + 1;
                /* cmpxchg %a1, off_14012D230 */;
            } while ((0 /* unresolved: flags != */));
            *a2 = a1;
        }
    } else {
        a1 = result;
    }
    *dst = a1;
    arg_20 = 0;
    arg_24 = 0;
    v4 = dst - 16;
    v_30 = v4;
    v5 = &off_140028030;
    v_28 = v5;
    v_20 = (__int64)dst;
    v7 = &off_140018400;
    v_18 = v7;
    v8 = &off_140112E58;
    v_60 = v8;
    v_58 = 3;
    v_40 = 0;
    result = dst - 48;
    v_50 = result;
    v_48 = 2;
    v10 = dst + 32;
    a2 = dst - 96;
    sub_140028050(v10, a2);
    a1 = result;
    a1 &= 3;
    if (a1 == 1) JUMPOUT(0x14003509d);
    return result;
}