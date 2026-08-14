__int64 sub_1400095F0();
__int64 sub_1400F6DC0();
__int64 sub_1400F6B10();
__int64 off_140108080();
__int64 off_140108088();
__int64 off_140108090();
extern __int64 off_140034970;
extern __int64 off_140112FC0;
extern __int64 off_14012D098;
extern __int64 off_14012D270;
extern __int64 off_14012D230;
extern __int64 off_14012D220;
extern __int64 off_140003500;
extern __int64 off_140112B98;
extern __int64 off_14012D090;
extern __int64 off_140113B60;

__int64 __fastcall sub_14000EBB0(int a1) {
    int v_10;
    int v_18;
    int v_20;
    int v_8;
    int v_9;
    char *str;
    __int64 v12;
    __int64 v13;
    __int64 result;
    __int64 *v8;
    __int64 *src;
    __int64 v3;
    __int64 *dst;
    __int64 v10;
    __int64 v5;
    __int64 v11;
    __int64 v7;
    __int64 v2;
    __int64 v6;

    v_8 = -2;
    v12 = &off_140034970;
    off_140108080(0, v12);
    v_10 = 0x5000;
    a1 = str - 16;
    off_140108088(a1);
    off_140108090();
    v13 = &off_140112FC0;
    ((__int64 (*)())v6)(src, v13, off_14012D098);
    result = off_14012D270;
    v8 = __readgsqword(88);
    src = v8[(__int64)src];
    v3 = *(src + 96);
    if (v3 == 0) {
        dst = src + 96;
        src = off_14012D230;
        while (src != -1) {
            v3 = src + 1;
            /* cmpxchg %v3, off_14012D230 */;
            *dst = v3;
            off_14012D220 = v3;
            v10 = &off_140003500;
            sub_1400095F0(v10, v3);
            if (a1 != 0) {
                src = (__int64 *)result;
                v_9 = 1;
                v5 = str - 9;
                v_18 = v5;
                result = &off_140112B98;
                v_20 = result;
                v11 = &off_14012D090;
                v7 = &off_140113B60;
                v2 = str - 24;
                sub_1400F6DC0(v11, 0, v2, v7);
                result = (__int64)src;
                return result;
            } else {
                return result;
            }
        }
        sub_1400F6B10(off_14012D090);
        return result;
    }
    return result;
}