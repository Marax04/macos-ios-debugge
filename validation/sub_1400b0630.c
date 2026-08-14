__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400B06D9();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400B0630(int *a1, __int64 a2) {
    __int64 result;
    __int64 v4;
    __int64 v3;
    __int64 v2;
    __int64 v5;
    __int64 v8;
    __int64 v9;
    __int64 v6;
    __int64 v7;

    if (a2 < 0) {
        sub_1400F3360();
    }
    if ((0 /* unresolved: flags == */)) {
        result = 1;
    } else {
        v4 = (__int64)a1;
        v3 = a2;
        sub_14002EDF0(8);
        if (result == 0) {
            sub_1400F3326(1, v3);
            v2 = (__int64)a1;
            v5 = *(a1 + 8);
            v8 = a1[2];
            if (v8 == 0) JUMPOUT(0x1400b06f3);
            v9 = v5 + 8;
            v6 = off_140108030;
            v7 = off_140108038;
            return sub_1400B06D9();
        } else {
            a2 = v3;
            a1 = (int *)v4;
        }
    }
    *a1 = a2;
    *(a1 + 8) = result;
    a1[2] = a2;
    return result;
}