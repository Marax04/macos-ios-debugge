__int64 sub_140040259();
extern __int64 off_140121CC8;

__int64 __fastcall sub_140040150(int *a1, int a2) {
    int arg_a0;
    __int64 v1;
    __int64 *src;

    arg_a0 = -2;
    v1 = *a1;
    src = &off_140121CC8;
    v1 = *(src + v1*4);
    v1 += (__int64)src;
    JUMPOUT(v1);
    return sub_140040259();
}