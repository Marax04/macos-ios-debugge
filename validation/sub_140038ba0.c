// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14002DFB0();
__int64 sub_140038D9F();
__int64 sub_140038C40();
extern __int64 off_14012D270;
extern __int64 off_140037740;

__int64 __fastcall sub_140038BA0(__int64 *a1, __int64 a2) {
    __int64 v_8;
    char *dst;
    __int64 *dst2;
    __int64 *src;
    __int64 *v5;
    struct Struct_1_t *ptr;
    __int64 v7;
    __m128i xmm0;
    __int64 *dst3;
    __int64 v6;

    *dst = -2;
    dst2 = a1;
    src = off_14012D270;
    v5 = __readgsqword(88);
    src = v5[(__int64)src];
    ptr = src + 112;
    src = *(src + 120);
    if (src != 1) {
        if (src != 2) {
            v7 = &off_140037740;
            sub_14002DFB0(ptr, v7);
            ptr->field_8 = 1;
        } else {
            *dst2 = 0;
            *(dst2 + 8) = 8;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)(dst2 + 16), xmm0);
            return sub_140038D9F();
        }
    }
    dst3 = ptr->field_0;
    v_8 = (__int64)dst3;
    *(__int64 *)ptr = (__int64)(0);
    if (dst3 == 0) JUMPOUT(0x140038c3e);
    *dst3 = *dst3 + 1;
    if ((*dst3 <= 0)) JUMPOUT(0x140038dc7);
    v6 = ptr->field_0;
    return sub_140038C40();
}