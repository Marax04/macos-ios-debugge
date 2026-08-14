// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140038D9F();
extern __int64 off_140108258;
extern __int64 off_14012D270;

__int64 __fastcall sub_140038B80(struct Struct_1_t *a1, __int64 a2) {
    char *dst;
    __int64 *result;
    __int64 *dst2;
    __int64 *v4;
    __int64 v2;
    __m128i xmm0;

    a1->field_8 = a1->field_8 - 1;
    if (!((a1->field_8 != 0))) {
        a1 = a1->field_0;
        result = 1;
        result = _InterlockedExchange64(&a1[5], result);
        if (result == 255) {
            a1 += 40;
            JUMPOUT(off_140108258);
            *dst = -2;
            dst2 = (__int64 *)a1;
            result = off_14012D270;
            v4 = __readgsqword(88);
            result = v4[(__int64)result];
            v2 = result + 112;
            result = *(result + 120);
            if (result == 1) JUMPOUT(0x140038c1c);
            if (result != 2) JUMPOUT(0x140038c09);
            *dst2 = 0;
            *(dst2 + 8) = 8;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)(dst2 + 16), xmm0);
            return sub_140038D9F();
        }
    }
    return (__int64)result;
}