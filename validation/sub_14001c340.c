__int64 sub_14001C478();

__int64 __fastcall sub_14001C340(size_t a1, __int64 a2, int a3, __int64 a4) {
    __int64 rsp;
    __int64 v3;
    __int64 v2;
    __int64 v4;
    __int64 v5;
    __int64 result;
    __int64 xmm6;

    /* vmovdqa %xmm6, (%rsp) */;
    /* vmovdqa (%a1), %ymm0 */;
    /* vpcmpeqb -32(%a3), %ymm0, %ymm1 */;
    /* vpmovmskb %ymm1, %result */;
    if (result == 0) {
        v3 = a3;
        v3 -= a2;
        v2 = a3;
        v2 &= -32;
        a4 = (v3 > 127) ? 1 : 0;
        v4 = a2 + 128;
        v5 = (v2 >= v4) ? 1 : 0;
        v5 &= a4;
        if (v5 == 1) {
            result = a3;
            result &= 31;
            a3 -= v2;
            a3 -= 128;
            do {
                /* vpcmpeqb (%a3), %ymm0, %ymm1 */;
                /* vpcmpeqb 32(%a3), %ymm0, %ymm2 */;
                /* vpcmpeqb 64(%a3), %ymm0, %ymm3 */;
                /* vpcmpeqb 96(%a3), %ymm0, %ymm4 */;
                /* vpor %ymm2, %ymm1, %ymm5 */;
                /* vpor %ymm4, %ymm3, %ymm6 */;
                /* vpor %ymm5, %ymm6, %ymm5 */;
                /* vpmovmskb %ymm5, %result */;
                if (result != 0) JUMPOUT(0x14001c437);
                v2 = a3 - 128;
                a3 = v2;
            } while ((a3 >= v4));
            v2 += 128;
        }
        v5 = a2 + 32;
        do {
            if (v2 < v5) JUMPOUT(0x14001c40d);
            /* vpcmpeqb -32(%v2), %ymm0, %ymm1 */;
            v2 -= 32;
            /* vpmovmskb %ymm1, %a3 */;
        } while (a3 == 0);
        a2 = 31 - __builtin_clz(a3);
        return sub_14001C478();
    } else {
        a3 -= 32;
        a2 = 31 - __builtin_clz(result);
        a2 += a3;
        result = 1;
        /* vmovaps (%rsp), %xmm6 */;
        /* vzeroupper  */;
        return result;
    }
}