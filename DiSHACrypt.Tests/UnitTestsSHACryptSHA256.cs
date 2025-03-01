namespace DiSHACrypt.Tests;

public class UnitTestsSHACryptSHA256 : UnitTestsSHACryptBase<SHACryptSHA256>
{
    [Theory]
    [InlineData("Cv4qSGQjH/sWFKsF2Knwpy7JxEN7ZcFQUUXbkqHE35A", "", "~", null)]
    [InlineData("w.ZhDC63hfgfi04Pj6Nld5zzVyrzSJmQyjCBvTxBVt5", "", "YV84^nX4,i>-e%KF", null)]
    [InlineData("2h93tYL./63COIsngDA03Ye7lTlAfKVR26T.RpPBVPA", "", "A]0/y=wjHQN#wstrf,r*", null)]
    [InlineData("loJpnwVKeSvTT7z.ndHnggP9Fd4SIhb425FhmaE/uaC", "JA==", "7i*TzB|9yoFGu*ol", null)]
    [InlineData("EvIc4.zO6KaOdaNZKGzvr2R5hIhdRxDkAoO6CZoDJV0", "Yw==", "F68I2wXJl*@vJSbL~>[5", null)]
    [InlineData("iL7NcvjlU15XlIg8T0v8CziqSN7e/nGDKmbn4pTY.E1", "tw==", "*@ezD_lEVcr|lNxQJB8liE#tTUt1H?LYYmw-", null)]
    [InlineData("bIFyJy8oIvEdywIIEC9OHLZBiXcY43KcaN5QOBklI.D", "VNx8l5+qUxXkgj3iyrqlYLI=", ":PJuirTG-W>", null)]
    [InlineData("4c/eXzb34L5Crt8PKC5pVJ6rIqgYAq2TUHgNkt/FwE.", "PO4qUDgnsqKTSOK+TDMaNiae", "_mUBHt5P~9!2P6.0qlOy", null)]
    [InlineData("8xsErS/Inkt9rSglhfeZf6m32pjKJql5Swv8B5piVo9", "UNWfBlSHW2R9Gkz+R4Y=", "d0L&x</:i~rF/*#(v04-,GY6.Ka^llbH=", null)]
    [InlineData("WMzbYnWZ0ZNzxVygA1Vl674YPT3b/JNjAg/MGOGWwf7", "pAiE+GKN7HoF+IhK", "t<^?pY0D!VjhDS.0=tXS", 10349)]
    [InlineData("jm8E6Vs5dJojDEmEdEff4ES7un4FCgPuFIy6enYaj9B", "/k8RwbMZkSsckw==", "Mnc#w3M6^{Q<-9CvFx.%", 11132)]
    [InlineData("QAp42pyIsbBiYU5viPBEr5FX.nJksr7GK4QSTOpdds4", "8d0LaSWdDtWKbnYcEeLwuXRaDv/+8IIBpLQ=", "N6jC|T7ioEYR_]", null)]
    [InlineData("9ekoh1NRTnpE61/PRuoaiqqbyr30dh9maLDEzBSm1e8", "YFf7Y2RBGLLgvgaiNLqwwZACsEB3r1rHLw==", "07;c9_JaGm_)pe)E]]qU", null)]
    [InlineData("8cHZtm.k/hW308CjH6WpLu1EZ9B9kaIpDB/rReXGTy1", "8ewOkB8/vcIvqWvOSYXw697Il2fM+g==", "lep:sAYPE9rg;_CGUShekoUt@Gu~3I1woq", null)]
    [InlineData("2QxZHUT8EPnggIMDdfGozA.5JZ6j8ZW2jdNToVCYFn/", "M5VPB5toe8N8izqFoylq3+eXI/TN3Q==", "^LqJO}@bs~3%<32bPRQK", 4132)]
    [InlineData("btQ1zjIab.wUfTPK8ZKJpEtsKPPsWK1Tvk6q2UodjXD", "A0OC8Eb3UtmQuBhGcZ2oN5rN+sRjyYnTvw==", "ev^:k<J_*yXUr.RyO4kL", 6180)]
    [InlineData("dmd.lOLz1bO0sUrZDUjzO0VoqIRcE8MY5aXj8K/.kPC", "uBiUgpbJRS36TVUWoX5s7HpoU4Z1dLFzf76qMFxXpumQ9fERHkhWhA==", "vF}J,-vj&L", null)]
    [InlineData("PJhducgHyWO9TU8CGnkemw05RkKWiUn4GGV5sMIIeR4", "gjzNfuKvfAmwPClNRGG0aU5PhPJQ3knU9AQxVR4k/bo=", "hIXgp:l-wz:p|lb0p_XH", null)]
    [InlineData("tZoUutr9p.MbAmaKCxs/o8ZzsZbpRXg3fPJ7SwFHyxD", "3KEQ+/4vnimYrhzjGznbcHnQCosjinHRb/cH/ZSUd5tU", "=XCSMS.V-l0B7PN666;E#T7D1x=Pk(dei(", null)]
    [InlineData("KpSxKmxGX9KBtLxuA0UJ8d3irOwxpvtLB49GllIwtED", "LPvFaHNiCdxxO6cyZCg0MLUl9a8Yw5E5lnMY0IXFL//K", "vNix_jfu?rk8yBMFtU<%", 11760)]
    [InlineData("bo6aGidCr52y6As27n/nVtqWS/KBJCiYNk/n0jrYFI6", "p2LEak6EXNDLW6wB8KKnyGRhP6MQddfi7MwFhBFLKSc=", "4)tgq}|xM8iUR}ohol~(", 4959)]
    [InlineData("KqDALfnqZ1BIFWVbpcmWDi.sc9JZs/AIe87pb.4CzAC", "vw5bqAhAc/kvY/z+xq2sISb+khsqlKPLTMS1q4OPM5viE/Hr+PkIcREH35wSgYruR5E=", "S}R0|=L;", null)]
    [InlineData("puM3rgQoCUC1xkJpPV7Lo1/Uq/uYGf/7ei0F0Z1qdE.", "20jLiSbsRQzLCDaV5GYaYjrixaaaEt/VYl5NxSdKI8KOuyhMIb7SeRA=", "*9_:d!2B)4-_guhGM8=d", null)]
    [InlineData("vjAMRMcLQMObRbTj7zogJqj3hrUa48AE/9xetuKVApB", "2rrvzzQZeqeE8XCr2JVAP1Rgx2MXRPV3m5Z1S1jHY1dNeaXhMNiQ57U=", "JME^jQWrp.?58^UpdgyhB%0u2oTFrgN)5", null)]
    [InlineData("DLGONStnyauTBv7BDVsG6dkd1spqS2hPYCiyZ8tHnW6", "yrqC//AmY4gb8yLR/sRXofQFsIIZ7l0OOpEIwUt5cuweX/prpocLfFs=", "=dG_-x?nGwcL}Z?I^OdA", 7807)]
    [InlineData("Ig0fd/t3sD1UlYJEqBtOmzE2cyVTzdQrAuoTQmrcQ5.", "qiqK4AZQLMLg14s0DfmDXj8xaVA8g6zC3ExdW+osbxpP9rPNRVaRxJc=", "j!,p)92pl0=6}OXt@7t#", 4926)]
    public void SHA256CryptReturnsExpectedDigest(string expectedDigest, string keyBase64, string saltStr, int? rounds)
    {
        CryptReturnsExpectedDigest(expectedDigest, keyBase64, saltStr, rounds);
    }

    [Theory]
    [InlineData("$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", "Hello world!", "saltstring", null)]
    [InlineData("$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA", "Hello world!", "saltstringsaltstring", 10000)]
    [InlineData("$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5", "This is just a test", "toolongsaltstring", 5000)]
    [InlineData("$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1", "a very much longer text to encrypt.  This one even stretches over morethan one line.", "anotherlongsaltstring", 1400)]
    [InlineData("$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/", "we have a short salt string but not a short password", "short", 77777)]
    [InlineData("$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD", "a short string", "asaltof16chars..", 123456)]
    [InlineData("$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC", "the minimum number is still observed", "roundstoolow", 10)]
    public void SHA256CryptReturnsExpectedDigestString(string expectedDigestString, string password, string? salt, int? rounds)
    {
        CryptReturnsExpectedDigestString(expectedDigestString, password, salt, rounds);
    }
}
