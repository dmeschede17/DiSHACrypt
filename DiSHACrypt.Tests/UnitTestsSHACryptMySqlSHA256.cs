namespace DiSHACrypt.Tests;

public class UnitTestsSHACryptMySqlSHA256 : UnitTestsSHACryptBase<SHACryptMySqlSHA256>
{
    [Theory]
    [InlineData("9AcNaMJwwO/FMo7XMl5HULzG3Gvja0iwCp9Ys8m0sX2", "", "e", null)]
    [InlineData("b1yLF2sof/7f52PTztkeMDingL.9yTzZt5yaozHK/h6", "", "_}-,V)Y%I3vOstQv", null)]
    [InlineData("oz472rCmr/iMLkN7eswI06iARWGJh3sAn1xkJv4dgy5", "", "]E/~o)}J@}OZJ?^?4=2b", null)]
    [InlineData("eRvuGvuKvnlhgKG.TODQsyICP17R5kYH9TSxdnPO7R5", "IQ==", "t%X7}O9Wvm!+[3xX", null)]
    [InlineData("Zv/lIo.gHNvvfh/GwGfKGSk.tAucdUQh9Yn92PG2/.0", "Fw==", "xL>tW/>)5.G5^DhX[I}I", null)]
    [InlineData("URhCh7TcEwZYnwx7VU4XpGXbQ5DM3xGSXJv1xS83RI6", "YQ==", "u=?2IY8zr:JnEkQ}ij4xQV9GnrI^ri]l(3~n", null)]
    [InlineData("7vM1/HQvV3w0Ri4b8UsCLJJX.76W1pFktDoAn0hF5y.", "oqU//RjEXa8OjAw=", "4SBfM*&OwjNK+Q0", null)]
    [InlineData("q/IFQQLDJCBZkIWn5AZqWn9gDPJzO.7ezMedf2p/hb4", "Qet1LJTU/+q/Rt2jwMeK", "-iqTcftnK-#.r:/HQw(|", null)]
    [InlineData("kdYnKu.wLXhaT7SzbhWiDQn1gJSMdEUU1EcjffKrr54", "T7gZGH3DcNzTnq8KcKJ2", "p[)}4o7=?y}ZhEWfLrPO*uDp3Cng2GtsqR2ZvnP", null)]
    [InlineData("0AQSLKL5gm1fV60IJoLkQAzcbkllU0fXZ6ErxWFnT9C", "War9S04hYu8XhEguTrzh+LegPKY=", "db+.PjD3UPiY:kH)+yhZ", 9415)]
    [InlineData("ErUXbRAuWoDcsafpVCb0OePthAmt9KZfwMm0jPMr.g/", "e+kiL0VyqJr3CwmumOzT8/A=", "_0!JI6gMw<G~YYmw^F]h", 8382)]
    [InlineData("AFTRTSiMW.PWwX99Nk/CjdhQ5aoENBc0uKyPERNuQw6", "AaIN4n717HZob84c9UmmEeWBoVqh5pc=", "h|uD^x}DgvP", null)]
    [InlineData("O8yaxZpR6DsJIgrd7PBf72J3bCQYYb0NvmaGeLyJps5", "h+ByRdY0lliLQBzE5pxsEAO6bPVSG8KXPHmJ", "x{RIl~-BiuzZ6+_;Lj>O", null)]
    [InlineData("9RErIcrWr2g8BD5wRG.Uqfkx4eX3pqlHyUP0ZCynck/", "IOmJrBQ1Tj9OwoN8Cedhu5cvTWHYvPnD+Qk=", "Ay,aR[9u6|IG]8=g/A*GgqC2/P+(_zNJJua", null)]
    [InlineData("7MLtkbHSEY/9mhI9KmAEMT4UTESsKX8RjgiYNLMD.O7", "ffptgupO0tufcLkTeW/lPL4B/FHBZV95Mw==", "f:,~IV9_,b7~}/z4>]f8", 11422)]
    [InlineData("CvmWXUukgM2/crUVv/FnYpPhAFeSk1bL9QKzU1InGJ9", "cv7QsE74Fs/Ui6bmluLpVwuvaXi8zkL6VHv0", "m*ldOS_^WO+U=3yPB4#:", 7624)]
    [InlineData("0gdFLTKQSurR.CLgPC.BfrddpbYO1wLAkVLapvp0u05", "hmV8sV43sqGRPSzd1UeKc7dKDJTwJ/Z77kvb7gyNk85Rpg==", "]BPj7<isacKA", null)]
    [InlineData("UXu.FAAKhe1zmP6nub/iMj5iAvBA.OkecOu5a.KMh08", "D/mmUfj+dPaNAf67SiFMaB/PNGFdwXsxnhVAU/gjSqb5WA==", "C!OB+w)#.r}y_K;P9Vie", null)]
    [InlineData("wwvTNphF9qrsugPR8ONL5gqOGdljRqN3NxlD0GRH2PB", "XGailLBrirftdWSfShs3ErOas7TCzkIBXU9MtVP98pVx2ySo/HCnKA==", "M]&1h{pF]dh1!IfR36F7Yh/.0rgM!Z+Z", null)]
    [InlineData("vAqNTslNUdAts418EqR31V4eZvyoNWSAYF3fJ1tR3u9", "8OPGz8oXE3xVmvSTO2UzNR49DNwmDdMPLoe/lk6coSO9v8NLKJJ+", "d2Wd4%Dy=OzMWRV+vc+T", 8068)]
    [InlineData("kZSMkh4byNEd11NF/Yth.i2d3jK1Zq9zWfQsXNDsqg4", "2HNlhQzFu4QfLLBVrxNl04FYH0rUesX7n0yiMFDnhHVQ6w==", "1Vt8%[uuw.[DV]<Ixe{p", 11892)]
    [InlineData("NMjQXo2wkDbt8knzr1wJR0DWGQNQ/1zr9DPtENyDIR8", "nn8gwFAH+/U0LqPWxzpmhn8lF0S8Wid6aqCh+bqmyjYOtzv1SIwDIMnYuR0=", "UFkqEPYqHWyKJ]", null)]
    [InlineData("RpZzFlLOqxQu8jtRqKeKA2PiEbaKCWG0n0Uuv1F5.ZB", "PFmArhwwxtzwIySCI5IjE59nvLwdRvEtFV0LpMx8+N3Qc0nIydyD9A==", "i3Yv_Z<kFe]tfZ(&%~C?", null)]
    [InlineData("QwBeOop6figAC5KtjCBIrkNg9Pj2XdS4tAj4JS/YQA3", "qyDf80QyIdK/KJDEbqmDmGc4B9ZTdjhtSug5tHsgZ2mUWOTvUiNvoUt5a7vbFoVfPg==", "E5:V,AP(EZ_M{;vgV!]%jMbK=V5_N:S>84", null)]
    [InlineData("xi2lhYLYKILHzn79wllfHtUpwMqp93OWyKbsn.M.KC7", "0raHHIAj+g7xRprz1qz+rL50aI5EejlpiJtt/KMSdvh5qS11BRR7OFI=", "33HU}=&:HEAk#/z^Fr;+", 9053)]
    [InlineData("Ufsls9T5KxlvT5l5GMbzDxyOJ.SFLodCykFSiJfk.a8", "hycXEqB0PXE1AqkD04+6OBETMPqNP6lfIk36FPZgdxQX8XRtsNoHP6px9DPm0LA=", "-]225o*QisHXB7*Yax4?", 7906)]
    public void MySqlSHA256CryptReturnsExpectedDigest(string expectedDigest, string keyBase64, string saltStr, int? rounds)
    {
        CryptReturnsExpectedDigest(expectedDigest, keyBase64, saltStr, rounds);
    }

    [Theory]
    [InlineData("$A$005$saltstring123456789|tZiSFrEBna2HetJRmQsiccoqM2dS.mYe1VQT/30E9l1", "", "saltstring123456789|", null)]
    [InlineData("$A$005$saltstring123456789|kvpr22UrFOh2wbD.qzZemKCYt1pGrZYG1fvB1zBYgT8", "test", "saltstring123456789|", null)]
    [InlineData("$A$005$saltstring123456789|kvpr22UrFOh2wbD.qzZemKCYt1pGrZYG1fvB1zBYgT8", "test", "saltstring123456789|TOOLONG", null)]
    [InlineData("$A$005$saltstring123456789|VQEYzmpZKxhKjwyaR2XFxwQN2wORhpvoCGbeoWAdc20", "12345678901234567890", "saltstring123456789|", null)]
    [InlineData("$A$005$saltstring123456789|8oIJKEdZ9y1QYkxxdimRXKtZhWDwFTT/HiuvCJcDfrB", "1234567890123456789012345678901234567890", "saltstring123456789|", null)]
    [InlineData("$A$005$saltstring123456789|aY9mMTJNTRkWsTBeGJlgOrFt7OZseUH/mqG/7NfkQk6", "hi", "saltstring123456789|", 10)]
    [InlineData("$A$009$saltstring123456789|Fw1JIi6rbFyWI/aFO053P90EbsHGsjPjhcd4xrZmDj4", "hallo", "saltstring123456789|", 9000)]
    [InlineData("$A$00A$SALTSTRINGabcdefghi~OOp6Z5YFoqFYBL7jJibje3veqZVY7QkIkdd7MDwCV53", "nocheintest", "SALTSTRINGabcdefghi~", 9999)]
    [InlineData("$A$00A$SALTSTRINGabcdefghi~OOp6Z5YFoqFYBL7jJibje3veqZVY7QkIkdd7MDwCV53", "nocheintest", "SALTSTRINGabcdefghi~", 10000)]
    [InlineData("$A$010$SALTSTRINGabcdefghi~kMrar.M.fFexhrtZveUk5bTeF9EonAxci3dTnCSELnB", "yetanothertest", "SALTSTRINGabcdefghi~", 15001)]
    [InlineData("$A$010$SALTSTRINGabcdefghi~kMrar.M.fFexhrtZveUk5bTeF9EonAxci3dTnCSELnB", "yetanothertest", "SALTSTRINGabcdefghi~", 16000)]
    [InlineData("$A$100$####################MNjX8ckYkqF56q1BtILPD/MdW2TT8H3c2AblnphAk9B", "TEST1234567890TEST", "####################", 256000)]
    [InlineData("$A$FFF$yetANOTHERsalt------DvkP5QfX1RUM9TJCK8nV5S3PvalhnPwUSXihGl9zLx1", "Hello_world!", "yetANOTHERsalt------", 4095000)]
    [InlineData("$A$FFF$yetANOTHERsalt------DvkP5QfX1RUM9TJCK8nV5S3PvalhnPwUSXihGl9zLx1", "Hello_world!", "yetANOTHERsalt------", 4096000)]
    public void MySqlSHA256CryptReturnsExpectedDigestString(string expectedDigestString, string password, string? salt, int? rounds)
    {
        CryptReturnsExpectedDigestString(expectedDigestString, password, salt, rounds);
    }
}
