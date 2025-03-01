namespace DiSHACrypt.Tests;

public class UnitTestsSHACryptSHA512 : UnitTestsSHACryptBase<SHACryptSHA512>
{
    [Theory]
    [InlineData("PSv1.XSDTCvqLhpdHruz9Sa.TWswE5lEqMh0LL1HvyDV5Kanz6uvZz2XFDkUn.krGfhNKAjgHms8qSMeE8LK1.", "", "C", null)]
    [InlineData("5OaRLkhI4A6ZZe0UygWDwfeeXEjeAls0dOPZxh8ndSwCH4y0Dnr.O4JJRW1A1cNfPSVytjW4fmxANec7mzdx/1", "", "|m6h??UGD4Q.k+q[", null)]
    [InlineData("Agx8.LeKFcaCU3buGZelMV6bMIvVeI6f/kv683vEfrbbq1TVDNE7y24BBinUNTM6NyTyIlA4/tXsV5HzB8vF7.", "", "iJ8_N]S:}D1oELY,h_ZI", null)]
    [InlineData("f8/pgelLbAajTuCZI4YxPjTbLAvpcEWWmzG9wlk6YjCixXkpqR1IISdOmLH08hzFEESuJSFrFdikU4ET64fFc.", "QA==", "::XC7u;p]RqWq3=H", null)]
    [InlineData("HuTyKYdYRvrcu2XHln8TpFWjBs.ZgQl3RRi/uX9wRToKHpLIj1BGNQ4Z2fbNXMv8t8GcVZqRretAq4YNQJ44K0", "oQ==", "GEqF{<UCHm-JGG0&z+&0", null)]
    [InlineData("lhjh344nGmqPp7uCQecH.PVijchD9axF4UGNfGl26g65LDzraJ0CeUADomHU0CNeJoKpJgT8fr5FgiJAa8O4Z1", "nw==", "XLMs7~xsHIv[1DNZJ-+CBZ^keYIpp}>F_tL%", null)]
    [InlineData("0cdrfUIWQvZoNdeHPN3dbD6bVsJR02cnlRzUQv3fMWxxsmON8VM3IMN2tjJhSpfX/zHV0ZvoXqgBLX8zjw6lG0", "5tOH8eegvsNl5gVEIlwJqhf5MECz", "rk*?l^)_7", null)]
    [InlineData("0gfihaBNnBky5qHhhSoCf9SK.a3XxpQIujPLAQyW1eBhcsMSIgTso3LHaTQoYxUr3bdIA.sQ.CYIsgX/0.Pb90", "2QsuKjnkMr2EYbNyJr5J19cisyZdq+CJXttJv+I=", "Ft=?t:Bl,(l4N4?Id9o5", null)]
    [InlineData("wC6RHNduuW4bHr2DEp3cl7daIWl8jXdavb9eeWApYv6BF.LjrUyrYXnR0FMmzFPRmNsFe/Wt/Cbc8yU4zLmPW/", "hPhy8ywQpSxBMpya4d4dlSDpCTtaHzVQa2tGDfQ=", "4MOObC/lmJ=+5!@C4ZUWq@wZg#&M}]RTv3x9hsX", null)]
    [InlineData("OU0xMEwlY0cD/3RGpRsn7A9g1qqIij65YCAtWSlidyQ5FjE6zLDi6dF7xEoPVj38RLDXgBiyB5sxs03j6E8G31", "577lStJyH2tx8lp979wSvOEgVVLZBQ==", "c7Jl<V]<XfOUrwG5JUMQ", 11457)]
    [InlineData("TWOV123nDeckFkkkSzqkSrXRs2YevCR1UKPdB5rJGL7SyhpSH4LB7.swAIewsQ9MhmWP6.VHlTx//txOMGFuF0", "NDwztfB/K1RGb/QE6MyS5hEIJTo=", "YYM/jQ:EqpiCoFR}t(c>", 6693)]
    [InlineData("zgb2s614mtcQZ41Ae3qh2F9lvOARaFt6eB8KEgwC8p1D1.dZr5vvy11K3uiHaX/osHCH4q6Uac09t46uXrim31", "ttDOVml/mXGJgXp+4df/JlQGgpqQfTanvO8xFtlYkYRi0UkzVQ8MwY1vvIo=", "2ODKO+M0@7Z", null)]
    [InlineData("VYVCSML286pYV2UK2tM25u/YHm39yihggOLn1OJpUA0wVeJChcxSfwcyP7bBUAfCf235mWihipLbO3C3MgS6p1", "eXZn83MhWvErirVWsVvNioaYE9b4BM20bq2czok45VxVDCcQWRI=", "^/.j0Og3L;p>D#Qk;[U&", null)]
    [InlineData("cTF889.wEbLN8QMDAjS7ke2K7.083EmDTEOr7VXtpD66k36JAwCs8VksYXKw41GwSTo6Ge1IR.9pscFo7sdg2/", "er87RwokiWSIeSk0TOYn5djlHjJdgYF6S0vb7gdABeQ2GQ681+3D", "[11I#eZ|nh:bs87DqnFH)lcWe0]O#1UTRfa2.", null)]
    [InlineData("QhiPOWrrVkCP4mheuVepmb1iIjqTlF/8DVSf/96Ront309ESYDcnvtTBpOQIYCA035oreqhRuEbhly.lTwMdT1", "po2vn5ENzsEiGhQ7HtmAUYsQoYECG2JC4Cn5eBMM", "L#r:Ux|}3Tn2fvw2=h86", 5156)]
    [InlineData("xggPJ6P71DnxeKpyygUvLZWGQnkZPyeWDaDaNeBUX1nPgAXUJ8ldd1uvA5YnHKER7sPfr9HvCaCxYGspdzkyJ1", "/ZadvSGNmrV+gXLoKeP6amf6tPLDK9yrA8LLcVzSVhFWQ8Eltkg2", "1qnB*B;<)lnD&2Jm=A1D", 10535)]
    [InlineData("Jmru5sW78pcyMOVTxwrUw/Bx4t.2jj5aJtinnaAlWYu9sv/bG2uyIPVkALGXX6YOoUw3f3onAe.d11cns67LI1", "pKizCFoF2px0dblGB6gREdjjptrjB19FI70mLKrx/wwQ5ym9Vy50UXRdN2EpTl/b30c581CZ2NkPPHyG", "VKG7ZHHp4_{}", null)]
    [InlineData("YHaku4oAWpCuOGnGKlCchy9eRU6TC.ZvEb2kbxJwicZIYjT2j8.9T9skm3MJcGZlXnU473wSmnqGArSPkxh0q.", "trVMW5XEb1QgSwzVyRTwzB/ZjuUW4XCDh98GYqCT4bklsJs8Td4tLdppMd2ix1e3k5zcwda/", "}H?LEQ*Yg)dQXPP3|1CZ", null)]
    [InlineData("8z1ls.OjUeUWNUcxMJtE2AemMh7YsNdRy3ivgoGWcCmV2eKDJ53h4g15fJ29RyTLDwzPIhcOYsF8PtnkbmWVu0", "0jyXhhnbKdFoiEKJEch8eHmOxNWpuWOZgBIJMlBwEDFRvQEG/e1k8zvZoNioO6MTPVWjS518rw4=", "AYzn=c#&,XyVNW9R~dgbfe!RJ,j-K>%4E()", null)]
    [InlineData("RIIgglNOz3UXXuIEAGw3PoI8g6CoNiN6bYNnOQSrFbDo1ruKyRTXfl2/nmJgH2JwiwgEw62VvPQEm.Nlnwcs51", "4tH5FuXWsKc4rGdyzP7p0ZZwEzeH6RI0foKKLZNjWGFJeiKGzCkif9MBB0XVOQ==", "U4=peKmh=.RL,/_s]PqQ", 5934)]
    [InlineData("tcoxCPhyLhd1iCl0ii17RWEQP2GDm8YxDUaYj8.gAMlCUxFaHJ9Q8Moc5L9FL.skQQ35j58dd2nRIVQcf9fEt0", "Lkb5M4ia9LJcIvkiJ9YTP4RPgAysKTJxfZE7CHnlP9WUhfAUiBe/opRokA1vkjRB/PmXBFe9", "j-;kBDSEAhB(=5.VDd~~", 6832)]
    [InlineData("cvLRXzBsUR8BPpqhHrWT.1z.8i5EkWtaI0uCuXlHwPySqjvu1qhbXNlB.paMZ/uIDxpPP9yJsb8dEmDyAQ41m1", "jn6P20+0XEMCHkLhDHnmYhPrKvp9TuzSCAj56mEUGpJgXJdjo5EXVXE893XCQSZHkA4ybba5j72XprRCT0cLM4jzqaIxIw==", "_Jj1gZhwyc?xzq2+", null)]
    [InlineData("5AFJHZeKgBIMX6y14wYQgJR21k3BT2u/Ug/NcKL0oFiPq4/ZEUtcfB.CQtUdJiUdsgZW3zPnJgwcsZqOg3ukf/", "ApJbyVs2A+iv9/xoCnPXwlWAHSkLJlN7a+Ucc6hCpZYeOZPkPIA3ut4DhmR1QwUhH29AeO7CW352F5pojcU9sXUCQf9Kk2A=", "K*}2ND8zt.gB6^^[h!MC", null)]
    [InlineData("iPPkb/c5v1Ygfs.bwLLYRefiZQi0EyeAVG6RcHdn.kwdPbxvPaYR2YKweGID0/xaRN9i9n4tOZx1pJPLR.nED1", "hrrCThvXSjVzBXsS+L3PIdJud0Cb0D37c3aHa0rOJHzMI49CxT/fre9qCvGGM0RLLy/kfqzCpEiauj9B0K4gXpxYjg==", "_N5=RM{#QTA5B#>5c|[rH+y))Ka,@XL1k_{", null)]
    [InlineData("9P519YfxuzSASN28iGGZ2wL1zH8iEPFdsSFo22ujwQ2bfi6E9kubAzywVUXVCCqW80ljSawxHREYINBeS7N2U/", "3SagvNrViQylimrEhahTKBb74zv0j9EI54r/BX1E/0oBdp7omDA8jioY1rY760wJqhETxD0Q/fUZ8Jq6YIs6B8+QDlDPGR+t", "2eGfufNjbM_&/,Iq=H[1", 9465)]
    [InlineData("Eb6DwPviyUTqAdVQM76wg50TrQCCUciH4MZeEJ89ONGFWfYidDIaeLoH7vdRExqMficaj.4I14Ik./XkNNVv2.", "tD/nthJnYXHlZVLSfCUp0EZJGAvU+jjDskvUiOZUNgbNM0DmaKy2hUdWUDqGoM9/XiPZc4F4R8Obos3LEkXCxEc0", "U%*)jkzjwhH083tEyE:f", 6163)]
    public void SHA512CryptReturnsExpectedDigest(string expectedDigest, string keyBase64, string saltStr, int? rounds)
    {
        CryptReturnsExpectedDigest(expectedDigest, keyBase64, saltStr, rounds);
    }

    [Theory]
    [InlineData("$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!", "saltstring", null)]
    [InlineData("$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.", "Hello world!", "saltstringsaltstring", 10000)]
    [InlineData("$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0", "This is just a test", "toolongsaltstring", 5000)]
    [InlineData("$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1", "a very much longer text to encrypt.  This one even stretches over morethan one line.", "anotherlongsaltstring", 1400)]
    [InlineData("$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0", "we have a short salt string but not a short password", "short", 77777)]
    [InlineData("$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1", "a short string", "asaltof16chars..", 123456)]
    [InlineData("$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.", "the minimum number is still observed", "roundstoolow", 10)]
    public void SHA512CryptReturnsExpectedDigestString(string expectedDigestString, string password, string? salt, int? rounds)
    {
        CryptReturnsExpectedDigestString(expectedDigestString, password, salt, rounds);
    }
}
