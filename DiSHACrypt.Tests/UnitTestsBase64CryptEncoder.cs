namespace DiSHACrypt.Tests;

public class UnitTestsBase64CryptEncoder
{
    [Theory]
    [InlineData("", "")]
    [InlineData("..", "AA==")]
    [InlineData("01", "wg==")]
    [InlineData("271", "RDI=")]
    [InlineData(".yJZ", "gF+V")]
    [InlineData("3HByG.", "xdT4Eg==")]
    [InlineData(".oOXRd6", "AK2NXYo=")]
    [InlineData("tsH11uYE", "OT4Ng05C")]
    [InlineData("aYaOYvayR1", "Jmlq5G763Q==")]
    [InlineData("hEaRyU6Gpb8", "LWR2PohI9ak=")]
    [InlineData("PnLUKXRVQVLR", "23yB1tiFXHh1")]
    [InlineData("KOhdvF7cS0KKY1", "ltame5SgnmBZ5A==")]
    [InlineData("NtbSAkajuXVRmO7", "WX56DGy++hh2spY=")]
    [InlineData("il9sgDgeJuFJ/sls", "brzg7MOqlR5VAR7j")]
    [InlineData("mjI1ZMipCUh9d2PpK0", "8ksNJebWDtguKbHVlg==")]
    [InlineData("0fu5AATp/pWu.0OUWo9", "wqofDPPVQS3qgKCBIr0=")]
    [InlineData("xYuy9o0cAV0ltHmwhahy", "Pan7Cy2gTCjE+STzrdn6")]
    [InlineData("W.KzHK7Q3yNdXfvgHmLVy0", "ImD9k5VwhZ+l47qzk3yFvg==")]
    [InlineData("47iKXibqXAkg.Wts9Ku0zL2", "RuJao3vaIwOzgJjji6UL/0U=")]
    [InlineData("JOfm8Q0fTJimXt.sxIhD28Oh", "lbbKCiesX+XKYw7gPdU+hKK1")]
    [InlineData("OrFK0mnppvxrAJztDD5uup/0I.", "2h1ZgjzX9d7fTPXnz3Poeh0IFA==")]
    public void EncodeReturnsExpectedResult(string expected, string bytesBase64)
    {
        var bytes = Convert.FromBase64String(bytesBase64);
        var result = Base64CryptEncoder.Encode(bytes);
        Assert.Equal(expected, result);
    }
}
