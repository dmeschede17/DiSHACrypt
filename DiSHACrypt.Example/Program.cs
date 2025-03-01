using DiSHACrypt;

// SHA-256 digest string with random salt and default rounds...

SHACryptSHA256 cryptSHA256 = new();

string digest1 = cryptSHA256.Crypt("my-SECURE-password!");

Console.WriteLine($"SHA-256 digest with random salt and default rounds:\n{digest1}");

// SHA-256 digest string with specified salt and default rounds...

string digest2 = cryptSHA256.Crypt("a_password", "my_salt");

Console.WriteLine($"\nSHA-256 digest with specified salt and default rounds:\n{digest2}");

// SHA-512 digest string with specified salt and rounds

string digest3 = new SHACryptSHA512().Crypt("yetanotherpwd", "yetanothersalt", 7000);

Console.WriteLine($"\nSHA-512 digest with specified salt and rounds:\n{digest3}");

// MySQL caching_sha2_password authentication string with random salt and specified rounds...

string digest4 = new SHACryptMySqlSHA256().Crypt("Another-password?", rounds: 15000);

Console.WriteLine($"\nMySQL caching_sha2_password authentication string:\n{digest4}");
