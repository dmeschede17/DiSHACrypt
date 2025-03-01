
# DiSHACrypt

## Implementation of 'Unix crypt using SHA-256 and SHA-512' 

This project provides an implementation of the 'Unix crypt using SHA-256 and SHA-512' algorithm (as specified by Ulrich Drepper in https://www.akkadia.org/drepper/SHA-crypt.txt).

It also includes a variant for MySQL's *caching_sha2_password* authentication plugin.

### Example Usage

#### Generate SHA-256 digest string with random salt and default rounds

```csharp
using DiSHACrypt;

string digest1 = new SHACryptSHA256().Crypt("my-SECURE-password!");

Console.WriteLine($"SHA-256 digest with random salt and default rounds:\n{digest1}");
```

#### Generate SHA-256 digest string with specified salt and default rounds

```csharp
using DiSHACrypt;

string digest2 = new SHACryptSHA256().Crypt("a_password", "my_salt");

Console.WriteLine($"\nSHA-256 digest with specified salt and default rounds:\n{digest2}");
```

#### Generate SHA-512 digest string with specified salt and rounds

```csharp
using DiSHACrypt;

string digest3 = new SHACryptSHA512().Crypt("yetanotherpwd", "yetanothersalt", 7000);

Console.WriteLine($"\nSHA-512 digest with specified salt and rounds:\n{digest3}");
```

#### Generate MySQL caching_sha2_password authentication string with random salt and specified rounds

```csharp
using DiSHACrypt;

string digest4 = new SHACryptMySqlSHA256().Crypt("Another-password?", rounds: 15000);

Console.WriteLine($"\nMySQL caching_sha2_password authentication string:\n{digest4}");
```
