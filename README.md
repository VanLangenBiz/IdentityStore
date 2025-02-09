# IdentityStore

Work in progress....


## Create an empty database (SQLite database)
- dotnet tool install --global dotnet-ef
- dotnet ef migrations add InitialCreate
- dotnet ef database update

## Add these to your secrets.json
There is a static functie `private static void GenerateKeys()` to easy generate keypairs.

-  "Issuer": "[issuer]",
-  "Audience": "[audience]",
-  "RSA:PrivateKey": "[privatekey]",
-  "RSA:PublicKey": "[publickey]"

To store values, you can use: dotnet user-secrets set "RSA:PrivateKey" "[privatekey]"
