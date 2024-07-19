# IdentityStore

Work in progress....


## Create an empty database (SQLite database)

- dotnet ef migrations add InitialCreate
- dotnet ef database update

## Add these to your secrets.json
-  "Issuer": "[issuer]",
-  "Audience": "[audience]",
-  "RSA:PrivateKey": "[privatekey]",
-  "RSA:PublicKey": "[publickey]"
