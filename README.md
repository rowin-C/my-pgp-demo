# 🔐 PGP Keygen + OpenPGP.js Demo

This repository demonstrates how to:

- Generate **PGP key pairs** using **C# (BouncyCastle)**.
- Export the keys in proper ASCII-armored format (`.asc`).
- Use those keys with **OpenPGP.js** in Node.js/Browser for encryption, decryption, signing, and verification.

It’s meant to save you from scrambling around multiple docs when setting up a C# + JS workflow for PGP.

---

## 📂 Project Structure

```
pgp-csharp-js-demo/
├── keygen/        # C# console app (BouncyCastle) for generating PGP keys
└── openpgpjs/     # Node.js project for testing OpenPGP.js encryption/decryption
```

---

## ⚙️ Prerequisites

- [.NET SDK](https://dotnet.microsoft.com/download) (tested with .NET 6+)
- [Node.js](https://nodejs.org/) (tested with v18+)
- Git + a GitHub account (if you want to push your own fork)

---

## 🔑 Generate Keys with C#

Inside `keygen/`:

```bash
dotnet build
dotnet run
```

This will generate:
- `public.asc` – your public key  
- `private.asc` – your private key (optionally passphrase protected)

---

## ✉️ Encrypt & Decrypt with OpenPGP.js

Inside `openpgpjs/`:

```bash
npm install openpgp
```

Example usage (simplified):

```js
import * as openpgp from 'openpgp';
import fs from 'fs';

// Load keys
const publicKeyArmored = fs.readFileSync('../keygen/public.asc', 'utf8');
const privateKeyArmored = fs.readFileSync('../keygen/private.asc', 'utf8');

// Decrypt private key (if passphrase protected)
const privateKey = await openpgp.decryptKey({
  privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
  passphrase: 'your-passphrase'
});

// Encrypt message
const encrypted = await openpgp.encrypt({
  message: await openpgp.createMessage({ text: 'Hello from JS!' }),
  encryptionKeys: await openpgp.readKey({ armoredKey: publicKeyArmored }),
  signingKeys: privateKey
});

// Decrypt message
const decrypted = await openpgp.decrypt({
  message: await openpgp.readMessage({ armoredMessage: encrypted }),
  decryptionKeys: privateKey
});

console.log(decrypted.data); // "Hello from JS!"
```

---

## 📝 Blog

I’ve written a blog post explaining all the pitfalls I faced (like missing `END PGP PUBLIC KEY BLOCK`, insecure passphrase hashes, etc.) so you don’t have to waste time.  

👉 Link: *([Medium Blog](https://medium.com/@rowin_dev/end-to-end-guide-generating-and-using-pgp-keys-with-c-and-openpgp-js-98999e2662b4))*

---

## 📜 License

MIT — free to use, share, and improve.
