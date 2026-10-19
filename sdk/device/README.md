> Status: 0.1, matches docs/api.md
> Last checked: 2026-10-19

# Device id

A privacy-preserving device id for the event `device` field: a random 128-bit id,
generated once on the device and kept in first-party storage. openfraud replaces it
with a keyed pseudonym before any rule sees it.

There is no fingerprinting of any kind: no canvas, fonts, audio or hardware probing.
The id means nothing outside your app, and clearing the storage resets it.

## Legal note

Storing an id on the user's device falls under the ePrivacy rules in the EU
(Art. 5(3) of Directive 2002/58/EC, as transposed in each member state). You, the
host, must decide the legal basis: either the storage is strictly necessary for
security (a fraud and abuse defence you can document), or you ask for consent.
Reading the id back is covered by the same rule. This is not legal advice.
Offer `forgetDevice()` (or the equivalent below) if you rely on consent.

## Web

Copy `device.js`, then:

```js
import { deviceId } from "./device.js";
await fetch("/login", { method: "POST", body: JSON.stringify({ ..., device: deviceId() }) });
```

Your backend puts that value in the event `device` field and calls openfraud. Never
call openfraud from the browser: the API key must stay on the server.

## iOS (Swift, Keychain)

```swift
import Security
func deviceId() -> String {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "openfraud_device", kSecReturnData as String: true]
    var out: AnyObject?
    if SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data {
        return String(decoding: d, as: UTF8.self)
    }
    var b = [UInt8](repeating: 0, count: 16); _ = SecRandomCopyBytes(kSecRandomDefault, 16, &b)
    let id = "dev_" + b.map { String(format: "%02x", $0) }.joined()
    SecItemAdd(q.merging([kSecValueData as String: Data(id.utf8)]) { $1 } as CFDictionary, nil)
    return id
}
```

## Android (Kotlin, EncryptedSharedPreferences)

```kotlin
fun deviceId(ctx: Context): String {
    val key = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    val prefs = EncryptedSharedPreferences.create(ctx, "openfraud", key,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    return prefs.getString("device", null) ?: ("dev_" + ByteArray(16)
        .also { java.security.SecureRandom().nextBytes(it) }
        .joinToString("") { "%02x".format(it) })
        .also { prefs.edit().putString("device", it).apply() }
}
```
