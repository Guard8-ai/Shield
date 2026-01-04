# Installation Guide

Step-by-step installation for every supported language.

---

## Python

**Requirements:** Python 3.8+

```bash
pip install shield-crypto
```

**Verify installation:**
```bash
python -c "from shield import Shield; print('OK')"
```

**From source:**
```bash
git clone https://github.com/Guard8-ai/Shield.git
cd Shield/python
pip install -e .
```

---

## JavaScript / Node.js

**Requirements:** Node.js 14+

```bash
npm install @guard8/shield
```

**Verify installation:**
```bash
node -e "const {Shield} = require('@guard8/shield'); console.log('OK')"
```

**From source:**
```bash
git clone https://github.com/Guard8-ai/Shield.git
cd Shield/javascript
npm install
npm link  # Makes it available globally
```

---

## Go

**Requirements:** Go 1.19+

```bash
go get github.com/Guard8-ai/shield
```

**In your code:**
```go
import "github.com/Guard8-ai/shield/shield"
```

**Verify installation:**
```bash
go run -e 'package main; import "github.com/Guard8-ai/shield/shield"; func main() { println("OK") }'
```

**From source:**
```bash
git clone https://github.com/Guard8-ai/Shield.git
cd Shield/go
go test ./...
```

---

## C

**Requirements:** GCC or Clang, Make

```bash
git clone https://github.com/Guard8-ai/Shield.git
cd Shield/c
make
```

**This creates:**
- `libshield.a` - Static library
- `include/shield.h` - Header file

**Link in your project:**
```bash
gcc your_program.c -I./include -L. -lshield -o your_program
```

**Verify installation:**
```bash
make test
```

---

## Java

**Requirements:** Java 11+, Gradle 7+

**build.gradle:**
```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation 'ai.guard8:shield:1.0.0'
}
```

**From source:**
```bash
git clone https://github.com/Guard8-ai/Shield.git
cd Shield/java
gradle build
gradle test
```

**Use in your code:**
```java
import ai.guard8.shield.Shield;

Shield s = Shield.create("password", "service");
byte[] encrypted = s.encrypt(data);
```

---

## C# / .NET

**Requirements:** .NET 6.0+

**NuGet:**
```bash
dotnet add package Guard8.Shield
```

**From source:**
```bash
git clone https://github.com/Guard8-ai/Shield.git
cd Shield/csharp
dotnet build
dotnet test
```

**Use in your code:**
```csharp
using Guard8.Shield;

var s = Shield.Create("password", "service");
byte[] encrypted = s.Encrypt(data);
```

---

## Swift

**Requirements:** Swift 5.5+, Xcode 13+

**Package.swift:**
```swift
dependencies: [
    .package(url: "https://github.com/Guard8-ai/Shield.git", from: "1.0.0")
]
```

**From source:**
```bash
git clone https://github.com/Guard8-ai/Shield.git
cd Shield/swift
swift build
swift test
```

**Use in your code:**
```swift
import Shield

let s = try Shield.create(password: "password", service: "service")
let encrypted = try s.encrypt(data)
```

---

## Kotlin

**Requirements:** Kotlin 1.9+, JDK 11+

**build.gradle.kts:**
```kotlin
dependencies {
    implementation("ai.guard8:shield:1.0.0")
}
```

**From source:**
```bash
git clone https://github.com/Guard8-ai/Shield.git
cd Shield/kotlin
gradle build
gradle test
```

**Use in your code:**
```kotlin
import ai.guard8.shield.Shield

Shield.create("password", "service").use { s ->
    val encrypted = s.encrypt(data)
}
```

---

## WebAssembly

**Requirements:** Rust, wasm-pack

**Install wasm-pack:**
```bash
cargo install wasm-pack
```

**Build for web:**
```bash
git clone https://github.com/Guard8-ai/Shield.git
cd Shield/wasm
wasm-pack build --target web
```

**Build for Node.js:**
```bash
wasm-pack build --target nodejs
```

**Use in browser:**
```html
<script type="module">
import init, { Shield } from './pkg/shield_wasm.js';

await init();
const s = new Shield("password", "service");
const encrypted = s.encrypt(new TextEncoder().encode("secret"));
</script>
```

---

## Rust (Native)

**Requirements:** Rust 1.70+

**Cargo.toml:**
```toml
[dependencies]
shield-core = "1.0"
```

**From source:**
```bash
git clone https://github.com/Guard8-ai/Shield.git
cd Shield/wasm  # Rust source is in wasm/
cargo build
cargo test
```

---

## Verify Cross-Language Compatibility

After installing multiple languages, verify they can decrypt each other's data:

```bash
# Python encrypts
python -c "
from shield import Shield
s = Shield('test', 'app')
enc = s.encrypt(b'hello')
print(enc.hex())
" > /tmp/test.hex

# JavaScript decrypts
node -e "
const {Shield} = require('@guard8/shield');
const fs = require('fs');
const hex = fs.readFileSync('/tmp/test.hex', 'utf8').trim();
const enc = Buffer.from(hex, 'hex');
const s = new Shield('test', 'app');
console.log(s.decrypt(enc).toString());
"
# Output: hello
```

---

## Troubleshooting

### Python: "No module named 'shield'"
```bash
pip install --upgrade shield-crypto
```

### JavaScript: "Cannot find module '@guard8/shield'"
```bash
npm install @guard8/shield
```

### Go: "package not found"
```bash
go mod tidy
go get github.com/Guard8-ai/shield@latest
```

### C: "undefined reference to shield_*"
Make sure you link with `-lshield`:
```bash
gcc program.c -L/path/to/shield -lshield -o program
```

### Java: "class not found"
Make sure the dependency is in your build.gradle and you ran `gradle build`.

---

## Getting Help

- [CHEATSHEET.md](CHEATSHEET.md) - Quick reference
- [GitHub Issues](https://github.com/Guard8-ai/Shield/issues) - Bug reports
- [SECURITY.md](SECURITY.md) - Security best practices
