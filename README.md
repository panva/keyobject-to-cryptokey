# keyobject-to-cryptokey

Converts KeyObject instances to CryptoKey for use with a given JSON Web Algorithm

```ts
import { convert } from "keyobject-to-cryptokey";
let key!: crypto.KeyObject;
let alg!: string;

const cryptoKey = convert(key, alg);
```
