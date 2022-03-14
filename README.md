# Wallet JS SDK

## Origin

This Typescript SDK is originated from the Elastos C++ SPVSDK. That C++ SDK is a SPV SDK and as such, can synchronize blocks and manage many things.

This JS SDK diverges a little bit from that original SDK in a few ways:

- No SPV support. Only account/wallet, transactions, signature management, but transactions are retrieved and published by RPC APIs.
- A wallet store layer is added, in order to let apps provide their own storage solution for wallet data.
- Non elastos chains (eg BTC, Ripple) are not going to be supported. Elastos Wallet SDK must focus on the elastos chains only, and not try to support too many chains. Each chains needs to use its own SDK.

## Note

- The current version is based on that [f1eba107](https://github.com/elastos/Elastos.ELA.SPV.Cpp/tree/no_p2p) commit ID.
- For now we continue to migrate C++ -> TS on this version
- When we will have a first stable version of the TS SDK, we will "replay" the diff between no_p2p and dev c++ branches into TS
