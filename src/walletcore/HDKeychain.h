////////////////////////////////////////////////////////////////////////////////
//
// HDKeychain.h
//
// Copyright (c) 2013-2014 Eric Lombrozo
// Copyright (c) 2011-2016 Ciphrex Corp.
//
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
//

#ifndef __ELASTOS_SDK_HDKEYCHAIN_H__
#define __ELASTOS_SDK_HDKEYCHAIN_H__

#include <Common/hash.h>
#include <Common/typedefs.h>
#include <Common/BigInt.h>
#include "secp256k1_openssl.h"

#include <stdexcept>
#include <map>

namespace Elastos {
	namespace ElaWallet {

		class HDKeychain
		{
			public:
				HDKeychain(CoinType type, const bytes_t& key, const bytes_t& chain_code, uint32_t child_num = 0, uint32_t parent_fp = 0, uint32_t depth = 0);
				HDKeychain(CoinType type, const bytes_t& extkey);
				HDKeychain(const HDKeychain& source);

				~HDKeychain() { _key.clean(); _chain_code.clean(); }

				HDKeychain& operator=(const HDKeychain& rhs);

				explicit operator bool() const { return _valid; }


				bool operator==(const HDKeychain& rhs) const;
				bool operator!=(const HDKeychain& rhs) const;

				// Serialization
				bytes_t extkey() const;

				CoinType coinType() const { return _type; }
				// Accessor Methods
				uint32_t version() const { return _version; }
				int depth() const { return _depth; }
				uint32_t parent_fp() const { return _parent_fp; }
				uint32_t child_num() const { return _child_num; }
				const bytes_t& chain_code() const { return _chain_code; }
				const bytes_t& key() const { return _key; }

				bytes_t privkey() const;
				const bytes_t& pubkey() const { return _pubkey; }
				bytes_t uncompressed_pubkey() const;

				bytes_t hash() const; // hash is ripemd160(sha256(pubkey))
				uint32_t fp() const; // fingerprint is first 32 bits of hash
				bytes_t full_hash() const; // full_hash is ripemd160(sha256(pubkey + chain_code))

				bool valid() const { return _valid; }

				HDKeychain getPublic() const;
				HDKeychain getChild(uint32_t i) const;
				HDKeychain getChild(const std::string& path) const;

				std::string toString() const;
		};

	}
}

#endif // __ELASTOS_SDK_HDKEYCHAIN_H__
