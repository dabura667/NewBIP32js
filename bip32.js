
var BITCOIN_MAINNET_PUBLIC = 0xc88fb5c4;
var BITCOIN_MAINNET_PRIVATE = 0xc88efaba;
var BITCOIN_TESTNET_PUBLIC = 0x043587cf;
var BITCOIN_TESTNET_PRIVATE = 0x04358394;
var DOGECOIN_MAINNET_PUBLIC = 0x02facafd;
var DOGECOIN_MAINNET_PRIVATE = 0x02fac398;
var DOGECOIN_TESTNET_PUBLIC = 0x0432a9a8;
var DOGECOIN_TESTNET_PRIVATE = 0x0432a243;
var LITECOIN_MAINNET_PUBLIC = 0x019da462;
var LITECOIN_MAINNET_PRIVATE = 0x019d9cfe;
var LITECOIN_TESTNET_PUBLIC = 0x0436f6e1;
var LITECOIN_TESTNET_PRIVATE = 0x0436ef7d;
var MONACOIN_MAINNET_PUBLIC = 0x01b04071;
var MONACOIN_MAINNET_PRIVATE = 0x01b040f5;
var MONACOIN_TESTNET_PUBLIC = 0x0434c85b;
var MONACOIN_TESTNET_PRIVATE = 0x0434c8e0;
var KUMACOIN_MAINNET_PUBLIC = 0x01864f84;
var KUMACOIN_MAINNET_PRIVATE = 0x01865009;
var KUMACOIN_TESTNET_PUBLIC = 0x04346c97;
var KUMACOIN_TESTNET_PRIVATE = 0x04346d1b;

var BIP32 = function(bytes) {
    // decode base58
    if( typeof bytes === "string" ) {
        var decoded = Bitcoin.Base58.decode(bytes);
        if( decoded.length != 115 ) throw new Error("Not enough data");
        var checksum = decoded.slice(111, 115);
        bytes = decoded.slice(0, 111);

        var hash = Crypto.SHA256( Crypto.SHA256( bytes, { asBytes: true } ), { asBytes: true } );

        if( hash[0] != checksum[0] || hash[1] != checksum[1] || hash[2] != checksum[2] || hash[3] != checksum[3] ) {
            throw new Error("Invalid checksum");
        }
    }

    if( bytes !== undefined ) 
        this.init_from_bytes(bytes);
}

BIP32.prototype.init_from_bytes = function(bytes) {
    // Both pub and private extended keys are 111 bytes
    if( bytes.length != 111 ) throw new Error("not enough data");

    this.version            = u32(bytes.slice(0, 4));
    this.depth              = u8 (bytes.slice(4, 5));
    this.parent_fingerprint = bytes.slice(5, 9);
    this.child_index        = u32(bytes.slice(9, 13));
    this.chain_code         = bytes.slice(13, 45);
    
    var akey_bytes = bytes.slice(45, 78);
    var bkey_bytes = bytes.slice(78, 111);

    var is_private = 
        (this.version == BITCOIN_MAINNET_PRIVATE  ||
         this.version == BITCOIN_TESTNET_PRIVATE  ||
         this.version == DOGECOIN_MAINNET_PRIVATE ||
         this.version == DOGECOIN_TESTNET_PRIVATE ||
         this.version == LITECOIN_MAINNET_PRIVATE ||
         this.version == LITECOIN_TESTNET_PRIVATE ||
         this.version == MONACOIN_MAINNET_PRIVATE ||
         this.version == MONACOIN_TESTNET_PRIVATE ||
         this.version == KUMACOIN_MAINNET_PRIVATE ||
         this.version == KUMACOIN_TESTNET_PRIVATE );

    var is_public = 
        (this.version == BITCOIN_MAINNET_PUBLIC  ||
         this.version == BITCOIN_TESTNET_PUBLIC  ||
         this.version == DOGECOIN_MAINNET_PUBLIC ||
         this.version == DOGECOIN_TESTNET_PUBLIC ||
         this.version == LITECOIN_MAINNET_PUBLIC ||
         this.version == LITECOIN_TESTNET_PUBLIC ||
         this.version == MONACOIN_MAINNET_PUBLIC ||
         this.version == MONACOIN_TESTNET_PUBLIC ||
         this.version == KUMACOIN_MAINNET_PUBLIC ||
         this.version == KUMACOIN_TESTNET_PUBLIC );

    if( is_private && akey_bytes[0] == 0 && bkey_bytes[0] == 0 ) {
        var ecparams = getSECCurveByName("secp256k1");
        this.aeckey = new Bitcoin.ECKey(akey_bytes.slice(1, 33));
        this.beckey = new Bitcoin.ECKey(bkey_bytes.slice(1, 33));
        this.eckey = new Bitcoin.ECKey(this.aeckey.priv.add(this.beckey.priv).mod(ecparams.getN()));
        
        this.aeckey.setCompressed(true);
        this.beckey.setCompressed(true);
        this.eckey.setCompressed(true);

        var apt = ecparams.getG().multiply(this.aeckey.priv);
        var bpt = ecparams.getG().multiply(this.beckey.priv);
        var pt = ecparams.getG().multiply(this.eckey.priv);

        this.aeckey.pub = apt;
        this.beckey.pub = bpt;
        this.eckey.pub = pt;

        this.aeckey.pubKeyHash = Bitcoin.Util.sha256ripe160(this.aeckey.pub.getEncoded(true));
        this.beckey.pubKeyHash = Bitcoin.Util.sha256ripe160(this.beckey.pub.getEncoded(true));
        this.eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(this.eckey.pub.getEncoded(true));
        
        this.has_private_key = true;
    } else if( is_public && (akey_bytes[0] == 0x02 || akey_bytes[0] == 0x03) && (bkey_bytes[0] == 0x02 || bkey_bytes[0] == 0x03) ) {
        this.aeckey = new Bitcoin.ECKey();
        this.beckey = new Bitcoin.ECKey();
        this.eckey = new Bitcoin.ECKey();

        this.aeckey.pub = decompress_pubkey(akey_bytes);
        this.beckey.pub = decompress_pubkey(bkey_bytes);
        this.eckey.pub = this.aeckey.pub.add(this.beckey.pub);

        this.aeckey.pubKeyHash = Bitcoin.Util.sha256ripe160(this.aeckey.pub.getEncoded(true));
        this.beckey.pubKeyHash = Bitcoin.Util.sha256ripe160(this.beckey.pub.getEncoded(true));
        this.eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(this.eckey.pub.getEncoded(true));

        this.aeckey.setCompressed(true);
        this.beckey.setCompressed(true);
        this.eckey.setCompressed(true);

        this.has_private_key = false;
    } else {
        throw new Error("Invalid key");
    }

    this.build_extended_public_key();
    this.build_extended_private_key();
}

BIP32.prototype.build_extended_public_key = function() {
    this.extended_public_key = [];

    var v = null;
    switch(this.version) {
    case BITCOIN_MAINNET_PUBLIC:
    case BITCOIN_MAINNET_PRIVATE:
        v = BITCOIN_MAINNET_PUBLIC;
        break;
    case BITCOIN_TESTNET_PUBLIC:
    case BITCOIN_TESTNET_PRIVATE:
        v = BITCOIN_TESTNET_PUBLIC;
        break;
    case DOGECOIN_MAINNET_PUBLIC:
    case DOGECOIN_MAINNET_PRIVATE:
        v = DOGECOIN_MAINNET_PUBLIC;
        break;
    case DOGECOIN_TESTNET_PUBLIC:
    case DOGECOIN_TESTNET_PRIVATE:
        v = DOGECOIN_TESTNET_PUBLIC;
        break;
    case LITECOIN_MAINNET_PUBLIC:
    case LITECOIN_MAINNET_PRIVATE:
        v = LITECOIN_MAINNET_PUBLIC;
        break;
    case LITECOIN_TESTNET_PUBLIC:
    case LITECOIN_TESTNET_PRIVATE:
        v = LITECOIN_TESTNET_PUBLIC;
        break;
    case MONACOIN_MAINNET_PUBLIC:
    case MONACOIN_MAINNET_PRIVATE:
        v = MONACOIN_MAINNET_PUBLIC;
        break;
    case MONACOIN_TESTNET_PUBLIC:
    case MONACOIN_TESTNET_PRIVATE:
        v = MONACOIN_TESTNET_PUBLIC;
        break;
    case KUMACOIN_MAINNET_PUBLIC:
    case KUMACOIN_MAINNET_PRIVATE:
        v = KUMACOIN_MAINNET_PUBLIC;
        break;
    case KUMACOIN_TESTNET_PUBLIC:
    case KUMACOIN_TESTNET_PRIVATE:
        v = KUMACOIN_TESTNET_PUBLIC;
        break;
     default:
        throw new Error("Unknown version");
    }

    // Version
    this.extended_public_key.push(v >> 24);
    this.extended_public_key.push((v >> 16) & 0xff);
    this.extended_public_key.push((v >> 8) & 0xff);
    this.extended_public_key.push(v & 0xff);

    // Depth
    this.extended_public_key.push(this.depth);

    // Parent fingerprint
    this.extended_public_key = this.extended_public_key.concat(this.parent_fingerprint);

    // Child index
    this.extended_public_key.push(this.child_index >>> 24);
    this.extended_public_key.push((this.child_index >>> 16) & 0xff);
    this.extended_public_key.push((this.child_index >>> 8) & 0xff);
    this.extended_public_key.push(this.child_index & 0xff);

    // Chain code
    this.extended_public_key = this.extended_public_key.concat(this.chain_code);

    // Public keys
    this.extended_public_key = this.extended_public_key.concat(this.aeckey.pub.getEncoded(true));
    this.extended_public_key = this.extended_public_key.concat(this.beckey.pub.getEncoded(true));
}

BIP32.prototype.extended_public_key_string = function(format) {
    if( format === undefined || format === "base58" ) {
        var hash = Crypto.SHA256( Crypto.SHA256( this.extended_public_key, { asBytes: true } ), { asBytes: true } );
        var checksum = hash.slice(0, 4);
        var data = this.extended_public_key.concat(checksum);
        return Bitcoin.Base58.encode(data);
    } else if( format === "hex" ) {
        return Crypto.util.bytesToHex(this.extended_public_key);
    } else {
        throw new Error("bad format");
    }
}

BIP32.prototype.build_extended_private_key = function() {
    if( !this.has_private_key ) return;
    this.extended_private_key = [];

    var v = this.version;

    // Version
    this.extended_private_key.push(v >> 24);
    this.extended_private_key.push((v >> 16) & 0xff);
    this.extended_private_key.push((v >> 8) & 0xff);
    this.extended_private_key.push(v & 0xff);

    // Depth
    this.extended_private_key.push(this.depth);

    // Parent fingerprint
    this.extended_private_key = this.extended_private_key.concat(this.parent_fingerprint);

    // Child index
    this.extended_private_key.push(this.child_index >>> 24);
    this.extended_private_key.push((this.child_index >>> 16) & 0xff);
    this.extended_private_key.push((this.child_index >>> 8) & 0xff);
    this.extended_private_key.push(this.child_index & 0xff);

    // Chain code
    this.extended_private_key = this.extended_private_key.concat(this.chain_code);

    // Private key
    var ak = this.aeckey.priv.toByteArrayUnsigned();
    var bk = this.beckey.priv.toByteArrayUnsigned();

    while (ak.length < 32) {
        ak.unshift(0);
    }
    while (bk.length < 32) {
        bk.unshift(0);
    }

    this.extended_private_key.push(0);
    this.extended_private_key = this.extended_private_key.concat(ak);
    this.extended_private_key.push(0);
    this.extended_private_key = this.extended_private_key.concat(bk);
}

BIP32.prototype.extended_private_key_string = function(format) {
    if( format === undefined || format === "base58" ) {
        var hash = Crypto.SHA256( Crypto.SHA256( this.extended_private_key, { asBytes: true } ), { asBytes: true } );
        var checksum = hash.slice(0, 4);
        var data = this.extended_private_key.concat(checksum);
        return Bitcoin.Base58.encode(data);
    } else if( format === "hex" ) {
        return Crypto.util.bytesToHex(this.extended_private_key);
    } else {
        throw new Error("bad format");
    }
}


BIP32.prototype.derive = function(path) {
    var e = path.split('/');

    // Special cases:
    if( path == 'm' || path == 'M' || path == 'm\'' || path == 'M\'' ) return this;

    if( path.toLowerCase().search('m/k') != -1 || path.toLowerCase().search('n/k') != -1 ) {
        throw new Error("invalid path");
    };

    var bip32 = this;
    var i;
    for(i = 0; i < e.length; i++) {
        var c = e[i];

        if( i == 0 ) {
            if( c != 'm' ) throw new Error("invalid path");
            continue;
        };

        // Figure out how to deal with key / node indexes
        if (c == 'n'){
            var child_index = 'n';
            bip32 = bip32.derive_child(child_index);
        } else if (c == 'k') {
            var child_index = 'k';
        } else if (i + 1 == e.length) {
            var child_index = parseInt(c);
            e[i] = 'k';
            i = i - 1;
        } else {
            var child_index = parseInt(c);
        }

        bip32 = bip32.derive_child(child_index);
    }

    return bip32;
}

BIP32.prototype.derive_child = function(idx) {
    var ib = [];
    if (idx == 'n') {
        ib.push(0x00);
        ib.push(0xff);
        ib.push(0xff);
        ib.push(0xff);
        ib.push(0xff);
    } else if (idx == 'k') {
        ib.push(0x01);
        ib.push(0xff);
        ib.push(0xff);
        ib.push(0xff);
        ib.push(0xff);
    } else {
        ib.push( (idx >> 24) & 0xff );
        ib.push( (idx >> 16) & 0xff );
        ib.push( (idx >>  8) & 0xff );
        ib.push( idx & 0xff );
    };
    console.log( ib );

    var ecparams = getSECCurveByName("secp256k1");

    var is_private = 
        (this.version == BITCOIN_MAINNET_PRIVATE  ||
         this.version == BITCOIN_TESTNET_PRIVATE  ||
         this.version == DOGECOIN_MAINNET_PRIVATE ||
         this.version == DOGECOIN_TESTNET_PRIVATE ||
         this.version == LITECOIN_MAINNET_PRIVATE ||
         this.version == LITECOIN_TESTNET_PRIVATE ||
         this.version == MONACOIN_MAINNET_PRIVATE ||
         this.version == MONACOIN_TESTNET_PRIVATE ||
         this.version == KUMACOIN_MAINNET_PRIVATE ||
         this.version == KUMACOIN_TESTNET_PRIVATE );

    var ret = null;
    if( this.has_private_key ) {
        var adata = null;
        var bdata = null;

        adata = this.aeckey.pub.getEncoded(true).concat(ib);
        bdata = this.beckey.pub.getEncoded(true).concat(ib);

        var ah = new jsSHA(Crypto.util.bytesToHex(adata), 'HEX'); 
        var bh = new jsSHA(Crypto.util.bytesToHex(bdata), 'HEX'); 
        var ahash = ah.getHMAC(Crypto.util.bytesToHex(this.chain_code), "HEX", "SHA-512", "HEX");
        var bhash = bh.getHMAC(Crypto.util.bytesToHex(this.chain_code), "HEX", "SHA-512", "HEX");
        var ail = new BigInteger(ahash.slice(0, 64), 16);
        var bil = new BigInteger(bhash.slice(0, 64), 16);
        var air = Crypto.util.hexToBytes(ahash.slice(64, 128));
        var bir = Crypto.util.hexToBytes(bhash.slice(64, 128));
        var ir = Crypto.util.hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
        for (i = 0; i < 32; i++) {
            ir[i] = air[i] ^ bir[i];
        };

        // ki = IL + kpar (mod n).
        var curve = ecparams.getCurve();
        var ak = ail.multiply(this.aeckey.priv).mod(ecparams.getN());
        var bk = bil.multiply(this.beckey.priv).mod(ecparams.getN());

        ret = new BIP32();
        ret.chain_code  = ir;

        ret.aeckey = new Bitcoin.ECKey(ak.toByteArrayUnsigned());
        ret.beckey = new Bitcoin.ECKey(bk.toByteArrayUnsigned());
        ret.eckey = new Bitcoin.ECKey(ret.aeckey.priv.add(ret.beckey.priv).mod(ecparams.getN()));
        ret.aeckey.pub = ret.aeckey.getPubPoint();
        ret.beckey.pub = ret.beckey.getPubPoint();
        ret.eckey.pub = ret.beckey.getPubPoint();
        ret.has_private_key = true;

    } else {
        var adata = this.aeckey.pub.getEncoded(true).concat(ib);
        var bdata = this.beckey.pub.getEncoded(true).concat(ib);

        var ah = new jsSHA(Crypto.util.bytesToHex(adata), 'HEX'); 
        var bh = new jsSHA(Crypto.util.bytesToHex(bdata), 'HEX'); 
        var ahash = ah.getHMAC(Crypto.util.bytesToHex(this.chain_code), "HEX", "SHA-512", "HEX");
        var bhash = bh.getHMAC(Crypto.util.bytesToHex(this.chain_code), "HEX", "SHA-512", "HEX");
        var ail = new BigInteger(ahash.slice(0, 64), 16);
        var bil = new BigInteger(bhash.slice(0, 64), 16);
        var air = Crypto.util.hexToBytes(ahash.slice(64, 128));
        var bir = Crypto.util.hexToBytes(bhash.slice(64, 128));
        var ir = Crypto.util.hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
        for (i = 0; i < 32; i++) {
            ir[i] = air[i] ^ bir[i];
        };

        // Ki = (IL + kpar)*G = IL*G + Kpar
        var ak = this.aeckey.pub.multiply(ail);
        var bk = this.beckey.pub.multiply(bil);

        ret = new BIP32();
        ret.chain_code  = ir;

        ret.aeckey = new Bitcoin.ECKey();
        ret.beckey = new Bitcoin.ECKey();
        ret.eckey = new Bitcoin.ECKey();

        ret.aeckey.pub = ak;
        ret.beckey.pub = bk;
        ret.eckey.pub = ak.add(bk);
        ret.has_private_key = false;
    }

    // Make sure the child index stays the same if deriving a node or key.
    if (idx == 'n' || idx == 'k') {
        ret.child_index = this.child_index
    } else {
        ret.child_index = idx;
    }
    // fingerprint is 2 bytes from the head of each pubkeyhash.
    ret.parent_fingerprint = this.eckey.pubKeyHash.slice(0,4);
    ret.version = this.version;
    ret.depth   = this.depth + 1;

    ret.aeckey.setCompressed(true);
    ret.aeckey.pubKeyHash = Bitcoin.Util.sha256ripe160(ret.aeckey.pub.getEncoded(true));
    ret.beckey.setCompressed(true);
    ret.beckey.pubKeyHash = Bitcoin.Util.sha256ripe160(ret.beckey.pub.getEncoded(true));
    ret.eckey.setCompressed(true);
    ret.eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(ret.eckey.pub.getEncoded(true));

    ret.build_extended_public_key();
    ret.build_extended_private_key();

    return ret;
}


function uint(f, size) {
    if (f.length < size)
        throw new Error("not enough data");
    var n = 0;
    for (var i = 0; i < size; i++) {
        n *= 256;
        n += f[i];
    }
    return n;
}

function u8(f)  { return uint(f,1); }
function u16(f) { return uint(f,2); }
function u32(f) { return uint(f,4); }
function u64(f) { return uint(f,8); }

function decompress_pubkey(key_bytes) {
    var y_bit = u8(key_bytes.slice(0, 1)) & 0x01;
    var ecparams = getSECCurveByName("secp256k1");

    // build X
    var x     = BigInteger.ZERO.clone();
    x.fromString(Crypto.util.bytesToHex(key_bytes.slice(1, 33)), 16);
    
    // get curve
    var curve = ecparams.getCurve();
    var a = curve.getA().toBigInteger();
    var b = curve.getB().toBigInteger();
    var p = curve.getQ();
    
    // compute y^2 = x^3 + a*x + b
    var tmp = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
    
    // compute modular square root of y (mod p)
    var y = tmp.modSqrt(p);
    
    // flip sign if we need to
    if( (y[0] & 0x01) != y_bit ) {
        y = y.multiply(new BigInteger("-1")).mod(p);
    }
    
    return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
}

