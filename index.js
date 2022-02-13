/*
  Copyright 2021 Fix Payments Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

'use strict';

const pbtx_pb = require('./lib/pbtx_pb');
const EC = require('elliptic').ec;
const { PrivateKey } = require('eosjs/dist/PrivateKey');
const { PublicKey } = require('eosjs/dist/PublicKey');
const { Signature } = require('eosjs/dist/Signature');
const { SerialBuffer } = require('eosjs/dist/eosjs-serialize');

const defaultEc = new EC('secp256k1');

class PbtxFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = "PbtxFormatError";
  }
}

class PbtxUnknownAccountError extends Error {
  constructor(message) {
    super(message);
    this.name = "PbtxUnknownAccountError";
  }
}

class PbtxTxSeqError extends Error {
  constructor(message) {
    super(message);
    this.name = "PbtxTxSeqError";
  }
}

class PbtxAuthorizationError extends Error {
  constructor(message) {
    super(message);
    this.name = "PbtxAuthorizationError";
  }
}


class PBTX {
    // takes permission attributes
    // returns a Permission protobuf object
    static makePermission(data) {
        let actor = BigInt(data.actor);

        if( !Number.isInteger(data.threshold) ) {
            throw Error('threshold must be an integer');
        }

        if( data.threshold == 0 ) {
            throw Error('threshold must be a positive integer');
        }

        if( !Array.isArray(data.keys) ) {
            throw Error('keys must be an array');
        }


        let perm = new pbtx_pb.Permission();
        perm.setActor(actor.toString());
        perm.setThreshold(data.threshold);

        data.keys.forEach( keyweight => {
            if( !Number.isInteger(keyweight.weight) ) {
                throw Error('key weight must be an integer');
            }

            if( keyweight.weight == 0 ) {
                throw Error('key weight must be a positive integer');
            }

            if( keyweight.key == null ) {
                throw Error('key must be defined');
            }

            let buffer = new SerialBuffer();
            buffer.pushPublicKey(keyweight.key);

            let pk = new pbtx_pb.PublicKey();
            pk.setType(pbtx_pb.KeyType.EOSIO_KEY);
            pk.setKeyBytes(buffer.asUint8Array());

            let kw = new pbtx_pb.KeyWeight();
            kw.setKey(pk);
            kw.setWeight(keyweight.weight);

            perm.addKeys(kw);
        });

        return perm;
    }


    static permissionToObject(perm) {
        let data = {
            actor: perm.getActor(),
            threshold: perm.getThreshold(),
            keys: new Array()
        };

        perm.getKeysList().forEach(keyweight => {
            let key = keyweight.getKey();
            if( key.getType() != pbtx_pb.KeyType.EOSIO_KEY ) {
                throw Error('unsupported key type: ' + key.getType());
            }
            let buffer = new SerialBuffer()
            buffer.pushArray(key.getKeyBytes());

            const keyNewFormat = buffer.getPublicKey();

            data.keys.push({weight: keyweight.getWeight(),  key: keyNewFormat});
        });

        return data;
    }


    // takes TransactionBody attributes
    // returns a Permission protobuf object
    static makeTransactionBody(data) {
        let tb = new pbtx_pb.TransactionBody();

        if( data.network_id == null || typeof(data.network_id) !== 'bigint' ) {
            throw Error('network_id must be a BigInt');
        }

        tb.setNetworkId(data.network_id.toString());

        if( data.actor == null || typeof(data.actor) !== 'bigint' ) {
            throw Error('actor must be a BigInt');
        }

        tb.setActor(data.actor.toString());

        if( data.cosignors ) {
            if( !Array.isArray(data.cosignors) ) {
                throw Error('cosignors must be an array');
            }

            data.cosignors.forEach( account => {
                if( typeof(account) !== 'bigint' ) {
                    throw Error('cosignors must be BigInt');
                }
                tb.addCosignor(account.toString());
            });
        }

        if( !Number.isInteger(data.seqnum) || data.seqnum < 1 ) {
            throw Error('seqnum must be a positive integer: ' + data.seqnum);
        }

        tb.setSeqnum(data.seqnum);

        if( data.prev_hash == null || typeof(data.prev_hash) !== 'bigint' ) {
            throw Error('prev_hash must be a BigInt');
        }

        tb.setPrevHash(data.prev_hash.toString());

        if( !Number.isInteger(data.transaction_type) || data.transaction_type < 0 ) {
            throw Error('transaction_type must be an unsigned integer: ' + data.transaction_type);
        }

        tb.setTransactionType(data.transaction_type);

        if( data.transaction_content ) {
            tb.setTransactionContent(data.transaction_content);
        }

        return tb;
    }

    // returns 64-bit BigInt that is a value passed to the next
    // transaction as prev_hash
    static getBodyHash(body) {
        const serializedBody = body.serializeBinary();
        const digest = defaultEc.hash().update(serializedBody).digest();

        let bodyhash = BigInt(0);
        for( let i=0; i < 8; i++ ) {
            bodyhash = (bodyhash << 8n) | BigInt(digest[i]);
        }
        return bodyhash;
    }

    // takes a message in a Buffer and a ECC private keys in EOSIO text format
    // returns pbtx.Authority object
    static signData(data, privateKeys) {
        const digest = defaultEc.hash().update(data).digest();

        let auth = new pbtx_pb.Authority();
        auth.setType(pbtx_pb.KeyType.EOSIO_KEY);

        privateKeys.forEach( key => {
            const priv = PrivateKey.fromString(key);
            const signature = priv.sign(digest, false);

            let buffer = new SerialBuffer();
            buffer.push(signature.signature.type);
            buffer.pushArray(signature.signature.data);

            auth.addSigs(buffer.asUint8Array());
        });

        return auth;
    }

    s
    // gets TransactionBody object and array of private keys in string format
    // creates a separate Authority object for each private key
    // returns Transaction object
    static signTransactionBody(body, privateKeys) {
        const serializedBody = body.serializeBinary();
        let tx = new pbtx_pb.Transaction();
        tx.setBody(serializedBody);
        privateKeys.forEach( key => {
            let auth = this.signData(serializedBody, new Array(key));
            tx.addAuthorities(auth);
        });

        return tx;
    }


    static verifyAuthority(data, permission, authority, verbose) {
        let signatures = authority.getSigsList();
        let keyweights = permission.getKeysList();
        const digest = defaultEc.hash().update(data).digest();

        let weight_sum = 0;
        for( let sig_index = 0; sig_index < signatures.length; sig_index++ ) {
            let sig_buf = signatures[sig_index];
            let signature = new Signature({
                type: sig_buf[0],
                data: sig_buf.subarray(1)
            }, defaultEc);

            for( let key_index = 0; key_index < keyweights.length; key_index++ ) {
                let keyweight = keyweights[key_index];
                let key = keyweight.getKey();
                let key_buf = key.getKeyBytes();
                let pubkey = new PublicKey({
                    type: key_buf[0],
                    data: key_buf.subarray(1)
                }, defaultEc);

                if( signature.verify(digest, pubkey, false) ) {
                    if( verbose ) {
                        console.log("Signature #" + sig_index + " matched key: " + pubkey.toString());
                    }
                    weight_sum += keyweight.getWeight();
                    break;
                }
            }
        }

        if( weight_sum == 0 ) {
            throw new PbtxAuthorizationError("Could not find a matching signature for actor " + acc);
        }
        else if( weight_sum < permission.getThreshold() ) {
            throw new PbtxAuthorizationError("Insufficient signatures for actor " + acc);
        }
    }


    static async setPermission(network_id, perm, api, contract, admin) {
        return api.transact(
            {
                actions:
                [
                    {
                        account: contract,
                        name: 'regactor',
                        authorization: [{
                            actor: admin,
                            permission: 'active'} ],
                        data: {
                            network_id: network_id.toString(),
                            permission: perm.serializeBinary()
                        },
                    }
                ]
            },
            {
                blocksBehind: 100,
                expireSeconds: 3600
            });
    }


    static async sendTransaction(tx, api, contract, worker) {
        // console.log(Buffer.from(tx.serializeBinary()).toString('hex'));
        return api.transact(
            {
                actions:
                [
                    {
                        account: contract,
                        name: 'exectrx',
                        authorization: [{
                            actor: worker,
                            permission: 'active'} ],
                        data: {
                            worker: worker,
                            trx_input: tx.serializeBinary()
                        },
                    }
                ]
            },
            {
                blocksBehind: 100,
                expireSeconds: 3600
            });
    }

    static async validateTransaction(txbinary, api, contract, verbose) {
        let tx = pbtx_pb.Transaction.deserializeBinary(txbinary);
        let body_buf = tx.getBody();
        let body = pbtx_pb.TransactionBody.deserializeBinary(body_buf);
        let network_id = body.getNetworkId();
        let actor = body.getActor();

        if( network_id == 0 ) { return Promise.reject(new PbtxFormatError("network_id must not be zero")); }
        if( actor == 0 ) { return Promise.reject(new PbtxFormatError("actor must not be zero")); }

        let seqres = await api.rpc.get_table_rows({
            code: contract,
            scope: network_id,
            table: 'actorseq',
            lower_bound: actor,
            limit: 1
        });

        if( seqres.rows.length == 0 || seqres.rows[0].actor != actor ) {
            return Promise.reject(new PbtxUnknownAccountError("Unknown actor #" + actor));
        }

        let actorseq = seqres.rows[0];
        if( body.getSeqnum() != actorseq.seqnum + 1 ) {
            return Promise.reject(new PbtxTxSeqError("Invalid sequence number " + body.getSeqnum() + " for actor #" + actor +
                                                 ", expected: " + (actorseq.seqnum + 1)));
        }

        if( BigInt(body.getPrevHash()) != BigInt(actorseq.prev_hash) ) {
            return Promise.reject(new PbtxTxSeqError("Invalid prev_hash " + body.getPrevHash() + " for actor #" + actor +
                                                 ", expected: " + BigInt(actorseq.prev_hash).toString()));
        }

        let signors = new Array();
        signors.push(actor);
        if( verbose ) {
            console.log("network_id: " + network_id);
            console.log("actor: " + actor);
        }
        body.getCosignorsList().forEach(acc => {
            signors.push(acc);
            console.log("co-signor: " + acc);
        });

        let authorities = tx.getAuthoritiesList();
        if( authorities.length != signors.length ) {
            return Promise.reject(new PbtxFormatError("number of authorities is not equal to number of signors: " +
                                                  authorities.length + " vs. " + signors.length));
        }

        for( let auth_index = 0; auth_index < signors.length; auth_index++ ) {
            let acc = signors[auth_index];
            let auth = authorities[auth_index];
            if( auth.getType() != pbtx_pb.KeyType['EOSIO_KEY'] ) {
                return Promise.reject(new PbtxFormatError("Unsupported key type in authority #" + auth_index + ": " + auth.getType()));
            }

            let res = await api.rpc.get_table_rows({
                code: contract,
                scope: network_id,
                table: 'actorperm',
                lower_bound: acc,
                limit: 1
            });

            if( res.rows.length == 0 || res.rows[0].actor != acc ) {
                return Promise.reject(new PbtxUnknownAccountError("Unknown actor #" + acc + " in authority #" + auth_index));
            }

            let perm = pbtx_pb.Permission.deserializeBinary(Buffer.from(res.rows[0].permission, 'hex'));

            try {
                this.verifyAuthority(body_buf, perm, auth, verbose);
            }
            catch(e) {
                return Promise.reject(e);
            }
        }
    }
}



module.exports = PBTX;
