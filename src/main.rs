use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, XOnlyPublicKey};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_DROP};
use bitcoin::psbt::{self, Input, Output, Psbt, PsbtSighashType};
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::sighash::{self, Prevouts, SighashCache, TapSighash, TapSighashType};
use bitcoin::taproot::{self, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    absolute, script, transaction, Address, Amount, Network, OutPoint, ScriptBuf, Transaction,
    TxIn, TxOut, Witness,
};
use rand::Rng;
use std::collections::BTreeMap;
use std::str::FromStr;

const BENEFACTOR_XPRIV_STR: &str = "tprv8ZgxMBicQKsPd4arFr7sKjSnKFDVMR2JHw9Y8L9nXN4kiok4u28LpHijEudH3mMYoL4pM5UL9Bgdz2M4Cy8EzfErmU9m86ZTw6hCzvFeTg7";
const BENEFICIARY_XPRIV_STR: &str = "tprv8ZgxMBicQKsPe72C5c3cugP8b7AzEuNjP4NSC17Dkpqk5kaAmsL6FHwPsVxPpURVqbNwdLAbNqi8Cvdq6nycDwYdKHDjDRYcsMzfshimAUq";
const BIP86_DERIVATION_PATH: &str = "m/86'/1'/0'/0/0";

const UTXO_SCRIPT_PUBKEY: &str =
    "5120be27fa8b1f5278faf82cab8da23e8761f8f9bd5d5ebebbb37e0e12a70d92dd16";
const UTXO_PUBKEY: &str = "a6ac32163539c16b6b5dbbca01b725b8e8acaa5f821ba42c80e7940062140d19";
const UTXO_MASTER_FINGERPRINT: &str = "e61b318f";
const ABSOLUTE_FEES_IN_SATS: Amount = Amount::from_sat(1_000);

// UTXO_1 will be used for spending example 1
const UTXO_1: P2trUtxo = P2trUtxo {
    txid: "a85d89b4666fed622281d3589474aa1f87971b54bd5d9c1899ed2e8e0447cc06",
    vout: 0,
    script_pubkey: UTXO_SCRIPT_PUBKEY,
    pubkey: UTXO_PUBKEY,
    master_fingerprint: UTXO_MASTER_FINGERPRINT,
    amount_in_sats: Amount::from_int_btc(50),
    derivation_path: BIP86_DERIVATION_PATH,
};

// UTXO_2 will be used for spending example 2
const UTXO_2: P2trUtxo = P2trUtxo {
    txid: "6f1c1df5862a67f4b6d1cde9a87e3c441b483ba6a140fbec2815f03aa3a5309d",
    vout: 0,
    script_pubkey: UTXO_SCRIPT_PUBKEY,
    pubkey: UTXO_PUBKEY,
    master_fingerprint: UTXO_MASTER_FINGERPRINT,
    amount_in_sats: Amount::from_int_btc(50),
    derivation_path: BIP86_DERIVATION_PATH,
};

// UTXO_3 will be used for spending example 3
const UTXO_3: P2trUtxo = P2trUtxo {
    txid: "9795fed5aedca219244a396dfd7bce55c851274418383c3ab43530e3f74e5dcc",
    vout: 0,
    script_pubkey: UTXO_SCRIPT_PUBKEY,
    pubkey: UTXO_PUBKEY,
    master_fingerprint: UTXO_MASTER_FINGERPRINT,
    amount_in_sats: Amount::from_int_btc(50),
    derivation_path: BIP86_DERIVATION_PATH,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();

    println!("\n----------------");
    println!("\nSTART EXAMPLE 1 - P2TR with a BIP86 commitment, signed with internal key\n");

    // Just some addresses for outputs from our wallets. Not really important.
    let to_address =
        Address::from_str("bcrt1p0p3rvwww0v9znrclp00uneq8ytre9kj922v8fxhnezm3mgsmn9usdxaefc")?
            .require_network(Network::Regtest)?;
    let change_address =
        Address::from_str("bcrt1pz449kexzydh2kaypatup5ultru3ej284t6eguhnkn6wkhswt0l7q3a7j76")?
            .require_network(Network::Regtest)?;
    let amount_to_send_in_sats = Amount::ONE_BTC;
    let change_amount = UTXO_1
        .amount_in_sats
        .checked_sub(amount_to_send_in_sats)
        .and_then(|x| x.checked_sub(ABSOLUTE_FEES_IN_SATS))
        .ok_or("Fees more than input amount!")?;

    let tx_hex_string = encode::serialize_hex(&generate_bip86_key_spend_tx(
        &secp,
        // The master extended private key from the descriptor in step 4
        Xpriv::from_str(BENEFACTOR_XPRIV_STR)?,
        // Set these fields with valid data for the UTXO from step 5 above
        UTXO_1,
        vec![
            TxOut {
                value: amount_to_send_in_sats,
                script_pubkey: to_address.script_pubkey(),
            },
            TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    )?);
    println!(
        "\nYou should now be able to broadcast the following transaction: \n\n{}",
        tx_hex_string
    );

    println!("\nEND EXAMPLE 1\n");
    println!("----------------\n");

    println!("START EXAMPLE 2 - Script path spending of inheritance UTXO\n");

    {
        let beneficiary = BeneficiaryWallet::new(Xpriv::from_str(BENEFICIARY_XPRIV_STR)?)?;

        let mut benefactor = BenefactorWallet::new(
            Xpriv::from_str(BENEFACTOR_XPRIV_STR)?,
            beneficiary.master_xpub(),
        )?;
        let (tx, psbt) = benefactor.create_inheritance_funding_tx(
            absolute::LockTime::from_height(1000).unwrap(),
            UTXO_2,
        )?;
        let tx_hex = encode::serialize_hex(&tx);

        println!("Inheritance funding tx hex:\n\n{}", tx_hex);
        // You can now broadcast the transaction hex:
        // bt sendrawtransaction ...
        //
        // And mine a block to confirm the transaction:
        // bt generatetoaddress 1 $(bt-benefactor getnewaddress '' 'bech32m')

        let spending_tx = beneficiary.spend_inheritance(
            psbt,
            absolute::LockTime::from_height(1000).unwrap(),
            to_address,
        )?;
        let spending_tx_hex = encode::serialize_hex(&spending_tx);
        println!("\nInheritance spending tx hex:\n\n{}", spending_tx_hex);
        // If you try to broadcast now, the transaction will be rejected as it is timelocked.
        // First mine 900 blocks so we're sure we are over the 1000 block locktime:
        // bt generatetoaddress 900 $(bt-benefactor getnewaddress '' 'bech32m')
        // Then broadcast the transaction with `bt sendrawtransaction ...`
    }

    println!("\nEND EXAMPLE 2\n");
    println!("----------------\n");

    println!("START EXAMPLE 3 - Key path spending of inheritance UTXO\n");

    {
        let beneficiary = BeneficiaryWallet::new(Xpriv::from_str(BENEFICIARY_XPRIV_STR)?)?;

        let mut benefactor = BenefactorWallet::new(
            Xpriv::from_str(BENEFACTOR_XPRIV_STR)?,
            beneficiary.master_xpub(),
        )?;
        let (tx, _) = benefactor.create_inheritance_funding_tx(
            absolute::LockTime::from_height(2000).unwrap(),
            UTXO_3,
        )?;
        let tx_hex = encode::serialize_hex(&tx);

        println!("Inheritance funding tx hex:\n\n{}", tx_hex);
        // You can now broadcast the transaction hex:
        // bt sendrawtransaction ...
        //
        // And mine a block to confirm the transaction:
        // bt generatetoaddress 1 $(bt-benefactor getnewaddress '' 'bech32m')

        // At some point we may want to extend the locktime further into the future for the beneficiary.
        // We can do this by "refreshing" the inheritance transaction as the benefactor. This effectively
        // spends the inheritance transaction via the key path of the taproot output, and is not encumbered
        // by the timelock so we can spend it immediately. We set up a new output similar to the first with
        // a locktime that is 'locktime_delta' blocks greater.
        let (tx, _) = benefactor.refresh_tx(1000)?;
        let tx_hex = encode::serialize_hex(&tx);

        println!("\nRefreshed inheritance tx hex:\n\n{}\n", tx_hex);

        println!("\nEND EXAMPLE 3\n");
        println!("----------------\n");
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct P2trUtxo<'a> {
    txid: &'a str,
    vout: u32,
    script_pubkey: &'a str,
    pubkey: &'a str,
    master_fingerprint: &'a str,
    amount_in_sats: Amount,
    derivation_path: &'a str,
}

#[allow(clippy::single_element_loop)]
fn generate_bip86_key_spend_tx(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    master_xpriv: Xpriv,
    input_utxo: P2trUtxo,
    outputs: Vec<TxOut>,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let from_amount = input_utxo.amount_in_sats;
    let input_pubkey = XOnlyPublicKey::from_str(input_utxo.pubkey)?;
    let mut rng = rand::thread_rng();
    let nonce: u32 = rng.gen_range(0..100000000);
    let unix_time: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // CREATOR + UPDATER
    let tx1 = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: input_utxo.txid.parse()?,
                vout: input_utxo.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence(0xFFFFFFFF), // Ignore nSequence.
            witness: Witness::default(),
        }],
        output: outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx1)?;

    let mut origins = BTreeMap::new();
    origins.insert(
        input_pubkey,
        (
            vec![],
            (
                Fingerprint::from_str(input_utxo.master_fingerprint)?,
                DerivationPath::from_str(input_utxo.derivation_path)?,
            ),
        ),
    );

    let mut input = Input {
        witness_utxo: {
            let script_pubkey = ScriptBuf::from_hex(input_utxo.script_pubkey)
                .expect("failed to parse input utxo scriptPubkey");
            Some(TxOut {
                value: from_amount,
                script_pubkey,
            })
        },
        tap_key_origins: origins,
        ..Default::default()
    };
    let ty = PsbtSighashType::from_str("SIGHASH_ALL")?;
    input.sighash_type = Some(ty);
    input.tap_internal_key = Some(input_pubkey);
    psbt.inputs = vec![input];

    // The `Prevouts::All` array is used to create the sighash to sign for each input in the
    // `psbt.inputs` array, as such it must be the same length and in the same order as the inputs.
    let mut input_txouts = Vec::<TxOut>::new();
    for input in [&input_utxo].iter() {
        input_txouts.push(TxOut {
            value: input.amount_in_sats,
            script_pubkey: ScriptBuf::from_hex(input.script_pubkey)?,
        });
    }

    // SIGNER
    let unsigned_tx = psbt.unsigned_tx.clone();
    psbt.inputs
        .iter_mut()
        .enumerate()
        .try_for_each::<_, Result<(), Box<dyn std::error::Error>>>(|(vout, input)| {
            let hash_ty = input
                .sighash_type
                .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
                .unwrap_or(TapSighashType::All);
            let hash = SighashCache::new(&unsigned_tx).taproot_key_spend_signature_hash(
                vout,
                &sighash::Prevouts::All(input_txouts.as_slice()),
                hash_ty,
            )?;

            let (_, (_, derivation_path)) = input
                .tap_key_origins
                .get(
                    &input
                        .tap_internal_key
                        .ok_or("Internal key missing in PSBT")?,
                )
                .ok_or("Missing taproot key origin")?;

            let secret_key = master_xpriv
                .derive_priv(secp, &derivation_path)?
                .to_priv()
                .inner;
            sign_psbt_taproot(
                &secret_key,
                input.tap_internal_key.unwrap(),
                None,
                input,
                hash,
                hash_ty,
                secp,
            );

            Ok(())
        })?;

    // FINALIZER
    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();
        script_witness.push(input.tap_key_sig.unwrap().to_vec());
        input.final_script_witness = Some(script_witness);

        // Clear all the data fields as per the spec.
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });

    // EXTRACTOR
    let tx = psbt.extract_tx_unchecked_fee_rate();

    Ok(tx)
}

#[allow(clippy::single_element_loop)]
fn atomicals_key_spend_tx(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    master_xpriv: Xpriv,
    utxos: &[P2trUtxo],
    outputs: Vec<TxOut>,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let nonce: u32 = rng.gen_range(0..100000000);
    let unix_time: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: utxos
            .iter()
            .map(|utxo| TxIn {
                previous_output: OutPoint {
                    txid: utxo.txid.parse().unwrap(),
                    vout: utxo.vout,
                },
                script_sig: Default::default(),
                sequence: bitcoin::Sequence(0xFFFFFFFF),
                witness: Default::default(),
            })
            .collect(),
        output: outputs,
    };

    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    let input_txouts: Vec<TxOut> = utxos
        .iter()
        .map(|utxo| TxOut {
            value: utxo.amount_in_sats,
            script_pubkey: ScriptBuf::from_hex(utxo.script_pubkey).unwrap(),
        })
        .collect();

    // SIGNER
    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut sighash_cache = SighashCache::new(&unsigned_tx);
    for (i, utxo) in utxos.iter().enumerate() {
        let input_pubkey = bitcoin::XOnlyPublicKey::from_str(utxo.pubkey)?;
        let mut origins = BTreeMap::new();
        origins.insert(
            input_pubkey,
            (
                vec![],
                (
                    Fingerprint::from_str(utxo.master_fingerprint)?,
                    DerivationPath::from_str(utxo.derivation_path)?,
                ),
            ),
        );

        let mut input = Input {
            witness_utxo: Some(input_txouts[i].clone()),
            tap_key_origins: origins,
            sighash_type: Some(PsbtSighashType::from(TapSighashType::All)),
            tap_internal_key: Some(input_pubkey),
            ..Default::default()
        };

        let hash = sighash_cache.taproot_key_spend_signature_hash(
            i,
            &Prevouts::All(&input_txouts),
            TapSighashType::All,
        )?;

        let derivation_path = DerivationPath::from_str(utxo.derivation_path)?;
        let secret_key = master_xpriv
            .derive_priv(&secp, &derivation_path)?
            .private_key;

        sign_psbt_taproot(
            &secret_key,
            input.tap_internal_key.unwrap(),
            None,
            &mut input,
            hash,
            TapSighashType::All,
            secp,
        );

        psbt.inputs[i] = input;
    }

    // Finalize and extract the transaction
    for input in &mut psbt.inputs {
        let mut script_witness = bitcoin::Witness::new();
        script_witness.push(input.tap_key_sig.unwrap().to_vec());
        input.final_script_witness = Some(script_witness);

        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    }

    Ok(psbt.extract_tx_unchecked_fee_rate())
}

/// A wallet that allows creating and spending from an inheritance directly via the key path for purposes
/// of refreshing the inheritance timelock or changing other spending conditions.
struct BenefactorWallet {
    master_xpriv: Xpriv,
    beneficiary_xpub: Xpub,
    current_spend_info: Option<TaprootSpendInfo>,
    next_psbt: Option<Psbt>,
    secp: Secp256k1<secp256k1::All>,
    next: ChildNumber,
}

impl BenefactorWallet {
    fn new(
        master_xpriv: Xpriv,
        beneficiary_xpub: Xpub,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            master_xpriv,
            beneficiary_xpub,
            current_spend_info: None,
            next_psbt: None,
            secp: Secp256k1::new(),
            next: ChildNumber::from_normal_idx(0).expect("Zero is a valid child number"),
        })
    }

    fn time_lock_script(
        locktime: absolute::LockTime,
        beneficiary_key: XOnlyPublicKey,
    ) -> ScriptBuf {
        script::Builder::new()
            .push_int(locktime.to_consensus_u32() as i64)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&beneficiary_key)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn create_inheritance_funding_tx(
        &mut self,
        lock_time: absolute::LockTime,
        input_utxo: P2trUtxo,
    ) -> Result<(Transaction, Psbt), Box<dyn std::error::Error>> {
        if let ChildNumber::Normal { index } = self.next {
            if index > 0 && self.current_spend_info.is_some() {
                return Err("Transaction already exists, use refresh_inheritance_timelock to refresh the timelock".into());
            }
        }
        // We use some other derivation path in this example for our inheritance protocol. The important thing is to ensure
        // that we use an unhardened path so we can make use of xpubs.
        let derivation_path = DerivationPath::from_str(&format!("m/101/1/0/0/{}", self.next))?;
        let internal_keypair = self
            .master_xpriv
            .derive_priv(&self.secp, &derivation_path)?
            .to_keypair(&self.secp);
        let beneficiary_key = self
            .beneficiary_xpub
            .derive_pub(&self.secp, &derivation_path)?
            .to_x_only_pub();

        // Build up the leaf script and combine with internal key into a taproot commitment
        let script = Self::time_lock_script(lock_time, beneficiary_key);
        let leaf_hash = script.tapscript_leaf_hash();

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&self.secp, internal_keypair.x_only_public_key().0)
            .expect("Should be finalizable");
        self.current_spend_info = Some(taproot_spend_info.clone());
        let script_pubkey = ScriptBuf::new_p2tr(
            &self.secp,
            taproot_spend_info.internal_key(),
            taproot_spend_info.merkle_root(),
        );
        let value = input_utxo.amount_in_sats - ABSOLUTE_FEES_IN_SATS;

        // Spend a normal BIP86-like output as an input in our inheritance funding transaction
        let tx = generate_bip86_key_spend_tx(
            &self.secp,
            self.master_xpriv,
            input_utxo,
            vec![TxOut {
                script_pubkey: script_pubkey.clone(),
                value,
            }],
        )?;

        // CREATOR + UPDATER
        let next_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: tx.txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence(0xFFFFFFFD), // enable locktime and opt-in RBF
                witness: Witness::default(),
            }],
            output: vec![],
        };
        let mut next_psbt = Psbt::from_unsigned_tx(next_tx)?;
        let mut origins = BTreeMap::new();
        origins.insert(
            beneficiary_key,
            (
                vec![leaf_hash],
                (self.beneficiary_xpub.fingerprint(), derivation_path.clone()),
            ),
        );
        origins.insert(
            internal_keypair.x_only_public_key().0,
            (
                vec![],
                (self.master_xpriv.fingerprint(&self.secp), derivation_path),
            ),
        );
        let ty = PsbtSighashType::from_str("SIGHASH_ALL")?;
        let mut tap_scripts = BTreeMap::new();
        tap_scripts.insert(
            taproot_spend_info
                .control_block(&(script.clone(), LeafVersion::TapScript))
                .unwrap(),
            (script, LeafVersion::TapScript),
        );

        let input = Input {
            witness_utxo: {
                Some(TxOut {
                    value,
                    script_pubkey,
                })
            },
            tap_key_origins: origins,
            tap_merkle_root: taproot_spend_info.merkle_root(),
            sighash_type: Some(ty),
            tap_internal_key: Some(internal_keypair.x_only_public_key().0),
            tap_scripts,
            ..Default::default()
        };

        next_psbt.inputs = vec![input];
        self.next_psbt = Some(next_psbt.clone());

        self.next.increment()?;
        Ok((tx, next_psbt))
    }

    fn refresh_tx(
        &mut self,
        lock_time_delta: u32,
    ) -> Result<(Transaction, Psbt), Box<dyn std::error::Error>> {
        if let Some(ref spend_info) = self.current_spend_info.clone() {
            let mut psbt = self.next_psbt.clone().expect("Should have next_psbt");
            let input = &mut psbt.inputs[0];
            let input_value = input.witness_utxo.as_ref().unwrap().value;
            let output_value = input_value - ABSOLUTE_FEES_IN_SATS;

            // We use some other derivation path in this example for our inheritance protocol. The important thing is to ensure
            // that we use an unhardened path so we can make use of xpubs.
            let new_derivation_path =
                DerivationPath::from_str(&format!("m/101/1/0/0/{}", self.next))?;
            let new_internal_keypair = self
                .master_xpriv
                .derive_priv(&self.secp, &new_derivation_path)?
                .to_keypair(&self.secp);
            let beneficiary_key = self
                .beneficiary_xpub
                .derive_pub(&self.secp, &new_derivation_path)?
                .to_x_only_pub();

            // Build up the leaf script and combine with internal key into a taproot commitment
            let lock_time = absolute::LockTime::from_height(
                psbt.unsigned_tx.lock_time.to_consensus_u32() + lock_time_delta,
            )
            .unwrap();
            let script = Self::time_lock_script(lock_time, beneficiary_key);
            let leaf_hash = script.tapscript_leaf_hash();

            let taproot_spend_info = TaprootBuilder::new()
                .add_leaf(0, script.clone())?
                .finalize(&self.secp, new_internal_keypair.x_only_public_key().0)
                .expect("Should be finalizable");
            self.current_spend_info = Some(taproot_spend_info.clone());
            let prevout_script_pubkey = input.witness_utxo.as_ref().unwrap().script_pubkey.clone();
            let output_script_pubkey = ScriptBuf::new_p2tr(
                &self.secp,
                taproot_spend_info.internal_key(),
                taproot_spend_info.merkle_root(),
            );

            psbt.unsigned_tx.output = vec![TxOut {
                script_pubkey: output_script_pubkey.clone(),
                value: output_value,
            }];
            psbt.outputs = vec![Output::default()];
            psbt.unsigned_tx.lock_time = absolute::LockTime::ZERO;

            let hash_ty = input
                .sighash_type
                .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
                .unwrap_or(TapSighashType::All);
            let hash = SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
                0,
                &sighash::Prevouts::All(&[TxOut {
                    value: input_value,
                    script_pubkey: prevout_script_pubkey,
                }]),
                hash_ty,
            )?;

            {
                let (_, (_, derivation_path)) = input
                    .tap_key_origins
                    .get(
                        &input
                            .tap_internal_key
                            .ok_or("Internal key missing in PSBT")?,
                    )
                    .ok_or("Missing taproot key origin")?;
                let secret_key = self
                    .master_xpriv
                    .derive_priv(&self.secp, &derivation_path)?
                    .to_priv()
                    .inner;
                sign_psbt_taproot(
                    &secret_key,
                    spend_info.internal_key(),
                    None,
                    input,
                    hash,
                    hash_ty,
                    &self.secp,
                );
            }

            // FINALIZER
            psbt.inputs.iter_mut().for_each(|input| {
                let mut script_witness: Witness = Witness::new();
                script_witness.push(input.tap_key_sig.unwrap().to_vec());
                input.final_script_witness = Some(script_witness);

                // Clear all the data fields as per the spec.
                input.partial_sigs = BTreeMap::new();
                input.sighash_type = None;
                input.redeem_script = None;
                input.witness_script = None;
                input.bip32_derivation = BTreeMap::new();
            });

            // EXTRACTOR
            let tx = psbt.extract_tx_unchecked_fee_rate();

            let next_tx = Transaction {
                version: transaction::Version::TWO,
                lock_time,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: tx.txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence(0xFFFFFFFD), // enable locktime and opt-in RBF
                    witness: Witness::default(),
                }],
                output: vec![],
            };
            let mut next_psbt = Psbt::from_unsigned_tx(next_tx)?;
            let mut origins = BTreeMap::new();
            origins.insert(
                beneficiary_key,
                (
                    vec![leaf_hash],
                    (self.beneficiary_xpub.fingerprint(), new_derivation_path),
                ),
            );
            let ty = PsbtSighashType::from_str("SIGHASH_ALL")?;
            let mut tap_scripts = BTreeMap::new();
            tap_scripts.insert(
                taproot_spend_info
                    .control_block(&(script.clone(), LeafVersion::TapScript))
                    .unwrap(),
                (script, LeafVersion::TapScript),
            );

            let input = Input {
                witness_utxo: {
                    let script_pubkey = output_script_pubkey;
                    let amount = output_value;

                    Some(TxOut {
                        value: amount,
                        script_pubkey,
                    })
                },
                tap_key_origins: origins,
                tap_merkle_root: taproot_spend_info.merkle_root(),
                sighash_type: Some(ty),
                tap_internal_key: Some(new_internal_keypair.x_only_public_key().0),
                tap_scripts,
                ..Default::default()
            };

            next_psbt.inputs = vec![input];
            self.next_psbt = Some(next_psbt.clone());

            self.next.increment()?;
            Ok((tx, next_psbt))
        } else {
            Err("No current_spend_info available. Create an inheritance tx first.".into())
        }
    }
}

/// A wallet that allows spending from an inheritance locked to a P2TR UTXO via a script path
/// after some expiry using CLTV.
struct BeneficiaryWallet {
    master_xpriv: Xpriv,
    secp: secp256k1::Secp256k1<secp256k1::All>,
}

impl BeneficiaryWallet {
    fn new(master_xpriv: Xpriv) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            master_xpriv,
            secp: Secp256k1::new(),
        })
    }

    fn master_xpub(&self) -> Xpub {
        Xpub::from_priv(&self.secp, &self.master_xpriv)
    }

    fn spend_inheritance(
        &self,
        mut psbt: Psbt,
        lock_time: absolute::LockTime,
        to_address: Address,
    ) -> Result<Transaction, Box<dyn std::error::Error>> {
        let input_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
        let input_script_pubkey = psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .unwrap()
            .script_pubkey
            .clone();
        psbt.unsigned_tx.lock_time = lock_time;
        psbt.unsigned_tx.output = vec![TxOut {
            script_pubkey: to_address.script_pubkey(),
            value: input_value - ABSOLUTE_FEES_IN_SATS,
        }];
        psbt.outputs = vec![Output::default()];
        let unsigned_tx = psbt.unsigned_tx.clone();

        // SIGNER
        for (x_only_pubkey, (leaf_hashes, (_, derivation_path))) in
            &psbt.inputs[0].tap_key_origins.clone()
        {
            let secret_key = self
                .master_xpriv
                .derive_priv(&self.secp, &derivation_path)?
                .to_priv()
                .inner;
            for lh in leaf_hashes {
                let hash_ty = TapSighashType::All;
                let hash = SighashCache::new(&unsigned_tx).taproot_script_spend_signature_hash(
                    0,
                    &sighash::Prevouts::All(&[TxOut {
                        value: input_value,
                        script_pubkey: input_script_pubkey.clone(),
                    }]),
                    *lh,
                    hash_ty,
                )?;
                sign_psbt_taproot(
                    &secret_key,
                    *x_only_pubkey,
                    Some(*lh),
                    &mut psbt.inputs[0],
                    hash,
                    hash_ty,
                    &self.secp,
                );
            }
        }

        // FINALIZER
        psbt.inputs.iter_mut().for_each(|input| {
            let mut script_witness: Witness = Witness::new();
            for (_, signature) in input.tap_script_sigs.iter() {
                script_witness.push(signature.to_vec());
            }
            for (control_block, (script, _)) in input.tap_scripts.iter() {
                script_witness.push(script.to_bytes());
                script_witness.push(control_block.serialize());
            }
            input.final_script_witness = Some(script_witness);

            // Clear all the data fields as per the spec.
            input.partial_sigs = BTreeMap::new();
            input.sighash_type = None;
            input.redeem_script = None;
            input.witness_script = None;
            input.bip32_derivation = BTreeMap::new();
            input.tap_script_sigs = BTreeMap::new();
            input.tap_scripts = BTreeMap::new();
            input.tap_key_sig = None;
        });

        // EXTRACTOR
        let tx = psbt.extract_tx_unchecked_fee_rate();

        Ok(tx)
    }
}

fn sign_psbt_taproot(
    secret_key: &secp256k1::SecretKey,
    pubkey: XOnlyPublicKey,
    leaf_hash: Option<TapLeafHash>,
    psbt_input: &mut psbt::Input,
    hash: TapSighash,
    hash_ty: TapSighashType,
    secp: &Secp256k1<secp256k1::All>,
) {
    let keypair = secp256k1::Keypair::from_seckey_slice(secp, secret_key.as_ref()).unwrap();
    let keypair = match leaf_hash {
        None => keypair
            .tap_tweak(secp, psbt_input.tap_merkle_root)
            .to_inner(),
        Some(_) => keypair, // no tweak for script spend
    };

    let msg = secp256k1::Message::from_digest(hash.to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    let final_signature = taproot::Signature { sig, hash_ty };

    if let Some(lh) = leaf_hash {
        psbt_input
            .tap_script_sigs
            .insert((pubkey, lh), final_signature);
    } else {
        psbt_input.tap_key_sig = Some(final_signature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_tx_result() {
        let secp = Secp256k1::new();
        let master_xpriv = Xpriv::from_str(BENEFACTOR_XPRIV_STR).unwrap();

        println!("\n----------------");
        println!("\nSTART EXAMPLE 1 - P2TR with a BIP86 commitment, signed with internal key\n");

        // Just some addresses for outputs from our wallets. Not really important.
        let to_address =
            Address::from_str("bcrt1p0p3rvwww0v9znrclp00uneq8ytre9kj922v8fxhnezm3mgsmn9usdxaefc")
                .unwrap()
                .require_network(Network::Regtest)
                .unwrap();
        let change_address =
            Address::from_str("bcrt1pz449kexzydh2kaypatup5ultru3ej284t6eguhnkn6wkhswt0l7q3a7j76")
                .unwrap()
                .require_network(Network::Regtest)
                .unwrap();

        // 计算总输入金额（150 BTC）
        let total_input_amount = Amount::from_int_btc(150);

        // 定义转账金额和找零金额
        let amount_to_send_in_sats = Amount::ONE_BTC;
        let change_amount = total_input_amount
            .checked_sub(amount_to_send_in_sats)
            .and_then(|x| x.checked_sub(ABSOLUTE_FEES_IN_SATS))
            .expect("Fees more than input amount");

        // 定义输出
        let output = vec![
            TxOut {
                value: amount_to_send_in_sats,
                script_pubkey: to_address.script_pubkey(),
            },
            TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            },
        ];

        // 执行批量处理函数
        let batch_tx_result =
            atomicals_key_spend_tx(&secp, master_xpriv, &[UTXO_1, UTXO_2, UTXO_3], output);

        // 断言结果应该是 Ok
        assert!(batch_tx_result.is_ok());
    }

    
    #[test]
    fn test_compare_tx_generation() {
        let master_xpriv = Xpriv::from_str(BENEFACTOR_XPRIV_STR).unwrap();

        let utxo = UTXO_1; // 使用相同的 UTXO
        let secp = Secp256k1::new();

        println!("\n----------------");
        println!("\nSTART EXAMPLE 1 - P2TR with a BIP86 commitment, signed with internal key\n");

        // Just some addresses for outputs from our wallets. Not really important.
        let to_address =
            Address::from_str("bcrt1p0p3rvwww0v9znrclp00uneq8ytre9kj922v8fxhnezm3mgsmn9usdxaefc")
                .unwrap()
                .require_network(Network::Regtest)
                .unwrap();
        let change_address =
            Address::from_str("bcrt1pz449kexzydh2kaypatup5ultru3ej284t6eguhnkn6wkhswt0l7q3a7j76")
                .unwrap()
                .require_network(Network::Regtest)
                .unwrap();
        let amount_to_send_in_sats = Amount::ONE_BTC;
        let change_amount = UTXO_1
            .amount_in_sats
            .checked_sub(amount_to_send_in_sats)
            .and_then(|x| x.checked_sub(ABSOLUTE_FEES_IN_SATS))
            .ok_or("Fees more than input amount!")
            .unwrap();

        let output = vec![
            TxOut {
                value: amount_to_send_in_sats,
                script_pubkey: to_address.script_pubkey(),
            },
            TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            },
        ];

        // 生成单个 UTXO 的交易
        let single_tx_result =
            generate_bip86_key_spend_tx(&secp, master_xpriv.clone(), utxo.clone(), output.clone());

        // 生成批量 UTXO 的交易
        let batch_tx_result =
            atomicals_key_spend_tx(&secp, master_xpriv, &[utxo], output.clone());

        assert!(single_tx_result.is_ok() && batch_tx_result.is_ok());

        let single_tx = single_tx_result.unwrap();
        let batch_tx = batch_tx_result.unwrap();

        // 比较两个交易的序列化形式是否相同
        assert_eq!(single_tx, batch_tx);
    }
}
