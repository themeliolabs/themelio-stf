use std::{convert::TryInto, time::Instant};

use dashmap::DashMap;
use novasmt::ContentAddrStore;
use parking_lot::Mutex;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rustc_hash::{FxHashMap, FxHashSet};
use themelio_structs::{
    Address, BlockHeight, CoinData, CoinDataHeight, CoinID, CoinValue, Denom, NetID, StakeDoc,
    Transaction, TxHash, TxKind,
};
use tmelcrypt::HashVal;

use crate::{
    melmint,
    melvm::{Covenant, CovenantEnv},
    LegacyMelPowHash, State, StateError, Tip910MelPowHash,
};

/// A mutable "handle" to a particular State. Can be "committed" like a database transaction.
pub(crate) struct StateHandle<'a, C: ContentAddrStore> {
    state: &'a mut State<C>,

    coin_cache: DashMap<CoinID, Option<CoinDataHeight>>,
    transactions_cache: DashMap<TxHash, Transaction>,

    fee_pool_cache: CoinValue,
    tips_cache: CoinValue,

    dosc_speed_cache: Mutex<u128>,

    stakes_cache: DashMap<TxHash, StakeDoc>,
}

fn faucet_dedup_pseudocoin(txhash: TxHash) -> CoinID {
    CoinID {
        txhash: tmelcrypt::hash_keyed(b"fdp", &txhash.0).into(),
        index: 0,
    }
}

impl<'a, C: ContentAddrStore> StateHandle<'a, C> {
    /// Creates a new state handle.
    pub fn new(state: &'a mut State<C>) -> Self {
        let fee_pool_cache = state.fee_pool;
        let tips_cache = state.tips;
        let dosc_speed = state.dosc_speed;
        StateHandle {
            state,

            coin_cache: DashMap::new(),
            transactions_cache: DashMap::new(),

            fee_pool_cache,
            tips_cache,

            dosc_speed_cache: Mutex::new(dosc_speed),

            stakes_cache: DashMap::new(),
        }
    }

    /// Applies a batch of transactions, returning an error if any of them fail. Consumes and re-returns the handle; if any fail the handle is gone.
    pub fn apply_tx_batch(mut self, txx: &[Transaction]) -> Result<Self, StateError> {
        let start = Instant::now();
        for tx in txx.iter() {
            if tx.kind == TxKind::Faucet {
                let pseudocoin = faucet_dedup_pseudocoin(tx.hash_nosigs());
                if self.get_coin(pseudocoin).is_some() {
                    return Err(StateError::DuplicateTx);
                }
                self.set_coin(
                    pseudocoin,
                    CoinDataHeight {
                        coin_data: CoinData {
                            denom: Denom::Mel,
                            value: 0.into(),
                            additional_data: vec![],
                            covhash: HashVal::default().into(),
                        },
                        height: 0.into(),
                    },
                );
            }
            if !tx.is_well_formed() {
                return Err(StateError::MalformedTx);
            }
            if tx.kind == TxKind::Faucet && self.state.network == NetID::Mainnet {
                return Err(StateError::UnbalancedInOut);
            }
            self.transactions_cache.insert(tx.hash_nosigs(), tx.clone());
            self.apply_tx_fees(tx)?;
        }
        // apply specials in parallel
        txx.par_iter()
            .filter(|tx| tx.kind != TxKind::Normal && tx.kind != TxKind::Faucet)
            .map(|tx| self.apply_tx_special(tx))
            .collect::<Result<_, _>>()?;
        // apply outputs in parallel
        txx.par_iter().for_each(|tx| self.apply_tx_outputs(tx));
        // apply inputs in parallel
        txx.par_iter()
            .map(|tx| self.apply_tx_inputs(tx))
            .collect::<Result<_, _>>()?;
        log::debug!(
            "[{}] applied batch of {} in {:.2}ms",
            self.state.height,
            txx.len(),
            start.elapsed().as_secs_f64() * 1000.0
        );
        Ok(self)
    }

    /// Commits all the changes in this handle, at once.
    pub fn commit(self) {
        let start = Instant::now();
        // commit coins
        let coin_count = self.coin_cache.len();
        self.coin_cache.into_iter().for_each(|(key, value)| {
            let start = Instant::now();
            if let Some(value) = value.clone() {
                self.state
                    .coins
                    .insert_coin(key, value, self.state.tip_906());
            } else {
                self.state.coins.remove_coin(key, self.state.tip_906());
            }
            if start.elapsed().as_millis() > 10 {
                log::warn!(
                    "insertion cost {:?}, trying to insert {:?}",
                    start.elapsed(),
                    (key, value)
                )
            }
        });
        log::debug!(
            "[{}] committed {} coins in {:.2}ms",
            self.state.height,
            coin_count,
            start.elapsed().as_secs_f64() * 1000.0
        );

        // commit txx
        self.transactions_cache
            .into_iter()
            .for_each(|(key, value)| {
                self.state.transactions.insert(key, value);
            });

        log::debug!(
            "[{}] committed transactions in {:.2}ms",
            self.state.height,
            start.elapsed().as_secs_f64() * 1000.0
        );

        // commit fees
        self.state.fee_pool = self.fee_pool_cache;
        self.state.tips = self.tips_cache;

        // commit stakes
        self.stakes_cache.into_iter().for_each(|(key, value)| {
            self.state.stakes.insert(key, value);
        });

        self.state.dosc_speed = *self.dosc_speed_cache.lock();
        log::debug!(
            "[{}] committed rest in {:.2}ms",
            self.state.height,
            start.elapsed().as_secs_f64() * 1000.0
        );
    }

    fn apply_tx_inputs(&self, tx: &Transaction) -> Result<(), StateError> {
        let txhash = tx.hash_nosigs();
        let start = Instant::now();
        let scripts = tx.covenants_as_map();
        // build a map of input coins
        let mut in_coins: FxHashMap<Denom, u128> = FxHashMap::default();
        // get last header
        let last_header = self
            .state
            .history
            .get(&(self.state.height.0.saturating_sub(1).into()))
            .0
            .unwrap_or_else(|| self.state.clone().seal(None).header());
        // iterate through the inputs
        let mut good_scripts: FxHashSet<Address> = FxHashSet::default();
        for (spend_idx, coin_id) in tx.inputs.iter().enumerate() {
            if self.get_stake(coin_id.txhash).is_some() {
                return Err(StateError::CoinLocked);
            }
            let coin_data = self.get_coin(*coin_id);
            match coin_data {
                None => return Err(StateError::NonexistentCoin(*coin_id)),
                Some(coin_data) => {
                    log::trace!(
                        "coin_data {:?} => {:?} for txid {:?}",
                        coin_id,
                        coin_data,
                        tx.hash_nosigs()
                    );
                    if !good_scripts.contains(&coin_data.coin_data.covhash) {
                        let script = Covenant(
                            scripts
                                .get(&coin_data.coin_data.covhash)
                                .ok_or(StateError::NonexistentScript(coin_data.coin_data.covhash))?
                                .clone(),
                        );
                        if !script.check(
                            tx,
                            CovenantEnv {
                                parent_coinid: coin_id,
                                parent_cdh: &coin_data,
                                spender_index: spend_idx as u8,
                                last_header: &last_header,
                            },
                        ) {
                            return Err(StateError::ViolatesScript(coin_data.coin_data.covhash));
                        }
                        good_scripts.insert(coin_data.coin_data.covhash);
                    }
                    self.del_coin(*coin_id);
                    in_coins.insert(
                        coin_data.coin_data.denom,
                        in_coins.get(&coin_data.coin_data.denom).unwrap_or(&0)
                            + coin_data.coin_data.value.0,
                    );
                }
            }
        }
        log::trace!("{}: processed all inputs {:?}", txhash, start.elapsed());
        // balance inputs and outputs. ignore outputs with empty cointype (they create a new token kind)
        let out_coins = tx.total_outputs();
        if tx.kind != TxKind::Faucet {
            for (currency, value) in out_coins.iter() {
                // we skip the created doscs for a DoscMint transaction
                if tx.kind == TxKind::DoscMint && *currency == Denom::Erg {
                    continue;
                }
                let in_value = *in_coins.get(currency).unwrap_or(&u128::MAX);
                if *currency != Denom::NewCoin && *value != CoinValue(in_value) {
                    log::warn!(
                        "unbalanced: {} {:?} in, {} {:?} out",
                        in_value,
                        currency,
                        value,
                        currency
                    );
                    return Err(StateError::UnbalancedInOut);
                }
            }
        }
        Ok(())
    }

    fn apply_tx_fees(&mut self, tx: &Transaction) -> Result<(), StateError> {
        // fees
        let min_fee = tx.base_fee(self.state.fee_multiplier, 0, |c| {
            Covenant(c.to_vec()).weight().unwrap_or(0)
        });
        if tx.fee < min_fee {
            Err(StateError::InsufficientFees(min_fee))
        } else {
            let tips = tx.fee - min_fee;
            self.tips_cache.0 = self.tips_cache.0.saturating_add(tips.0);
            self.fee_pool_cache.0 = self.fee_pool_cache.0.saturating_add(min_fee.0);

            Ok(())
        }
    }

    fn apply_tx_outputs(&self, tx: &Transaction) {
        let height = self.state.height;

        tx.outputs
            .iter()
            .enumerate()
            .for_each(|(index, coin_data)| {
                let mut coin_data = coin_data.clone();
                if coin_data.denom == Denom::NewCoin {
                    coin_data.denom = Denom::Custom(tx.hash_nosigs());
                }
                // if covenant hash is zero, this destroys the coins permanently
                if coin_data.covhash != Address::coin_destroy() {
                    self.set_coin(
                        CoinID {
                            txhash: tx.hash_nosigs(),
                            index: index.try_into().unwrap(),
                        },
                        CoinDataHeight { coin_data, height },
                    );
                }
            });
    }

    fn apply_tx_special(&self, tx: &Transaction) -> Result<(), StateError> {
        match tx.kind {
            TxKind::DoscMint => self.apply_tx_special_doscmint(tx),
            TxKind::Stake => self.apply_tx_special_stake(tx),
            _ => Ok(()),
        }
    }

    fn apply_tx_special_doscmint(&self, tx: &Transaction) -> Result<(), StateError> {
        let coin_id = *tx.inputs.get(0).unwrap();
        let coin_data = self.get_coin(coin_id).ok_or(StateError::MalformedTx)?;
        // make sure the time is long enough that we can easily measure it
        if (self.state.height - coin_data.height).0 < 100 && self.state.network == NetID::Mainnet {
            log::warn!("rejecting doscmint due to too recent");
            return Err(StateError::InvalidMelPoW);
        }
        // construct puzzle seed
        let chi = tmelcrypt::hash_keyed(
            &self.state.history.get(&coin_data.height).0.unwrap().hash(),
            &stdcode::serialize(tx.inputs.get(0).unwrap()).unwrap(),
        );
        // get difficulty and proof
        let (difficulty, proof_bytes): (u32, Vec<u8>) =
            stdcode::deserialize(&tx.data).map_err(|e| {
                log::warn!("rejecting doscmint due to malformed proof: {:?}", e);
                StateError::MalformedTx
            })?;
        let proof = melpow::Proof::from_bytes(&proof_bytes).unwrap();

        // try verifying the proof under the old and the new system
        let is_tip910 = {
            if proof.verify(&chi, difficulty as _, LegacyMelPowHash) {
                false
            } else if proof.verify(&chi, difficulty as _, Tip910MelPowHash) {
                true
            } else {
                return Err(StateError::InvalidMelPoW);
            }
        };

        // compute speeds
        let my_speed = 2u128.pow(difficulty) / (self.state.height - coin_data.height).0 as u128;
        let reward_real = melmint::calculate_reward(
            my_speed,
            self.state
                .history
                .get(&BlockHeight(self.state.height.0 - 1))
                .0
                .unwrap()
                .dosc_speed,
            difficulty,
            is_tip910,
        );
        {
            let mut dosc_speed = self.dosc_speed_cache.lock();
            *dosc_speed = dosc_speed.max(my_speed);
        }
        let reward_nom = CoinValue(melmint::dosc_to_erg(self.state.height, reward_real));
        // ensure that the total output of DOSCs is correct
        let total_dosc_output = tx
            .total_outputs()
            .get(&Denom::Erg)
            .cloned()
            .unwrap_or_default();
        if total_dosc_output > reward_nom {
            log::warn!("tried to get too much reward");
            return Err(StateError::InvalidMelPoW);
        }
        Ok(())
    }
    fn apply_tx_special_stake(&self, tx: &Transaction) -> Result<(), StateError> {
        // first we check that the data is correct
        let stake_doc: StakeDoc =
            stdcode::deserialize(&tx.data).map_err(|_| StateError::MalformedTx)?;
        let curr_epoch = self.state.height.epoch();
        // then we check that the first coin is valid
        let first_coin = tx.outputs.get(0).ok_or(StateError::MalformedTx)?;

        let is_first_coin_not_a_sym: bool = first_coin.denom != Denom::Sym;

        // Are we operating under OLD BUGGY RULES?
        if (self.state.network == NetID::Mainnet || self.state.network == NetID::Testnet)
            && self.state.height.0 < 500000
        {
            log::warn!("LETTING THROUGH BAD STAKING TRANSACTION UNDER OLD BUGGY RULES");
            return Ok(());
        }

        if is_first_coin_not_a_sym {
            Err(StateError::MalformedTx)
        // then we check consistency
        } else if stake_doc.e_start > curr_epoch
            && stake_doc.e_post_end > stake_doc.e_start
            && stake_doc.syms_staked == first_coin.value
        {
            self.set_stake(tx.hash_nosigs(), stake_doc);
            log::warn!("**** ADDING STAKER {:?} ****", stake_doc);
            Ok(())
        } else {
            log::warn!("**** REJECTING STAKER {:?} ****", stake_doc);
            Ok(())
        }
    }

    fn get_coin(&self, coin_id: CoinID) -> Option<CoinDataHeight> {
        self.coin_cache
            .entry(coin_id)
            .or_insert_with(|| self.state.coins.get_coin(coin_id))
            .value()
            .clone()
    }

    fn set_coin(&self, coin_id: CoinID, value: CoinDataHeight) {
        self.coin_cache.insert(coin_id, Some(value));
    }

    fn del_coin(&self, coin_id: CoinID) {
        self.coin_cache.insert(coin_id, None);
    }

    fn get_stake(&self, txhash: TxHash) -> Option<StakeDoc> {
        if let Some(cached_sd) = self.stakes_cache.get(&txhash).as_deref() {
            Some(cached_sd).cloned()
        } else if let Some(sd) = self.state.stakes.get(&txhash).0 {
            self.stakes_cache.insert(txhash, sd)
        } else {
            None
        }
    }

    fn set_stake(&self, txhash: TxHash, sdoc: StakeDoc) {
        self.stakes_cache.insert(txhash, sdoc);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    // use crate::melvm::Covenant;
    // use crate::state::applytx::StateHandle;
    // // use crate::testing::factory::*;
    // use crate::testing::fixtures::*;
    // use crate::{CoinData, CoinID, State};
    // use rstest::*;
    // use tmelcrypt::{Ed25519PK, Ed25519SK};
    //
    // #[rstest]
    // fn test_apply_tx_inputs_single_valid_tx(
    //     genesis_state: State,
    //     genesis_mel_coin_id: CoinID,
    //     genesis_mel_coin_data: CoinData,
    //     genesis_covenant_keypair: (Ed25519PK, Ed25519SK),
    //     genesis_covenant: Covenant,
    //     keypair: (Ed25519PK, Ed25519SK),
    // ) {
    //     // Init state and state handle
    //     let mut state = genesis_state.clone();
    //     let state_handle = StateHandle::new(&mut state);
    //
    //     // Create a valid signed transaction from first coin
    //     // let fee = 3000000;
    //     // let tx = tx_factory(
    //     //     TxKind::Normal,
    //     //     genesis_covenant_keypair,
    //     //     keypair.0,
    //     //     genesis_mel_coin_id,
    //     //     genesis_covenant,
    //     //     genesis_mel_coin_data.value,
    //     //     fee,
    //     // );
    //     //
    //     // // Apply tx inputs and verify no error
    //     // let res = state_handle.apply_tx_inputs(&tx);
    //     //
    //     // assert!(res.is_ok());
    // }
}
