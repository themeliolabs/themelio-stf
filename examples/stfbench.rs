use std::{collections::BinaryHeap, path::Path, time::Instant};

use novasmt::Database;
use rand::RngCore;
use themelio_stf::{melvm::Covenant, GenesisConfig};
use themelio_structs::{CoinData, CoinValue, Denom, NetID, Transaction, TxKind};

fn main() {
    env_logger::init();
    let meshacas =
        MeshaCas::new(meshanina::Mapping::open(Path::new("/home/miyuruasuka/test.db")).unwrap());
    let mut test_state = GenesisConfig {
        network: NetID::Custom02,
        init_coindata: CoinData {
            value: CoinValue(10000),
            denom: Denom::Mel,
            additional_data: vec![],
            covhash: Covenant::always_true().hash(),
        },
        stakes: Default::default(),
        init_fee_pool: CoinValue(0),
    }
    .realize(&Database::new(meshacas))
    .seal(None)
    .next_state();
    // test basic transactions
    let mut cue = BinaryHeap::new();
    for iter in 0.. {
        if iter % 10000 == 0 {
            test_state = test_state.seal(None).next_state();
        }
        let start = Instant::now();
        let mut data = vec![0; 1024];
        rand::thread_rng().fill_bytes(&mut data);
        let mut test_tx = Transaction {
            kind: TxKind::Faucet,
            inputs: vec![],
            outputs: vec![
                CoinData {
                    value: CoinValue(10000),
                    denom: Denom::Mel,
                    additional_data: vec![],
                    covhash: Covenant::always_true().hash(),
                },
                CoinData {
                    value: CoinValue(10000),
                    denom: Denom::Mel,
                    additional_data: vec![],
                    covhash: Covenant::always_true().hash(),
                },
            ],
            fee: CoinValue(100000000),
            covenants: vec![Covenant::always_true().0],
            data,
            sigs: vec![],
        };
        if cue.len() > 5000 {
            test_tx.inputs.push(cue.pop().unwrap());
            test_tx.inputs.push(cue.pop().unwrap());
        }
        cue.push(test_tx.output_coinid(0));
        cue.push(test_tx.output_coinid(1));
        test_state.apply_tx(&test_tx).unwrap();
        test_state.coins.inner().database().storage().flush();
        eprintln!("iteration {} took {:?}", iter, start.elapsed());
        println!("iteration,interval");
        println!("{},{}", iter, start.elapsed().as_secs_f64());
    }
}

use ethnum::U256;
use novasmt::ContentAddrStore;

/// A meshanina-backed autosmt backend
pub struct MeshaCas {
    inner: meshanina::Mapping,
}

impl MeshaCas {
    /// Takes exclusively ownership of a Meshanina database and creates an autosmt backend.
    pub fn new(db: meshanina::Mapping) -> Self {
        Self { inner: db }
    }

    /// Syncs to disk.
    pub fn flush(&self) {
        self.inner.flush()
    }
}

impl ContentAddrStore for MeshaCas {
    fn get<'a>(&'a self, key: &[u8]) -> Option<std::borrow::Cow<'a, [u8]>> {
        self.inner
            .get(U256::from_le_bytes(tmelcrypt::hash_single(key).0))
    }

    fn insert(&self, key: &[u8], value: &[u8]) {
        self.inner
            .insert(U256::from_le_bytes(tmelcrypt::hash_single(key).0), value)
    }
}
