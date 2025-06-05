use cmz::*;
use group::Group;
use rand::RngCore;

use crate::registration::UserAuthCredential;

muCMZProtocol!(submit,
    Old: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    New: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    Old.nym_id = New.nym_id,
    Old.age = New.age,
    New.measurement_count = Old.measurement_count + Scalar::from(1u64),
);
