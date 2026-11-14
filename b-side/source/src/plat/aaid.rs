use der::asn1::{OctetString, SetOfVec};

/// 调用方实际发来的形状：两个字段都是 `SET OF`（tag 0x31）。
///
/// 我们自己的 A 端（TA 里的 tag 709 编码）走的是这一种，所以这里必须是它，
/// 否则所有 attest 请求都会在 B 层被拒，请求直接掉到服务端 keybox。
#[derive(der::Sequence, Debug)]
pub struct AttestationApplicationId {
    pub package_info_records: SetOfVec<PackageInfoRecord>,
    pub signature_digests: SetOfVec<OctetString>,
}

/// AOSP 规范写的形状：两个字段是 `SEQUENCE OF`（tag 0x30）。
///
/// ```
/// AttestationApplicationId ::= SEQUENCE {
///     packageInfos SEQUENCE OF AttestationPackageInfo,
///     signatureDigests SEQUENCE OF OCTET STRING
/// }
/// ```
///
/// 系统 keystore2 生成的是这一种。两种都要认：只认 SET 会把标准格式的请求
/// 判死，只认 SEQUENCE 会把 A 端的请求判死。
#[derive(der::Sequence, Debug)]
pub struct AttestationApplicationIdSeq {
    pub package_info_records: Vec<PackageInfoRecord>,
    pub signature_digests: Vec<OctetString>,
}

#[derive(der::Sequence, der::ValueOrd, Debug)]
pub struct PackageInfoRecord {
    pub package_name: OctetString,
    pub version: u64,
}
