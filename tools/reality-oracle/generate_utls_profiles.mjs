import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const fingerprintsSource = readFileSync(
  resolve(workspaceRoot, "crates/xray-utls/src/lib.rs"),
  "utf8",
);
const fingerprints = fingerprintsSource
  .match(/XRAY_REALITY_FINGERPRINTS[^=]*=\s*&\[([\s\S]*?)\];/)[1]
  .match(/"([^"]+)"/g)
  .map((value) => value.slice(1, -1));

const oracleBinary = process.argv[2] ?? "/tmp/clienthello_shape";
const outputPath =
  process.argv[3] ??
  resolve(workspaceRoot, "crates/xray-transport/src/reality_utls_profiles.rs");

function numericValue(value) {
  return value === "GREASE" ? 0x0a0a : Number.parseInt(value, 16);
}

function hexLiteral(value) {
  return `0x${value.toString(16).padStart(4, "0")}`;
}

function numericArray(values) {
  return `&[${values.map((value) => hexLiteral(numericValue(value))).join(", ")}]`;
}

function rustByteString(value) {
  return `b"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function byteStringArray(values) {
  return `&[${values.map(rustByteString).join(", ")}]`;
}

const profileGroups = new Map();
for (const fingerprint of fingerprints) {
  const rawShape = execFileSync(oracleBinary, ["-fingerprint", fingerprint], {
    encoding: "utf8",
  });
  const shape = JSON.parse(rawShape);
  const stableShape = { ...shape, fingerprint: "" };
  const shapeKey = createHash("sha256")
    .update(JSON.stringify(stableShape))
    .digest("hex")
    .slice(0, 12);

  if (!profileGroups.has(shapeKey)) {
    profileGroups.set(shapeKey, {
      index: profileGroups.size,
      fingerprints: [],
      shape,
    });
  }

  profileGroups.get(shapeKey).fingerprints.push(fingerprint);
}

let output = `#[derive(Clone, Copy, Debug)]
pub(super) struct UtlsClientHelloProfile {
    pub cipher_suites: &'static [u16],
    pub supported_versions: &'static [u16],
    pub supported_groups: &'static [u16],
    pub key_shares: &'static [UtlsKeyShare],
    pub signature_algorithms: &'static [u16],
    pub alpn_protocols: &'static [&'static [u8]],
    pub certificate_compression_algorithms: &'static [u16],
    pub application_settings: &'static [UtlsApplicationSettings],
    pub extensions: &'static [UtlsExtension],
    pub padding_length: Option<usize>,
    pub encrypted_client_hello_length: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct UtlsKeyShare {
    pub group: u16,
    pub key_exchange_len: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct UtlsApplicationSettings {
    pub extension_type: u16,
    pub protocols: &'static [&'static [u8]],
}

#[derive(Clone, Copy, Debug)]
pub(super) struct UtlsExtension {
    pub extension_type: u16,
    pub payload_len: usize,
}

const GREASE: u16 = 0x0a0a;
const GREASE_SECOND: u16 = 0x1a1a;

`;

for (const profileGroup of profileGroups.values()) {
  const { index, shape } = profileGroup;
  const prefix = `PROFILE_${index}`;
  const cipherSuites = shape.cipher_suites ?? [];
  const supportedVersions = shape.supported_versions ?? [];
  const supportedGroups = shape.supported_groups ?? [];
  const keyShares = shape.key_shares ?? [];
  const signatureAlgorithms = shape.signature_algorithms ?? [];
  const alpnProtocols = shape.alpn_protocols ?? [];
  const certificateCompressionAlgorithms =
    shape.certificate_compression_algorithms ?? [];
  const applicationSettings = shape.application_settings ?? [];
  const extensions = shape.extensions ?? [];

  output += `const ${prefix}_CIPHERS: &[u16] = ${numericArray(cipherSuites)};\n`;
  output += `const ${prefix}_VERSIONS: &[u16] = ${numericArray(supportedVersions)};\n`;
  output += `const ${prefix}_GROUPS: &[u16] = ${numericArray(supportedGroups)};\n`;
  output += `const ${prefix}_KEY_SHARES: &[UtlsKeyShare] = &[${keyShares
    .map(
      (keyShare) =>
        `UtlsKeyShare { group: ${hexLiteral(
          numericValue(keyShare.group),
        )}, key_exchange_len: ${keyShare.key_exchange_length} }`,
    )
    .join(", ")}];\n`;
  output += `const ${prefix}_SIGALGS: &[u16] = ${numericArray(
    signatureAlgorithms,
  )};\n`;
  output += `const ${prefix}_ALPN: &[&[u8]] = ${byteStringArray(
    alpnProtocols,
  )};\n`;
  output += `const ${prefix}_CERT_COMP: &[u16] = ${numericArray(
    certificateCompressionAlgorithms,
  )};\n`;

  for (let index = 0; index < applicationSettings.length; index += 1) {
    output += `const ${prefix}_APP_${index}_PROTOCOLS: &[&[u8]] = ${byteStringArray(
      applicationSettings[index].protocols ?? [],
    )};\n`;
  }

  output += `const ${prefix}_APPS: &[UtlsApplicationSettings] = &[${applicationSettings
    .map(
      (applicationSetting, index) =>
        `UtlsApplicationSettings { extension_type: ${hexLiteral(
          numericValue(applicationSetting.type),
        )}, protocols: ${prefix}_APP_${index}_PROTOCOLS }`,
    )
    .join(", ")}];\n`;

  let greaseExtensionIndex = 0;
  output += `const ${prefix}_EXTENSIONS: &[UtlsExtension] = &[${extensions
    .map((extension) => {
      let extensionType;
      if (extension.type === "GREASE") {
        extensionType = greaseExtensionIndex === 0 ? "GREASE" : "GREASE_SECOND";
        greaseExtensionIndex += 1;
      } else {
        extensionType = hexLiteral(numericValue(extension.type));
      }

      return `UtlsExtension { extension_type: ${extensionType}, payload_len: ${extension.length} }`;
    })
    .join(", ")}];\n`;
  output += `const ${prefix}: UtlsClientHelloProfile = UtlsClientHelloProfile { cipher_suites: ${prefix}_CIPHERS, supported_versions: ${prefix}_VERSIONS, supported_groups: ${prefix}_GROUPS, key_shares: ${prefix}_KEY_SHARES, signature_algorithms: ${prefix}_SIGALGS, alpn_protocols: ${prefix}_ALPN, certificate_compression_algorithms: ${prefix}_CERT_COMP, application_settings: ${prefix}_APPS, extensions: ${prefix}_EXTENSIONS, padding_length: ${
    shape.padding_length == null ? "None" : `Some(${shape.padding_length})`
  }, encrypted_client_hello_length: ${
    shape.encrypted_client_hello_length == null
      ? "None"
      : `Some(${shape.encrypted_client_hello_length})`
  } };\n\n`;
}

output += `pub(super) fn profile_for_fingerprint(fingerprint: &str) -> Option<&'static UtlsClientHelloProfile> {
    match fingerprint {
`;

for (const profileGroup of profileGroups.values()) {
  for (const fingerprint of profileGroup.fingerprints) {
    output += `        "${fingerprint}" => Some(&PROFILE_${profileGroup.index}),\n`;
  }
}

output += `        _ => None,
    }
}
`;

mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, output);
console.log(
  `wrote ${outputPath} (${profileGroups.size} profiles, ${fingerprints.length} aliases)`,
);
