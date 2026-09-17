#!/usr/bin/env bash
set -euo pipefail

# Install the F6-B compiler/decompiler stack without sudo or system changes.
# The caller must place it outside Git and model/data artifact directories.
: "${AEGISLM_BINARY_TOOL_ROOT:?set an absolute external tool root}"
case "${AEGISLM_BINARY_TOOL_ROOT}" in
  /*) ;;
  *)
    echo "AEGISLM_BINARY_TOOL_ROOT must be an absolute path" >&2
    exit 2
    ;;
esac

tool_root="${AEGISLM_BINARY_TOOL_ROOT}"
downloads="${tool_root}/downloads"
bin_dir="${tool_root}/bin"
mkdir -p "${downloads}" "${bin_dir}"

jdk_name="OpenJDK21U-jdk_x64_linux_hotspot_21.0.12_8.tar.gz"
jdk_url="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12%2B8/${jdk_name}"
jdk_sha256="e4446ff06a276155697597cc0f1b15da004ff083f4964a35271ecee567177370"
jdk_dir="${tool_root}/jdk-21.0.12+8"

ghidra_name="ghidra_12.1.2_PUBLIC_20260605.zip"
ghidra_url="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/${ghidra_name}"
ghidra_sha256="b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d"
ghidra_dir="${tool_root}/ghidra_12.1.2_PUBLIC"

clang_version="1:18.1.3-1ubuntu1"
clang_packages=(
  clang-18
  libclang-cpp18
  libllvm18
  libclang-common-18-dev
  llvm-18-linker-tools
  libclang1-18
)
clang_root="${tool_root}/clang-18.1.3-ubuntu24.04"

download_verified() {
  local url="$1"
  local output="$2"
  local expected="$3"
  if [[ ! -f "${output}" ]]; then
    curl --fail --location --retry 3 --output "${output}" "${url}"
  fi
  printf '%s  %s\n' "${expected}" "${output}" | sha256sum --check -
}

download_verified "${jdk_url}" "${downloads}/${jdk_name}" "${jdk_sha256}"
if [[ ! -x "${jdk_dir}/bin/java" ]]; then
  tar -xzf "${downloads}/${jdk_name}" -C "${tool_root}"
fi

download_verified \
  "${ghidra_url}" \
  "${downloads}/${ghidra_name}" \
  "${ghidra_sha256}"
if [[ ! -x "${ghidra_dir}/support/analyzeHeadless" ]]; then
  unzip -q "${downloads}/${ghidra_name}" -d "${tool_root}"
fi

if [[ ! -x "${clang_root}/usr/lib/llvm-18/bin/clang" ]]; then
  tmp_dir="$(mktemp -d "${tool_root}/clang-debs.XXXXXX")"
  case "${tmp_dir}" in
    "${tool_root}"/clang-debs.*) ;;
    *)
      echo "temporary directory escaped tool root" >&2
      exit 3
      ;;
  esac
  (
    cd "${tmp_dir}"
    for package in "${clang_packages[@]}"; do
      apt-get download "${package}=${clang_version}"
    done
    mkdir -p "${clang_root}"
    for package_file in ./*.deb; do
      dpkg-deb --extract "${package_file}" "${clang_root}"
      mv "${package_file}" "${downloads}/"
    done
  )
  rm -rf -- "${tmp_dir}"
fi

cat >"${bin_dir}/clang" <<EOF
#!/usr/bin/env bash
export LD_LIBRARY_PATH="${clang_root}/usr/lib/x86_64-linux-gnu:\${LD_LIBRARY_PATH:-}"
exec "${clang_root}/usr/lib/llvm-18/bin/clang" "\$@"
EOF

cat >"${bin_dir}/clang++" <<EOF
#!/usr/bin/env bash
export LD_LIBRARY_PATH="${clang_root}/usr/lib/x86_64-linux-gnu:\${LD_LIBRARY_PATH:-}"
exec "${clang_root}/usr/lib/llvm-18/bin/clang++" "\$@"
EOF

cat >"${bin_dir}/java" <<EOF
#!/usr/bin/env bash
exec "${jdk_dir}/bin/java" "\$@"
EOF

cat >"${bin_dir}/analyzeHeadless" <<EOF
#!/usr/bin/env bash
export JAVA_HOME="${jdk_dir}"
export PATH="${jdk_dir}/bin:\${PATH}"
exec "${ghidra_dir}/support/analyzeHeadless" "\$@"
EOF

chmod +x \
  "${bin_dir}/clang" \
  "${bin_dir}/clang++" \
  "${bin_dir}/java" \
  "${bin_dir}/analyzeHeadless"

{
  printf 'schema_version=aegislm.binary-toolchain-manifest.v1\n'
  printf 'tool_root=%s\n' "${tool_root}"
  printf 'temurin_jdk=21.0.12+8\n'
  printf 'temurin_jdk_archive_sha256=%s\n' "${jdk_sha256}"
  printf 'ghidra=12.1.2\n'
  printf 'ghidra_archive_sha256=%s\n' "${ghidra_sha256}"
  printf 'clang=18.1.3-1ubuntu1\n'
  printf 'clang_packages=\n'
  (
    cd "${downloads}"
    sha256sum ./*.deb | sort
  )
} >"${tool_root}/toolchain-manifest.txt"

export PATH="${bin_dir}:${PATH}"
clang --version | head -n 1
java -version
analyzeHeadless 2>&1 | head -n 8 || true
sha256sum "${tool_root}/toolchain-manifest.txt"
