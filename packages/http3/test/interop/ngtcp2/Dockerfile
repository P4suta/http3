# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
FROM gcc:15.2-bookworm@sha256:9ca91b05c7b07d2979f16413e8b2cd6ec8a7c80ffca4121ccab0aeba33f90460 AS build
RUN timeout 180s apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 update \
 && timeout 180s apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 install -y --no-install-recommends \
    cmake=3.25.1-1 libgnutls28-dev=3.7.9-2+deb12u7 libev-dev=1:4.33-1 patchelf=0.14.3-1+b1 python3 pkg-config
COPY packages/http3/test/interop/ngtcp2/sources.lock.json /inputs/sources.lock.json
COPY packages/http3/test/interop/ngtcp2/identity_patch.py /inputs/identity_patch.py
COPY packages/http3/test/interop/ngtcp2/Dockerfile /inputs/Dockerfile
COPY scripts/process_supervisor.py /inputs/process_supervisor.py
RUN python3 - <<'PY'
import hashlib,json,subprocess
from pathlib import Path
Path('/archives').mkdir()
Path('/sources').mkdir()
for source in json.loads(Path('/inputs/sources.lock.json').read_text())['sources']:
    archive = Path('/archives') / (source['name'] + '-' + source['version'] + '.tar.xz')
    subprocess.run(['curl','--fail','--location','--silent','--show-error','--retry','2','--connect-timeout','20','--max-time','120','--max-filesize','33554432','--output',str(archive),source['url']],check=True,timeout=380)
    if archive.stat().st_size > 32*1024*1024 or hashlib.sha256(archive.read_bytes()).hexdigest() != source['sha256']:
        raise ValueError('archive_digest_mismatch')
    subprocess.run(['tar','-xJf',str(archive),'-C','/sources'],check=True,timeout=30)
PY
RUN python3 /inputs/identity_patch.py apply
RUN cmake -S /sources/nghttp3-1.18.0 -B /build/nghttp3 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/peer -DENABLE_LIB_ONLY=ON -DENABLE_SHARED_LIB=OFF -DENABLE_STATIC_LIB=ON \
 && timeout 300s cmake --build /build/nghttp3 --parallel 2 && timeout 30s cmake --install /build/nghttp3
RUN cmake -S /sources/ngtcp2-1.25.0 -B /build/ngtcp2 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/peer -DCMAKE_PREFIX_PATH=/opt/peer -DENABLE_GNUTLS=ON -DENABLE_OPENSSL=OFF -DENABLE_SHARED_LIB=ON -DENABLE_STATIC_LIB=ON -DBUILD_TESTING=OFF \
 && timeout 420s cmake --build /build/ngtcp2 --parallel 2 && timeout 30s cmake --install /build/ngtcp2
RUN cmake -S /sources/curl-8.22.0 -B /build/curl -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/peer -DCMAKE_PREFIX_PATH=/opt/peer -DCMAKE_C_FLAGS=-I/opt/peer/include -DCURL_USE_GNUTLS=ON -DCURL_USE_OPENSSL=OFF -DUSE_NGTCP2=ON -DUSE_NGHTTP2=OFF -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DCURL_ZLIB=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DCURL_USE_LIBPSL=OFF \
 && timeout 420s cmake --build /build/curl --parallel 2 && timeout 30s cmake --install /build/curl
RUN python3 /inputs/identity_patch.py verify
RUN python3 - <<'PY'
import os,re,shutil,subprocess
from pathlib import Path
output = Path('/output')
(output/'bin').mkdir(parents=True)
(output/'lib').mkdir()
native = [('client',Path('/build/curl/src/curl')),('server',Path('/build/ngtcp2/examples/gtlsserver'))]
for role, binary in native:
    libraries = subprocess.check_output(['ldd',str(binary)],timeout=20).decode()
    if len(libraries) > 65536 or 'not found' in libraries:
        raise ValueError('unresolved_native_library')
    for name, source in re.findall(r'^\s*(\S+) => (/\S+) \(',libraries,re.M):
        if name in ('libc.so.6','libm.so.6','libpthread.so.0','libdl.so.2','librt.so.1','libresolv.so.2'):
            continue
        target = output/'lib'/name
        if not target.exists():
            shutil.copyfile(source,target)
    target = output/'bin'/('ngtcp2-'+role)
    shutil.copyfile(binary,target)
    target.chmod(0o755)
    subprocess.run(['patchelf','--set-rpath','$ORIGIN/../lib',str(target)],check=True,timeout=20)
for library in (output/'lib').iterdir():
    subprocess.run(['patchelf','--set-rpath','$ORIGIN',str(library)],check=True,timeout=20)
shutil.copyfile('/inputs/build-identity.json',output/'build-identity.json')
for role,_ in native:
    subprocess.run([str(output/'bin'/('ngtcp2-'+role)),'--http-interop-identity'],check=True,timeout=20)
PY
FROM scratch AS artifacts
COPY --from=build /output/ /
