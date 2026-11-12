#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Regenerate 517 fixed URLPattern controls with real pinned Node and Chromium.

Run in the existing nonroot browser container (no network, pids.max <= 256,
NoNewPrivs, seccomp, no capabilities), supplying the pinned Linux Node binary:
  python3 -B scripts/urlpattern_full_reference.py --write --node /probe/node
Node's pinned libatomic.so.1 must be in /probe/node-libraries beside the binary.
Use --check for byte-identical regeneration; --output overrides the fixture.
--proof retains scalar ownership evidence separately from deterministic bytes.
The two actual engines run before either mode can succeed; imported observations
are not accepted as substitutes. No dependency installation or network is used.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
from pathlib import Path
import socket
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'test/interop/browser'))
from browser_worker import Driver, environment, isolation, profile, require
from owned import OwnedChildren, supervise

NODE_VERSION = 'v26.8.2'
NODE_HASH = '8a22a371fd85aecf5411636574309f6380fbc42694aaf0651a089a8ef9c44e52'
ATOMIC_HASH = '9d8a34468e614a71a6427dbabb0ac24eb8cb1e324dc6aa3bf95eb6f59201f000'
CHROME_VERSION = '153.0.8010.36'
CHROME = Path('/opt/browser/chrome-linux64/chrome')
DRIVER = Path('/opt/browser/chromedriver-linux64/chromedriver')
CHROME_HASH = '79a4ebf6da53e4ceab11844257aabc5166f17b595dc694d6382cbee8ff50565f'
DRIVER_HASH = 'cdb68fb7c5de1e8db562cc77ec767c67802cc45f7aaf5fff1b2f37590ab41a60'
SPEC = '696b4029d52e5854044bac6b72cdb198cb962ed0'
HOST_VALUES = ['EXAMPLE.COM.', '127.1', 'exa\tmple.com', 'example.com/ignored',
               'example.com\\ignored', 'example.com?ignored', 'example.com#ignored',
               'example.com:443', '/ignored', '\\ignored', '?ignored', '#ignored', '']
EVALUATE = r'''function evaluate(data) {
 const rows=data.cases.map(r=>{try{const p=new URLPattern(r.pattern,r.base);return p.test(r.candidate)?0:1;}catch{return 2;}});
 const hostname=data.host_values.map((v,id)=>{try{const p=new URLPattern({protocol:'https',hostname:v.replace(/[+*?:{}()\\]/g,'\\$&')});return {id,constructed:true,value:p.hostname};}catch{return {id,constructed:false};}});
 return {rows,hostname};
}'''


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(path):
    size = path.stat().st_size
    require(0 < size <= 536870912)
    result = hashlib.sha256()
    with path.open('rb') as stream:
        count = 0
        for chunk in iter(lambda: stream.read(1048576), b''):
            count += len(chunk)
            require(count <= 536870912)
            result.update(chunk)
    require(count == size)
    return result.hexdigest()


def fixed_cases():
    rows = []
    def add(pattern, base, candidate, group):
        rows.append(dict(id=len(rows), pattern=pattern, base=base,
                         candidate=candidate, group=group))
    for host in ['ex\tample.com', 'ex\nample.com', 'ex\rample.com',
                 '{exam/ignored}ple.com', '{exam?ignored}ple.com', '{exam#ignored}ple.com',
                 r'{exam\\ignored}ple.com', '{sub.}?example{.com/}foo', '127.0.0.1',
                 r'[\:\:1]', ':sub.example.com', '*.example.com', '{example.com}?',
                 '0x100000000', 'xn--a.example']:
        for candidate in ['https://example.com/a', 'https://sub.example.com/a',
                          'https://127.0.0.1/a', 'https://[::1]/a', 'https://example.comfoo/a']:
            add('https://' + host + '/*', 'https://base.example/dir/base', candidate, 'host')
    for base in ['/dir/base', '/a*/(fixed)/base', '/a:b/{x}/base', '/a+b/base',
                 '/a%3Fb/base', '/a%5Cb/base', '/a?/base', '/a#base']:
        for pattern in ['file', '../file', './file', '/file', '\\/file', '{/file}',
                        '?q=1', '#new', '##new', '??q=1', '']:
            for candidate in ['https://example.com/file', 'https://example.com/dir/file',
                              'https://example.com/a*/(fixed)/file',
                              'https://example.com' + base + '?q=1#new']:
                add(pattern, 'https://example.com' + base + '?q=old#before', candidate, 'base')
    for scheme in ['http{s}?', '{http}s', '{https}?', '*', 'h:proto', '{http:rest}?',
                   'h*tps', 'https{foo}?']:
        for candidate in ['http://example.com/a', 'https://example.com/a',
                          'https://example.com:443/a', 'https://example.com/a/../b']:
            add(scheme + '://example.com/*', 'https://base.example/dict', candidate, 'scheme')
    for host in ['{a}\u0301.example', '{ex}ample.com', '{127}.0.0.1', '127{.0}.0.1',
                 '{0}x7f000001', '{xn--}bcher-kva.example', '{example}/ignored', '{exa/mple}.com']:
        for candidate in ['https://xn--1ca.example/a', 'https://example.com/a',
                          'https://127.0.0.1/a', 'https://xn--bcher-kva.example/a', 'https://exa/a']:
            add('https://' + host + '/*', 'https://base.example/dir/base', candidate, 'fixed_groups')
    for pattern in ['/a{.}/../b', '/a/{..}/b', '/a{b}/../c', '/{a}/../b', '/{%2e}/b', '/{%2e%2e}/b']:
        for candidate in ['https://example.com/b', 'https://example.com/a/b', 'https://example.com/c']:
            add(pattern, 'https://example.com/base', candidate, 'fixed_path_groups')
    require(len(rows) == 517)
    return rows


def validate_observation(value):
    require(type(value) is dict and set(value) == {'rows', 'hostname'})
    require(type(value['rows']) is list and len(value['rows']) == 517)
    require(all(type(v) is int and v in {0, 1, 2} for v in value['rows']))
    require(type(value['hostname']) is list and len(value['hostname']) == 13)
    for index, row in enumerate(value['hostname']):
        require(type(row) is dict and row['id'] == index and type(row['constructed']) is bool)
        require(set(row) == ({'id', 'constructed', 'value'} if row['constructed'] else {'id', 'constructed'}))
        if row['constructed']:
            require(type(row['value']) is str and len(row['value']) <= 512)
    require(len(encoded(value)) <= 4096)
    return value


def valid_ownership(value):
    require(type(value) is dict and set(value) == {'children_observed', 'children_joined'})
    require(all(type(v) is int and 0 < v <= 256 for v in value.values()))
    require(value['children_observed'] == value['children_joined'])


def validate_run(value):
    require(type(value) is dict and set(value) == {'observation', 'ownership'})
    validate_observation(value['observation'])
    valid_ownership(value['ownership'])
    return value


def node_run(node, data):
    isolation()
    require(digest(node) == NODE_HASH)
    libraries = node.parent / 'node-libraries'
    atomic = libraries / 'libatomic.so.1'
    require({p.name for p in libraries.iterdir()} == {'libatomic.so.1'})
    require(digest(atomic) == ATOMIC_HASH)
    owner = OwnedChildren()
    with profile(owner) as directory:
        home = Path(directory)
        input_path, output_path = home / 'input.json', home / 'output.json'
        input_path.write_bytes(encoded(data))
        script = home / 'reference.mjs'
        script.write_text("import fs from 'node:fs';\n" + EVALUATE +
            "\nif(process.version!==" + json.dumps(NODE_VERSION) + ")process.exit(2);\n" +
            "const value=evaluate(JSON.parse(fs.readFileSync(process.argv[2],'utf8')));\n" +
            "fs.writeFileSync(process.argv[3],JSON.stringify(value));\n", encoding='utf-8')
        deadline = time.monotonic() + 15
        child = owner.start([str(node), str(script), str(input_path), str(output_path)],
                            env=dict(environment(home), LD_LIBRARY_PATH=str(libraries)))
        require(child.wait(timeout=max(.001, deadline-time.monotonic())) == 0)
        require(time.monotonic() < deadline and output_path.stat().st_size <= 4096)
        value = validate_observation(json.loads(output_path.read_bytes()))
        joined = owner.close()
        require(digest(node) == NODE_HASH and digest(atomic) == ATOMIC_HASH)
        return {'observation': value, 'ownership': joined}


def chrome_run(data):
    isolation()
    require(digest(CHROME) == CHROME_HASH and digest(DRIVER) == DRIVER_HASH)
    owner = OwnedChildren()
    deadline = time.monotonic() + 35
    with profile(owner) as directory:
        home = Path(directory)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        child = owner.start([str(DRIVER), '--port='+str(port), '--allowed-ips=127.0.0.1',
                             '--log-level=OFF'], env=environment(home))
        driver = Driver(port, deadline)
        while True:
            try:
                driver.command('GET', '/status')
                break
            except Exception:
                require(child.poll() is None and time.monotonic() < deadline)
                time.sleep(.02)
        response = driver.command('POST', '/session', {'capabilities': {'alwaysMatch': {
            'browserName': 'chrome', 'acceptInsecureCerts': False,
            'goog:chromeOptions': {'binary': str(CHROME), 'args': ['--headless', '--no-sandbox',
                '--no-first-run', '--disable-background-networking', '--disable-dev-shm-usage',
                '--user-data-dir='+str(home/'profile')]}}}})
        require(response['capabilities']['browserVersion'] == CHROME_VERSION)
        require(response['capabilities']['chrome']['chromedriverVersion'].split(' ', 1)[0] == CHROME_VERSION)
        base = '/session/' + response['sessionId']
        driver.command('POST', base+'/timeouts', {'script': 5000, 'pageLoad': 5000, 'implicit': 0})
        driver.command('POST', base+'/url', {'url': 'data:text/html,<title>fixed</title>'})
        value = validate_observation(driver.command('POST', base+'/execute/sync',
            {'script': EVALUATE+'\nreturn evaluate(arguments[0]);', 'args': [data]}))
        driver.command('DELETE', base)
        joined = owner.close()
        require(digest(CHROME) == CHROME_HASH and digest(DRIVER) == DRIVER_HASH)
        return {'observation': value, 'ownership': joined}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true')
    mode.add_argument('--check', action='store_true')
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'test/fixtures/urlpattern-full-independent.json')
    parser.add_argument('--proof', type=Path)
    args = parser.parse_args()
    data = {'cases': fixed_cases(), 'host_values': HOST_VALUES}
    source_paths = [Path(__file__).resolve()] + [ROOT/'test/interop/browser'/name
        for name in ['browser_worker.py', 'owned.py', 'netlog.py', 'oracle.py', 'receipt.py']]
    before = {str(path.relative_to(ROOT)): digest(path) for path in source_paths}
    require(digest(args.node) == NODE_HASH)
    node, node_supervision = supervise(lambda: node_run(args.node.resolve(), data), validate_run, seconds=25)
    chrome, chrome_supervision = supervise(lambda: chrome_run(data), validate_run, seconds=45)
    require(before == {str(path.relative_to(ROOT)): digest(path) for path in source_paths})
    require(node['observation']['rows'] == chrome['observation']['rows'])
    mismatches = [i for i in range(13) if node['observation']['hostname'][i] != chrome['observation']['hostname'][i]]
    require(mismatches == [8, 10, 11])
    names = ['matched', 'not_matched', 'invalid_pattern']
    fixture = {'schema': 1, 'specification_commit': SPEC, 'full_string_cases': 517,
        'input_sha256': hashlib.sha256(encoded(data)).hexdigest(),
        'generator_sha256': before[str(Path(__file__).resolve().relative_to(ROOT))],
        'evaluation_sha256': hashlib.sha256(EVALUATE.encode()).hexdigest(),
        'references': {'node': {'version': NODE_VERSION, 'binary_sha256': NODE_HASH,
                               'libatomic_sha256': ATOMIC_HASH},
            'chromium': {'version': CHROME_VERSION, 'binary_sha256': CHROME_HASH,
                        'driver_sha256': DRIVER_HASH}},
        'cases': [dict(row, expected=names[node['observation']['rows'][i]]) for i, row in enumerate(data['cases'])],
        'hostname_object_controls': [dict(id=i, literal=value, node=node['observation']['hostname'][i],
            chromium=chrome['observation']['hostname'][i], normative='reject_empty_special_host' if i in mismatches else 'reference_agreement')
            for i, value in enumerate(HOST_VALUES)],
        'hostname_reference_disagreements': mismatches}
    output = json.dumps(fixture, indent=2, ensure_ascii=False, sort_keys=True).encode('utf-8') + b'\n'
    require(len(output) <= 1048576)
    if args.write:
        args.output.write_bytes(output)
    else:
        require(args.output.stat().st_size <= 1048576 and args.output.read_bytes() == output)
    if args.proof:
        args.proof.write_bytes(encoded({'source_files': before, 'cases': 517,
            'fixture_sha256': hashlib.sha256(output).hexdigest(), 'node': node['ownership'],
            'node_supervision': node_supervision, 'chromium': chrome['ownership'],
            'chromium_supervision': chrome_supervision, 'source_unchanged': True}) + b'\n')
    print('URLPattern reference cases=517 full_agreement=true hostname_disagreements=3 joined=true')


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print('URLPattern reference failed')
        raise SystemExit(1)
