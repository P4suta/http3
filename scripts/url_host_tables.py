#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate bounded, immutable Unicode16 host tables from pinned official data."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
from process_supervisor import owned_run

INPUTS = {
    "IdnaMappingTable.txt": "6db2ef4ed35f3b3de74ebc2e00404a9607f76d499f576b8d4043cf14f1ed175c",
    "UnicodeData.txt": "ff58e5823bd095166564a006e47d111130813dcf8bf234ef79fa51a870edb48f",
    "DerivedNormalizationProps.txt": "4d4c03892dea9146d674b686e495df2d55a28d071ac474041d73518f887abddc",
    "DerivedBidiClass.txt": "71ed943a49c58568d8d92e80ecc2ba2f06e62aee9c8ebb0e6e8bd2c3ed8b180e",
    "DerivedJoiningType.txt": "6bd08b97da66b70ccfdab105a352de2984e02625239ec5695422c99b33d854f0",
}
BIDI = {v: i for i, v in enumerate("L R AL EN AN ES CS ET ON BN NSM".split())}
JOINING = {v: i for i, v in enumerate("U R L D T C".split())}


def label_parameters(source):
    """Label generated helper parameters and calls using lexical boundaries."""
    pattern = r'//[^\n]*|"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z_0-9]*|<<|>>|[^\s]'
    tokens = [(m.group(), m.start()) for m in re.finditer(pattern, source)
              if not m.group().startswith('//')]
    def arguments(start):
        stack, values, current = [], [], start + 1
        for index in range(start + 1, len(tokens)):
            word = tokens[index][0]
            if word == ')' and not stack:
                if index > current:
                    values.append((current, index))
                return values
            if word == ',' and not stack:
                values.append((current, index))
                current = index + 1
            elif word in ('(', '[', '{', '<<'):
                stack.append(word)
            elif word in (')', ']', '}', '>>'):
                assert stack
                stack.pop()
        raise AssertionError('generated_signature')
    signatures, insertions = {}, []
    for i, (word, _) in enumerate(tokens[:-2]):
        if word != 'fn' or tokens[i + 2][0] != '(':
            continue
        params = arguments(i + 2)
        if len(params) < 2:
            continue
        names = [tokens[first][0] for first, _ in params]
        signatures[tokens[i + 1][0]] = names
        for (first, _), name in zip(params, names):
            if tokens[first + 1][0] == ':':
                insertions.append((tokens[first][1], name + ' '))
    for i, (word, _) in enumerate(tokens[:-1]):
        if word not in signatures or tokens[i + 1][0] != '(' or i > 0 and tokens[i - 1][0] in ('fn', '.'):
            continue
        args = arguments(i + 1)
        names = signatures[word]
        if i >= 2 and tokens[i - 2][0] == '|' and tokens[i - 1][0] == '>':
            names = names[1:]
        assert len(args) == len(names)
        for (first, last), name in zip(args, names):
            if first + 1 < last and tokens[first + 1][0] == ':':
                continue
            insertions.append((tokens[first][1], name + ': '))
    for index, text in sorted(insertions, reverse=True):
        source = source[:index] + text + source[index:]
    return source


def guard_helpers(source):
    pattern = r'^  case ([^\n]+) \{\n    True -> ([^\n]+)\n    False -> \{\n(.*?)\n    \}\n  \}\n\}'
    def replace(match):
        body = '\n'.join(line[4:] if line.startswith('    ') else line
                         for line in match[3].splitlines())
        return f'  use <- bool.guard({match[1]}, {match[2]})\n{body}\n}}'
    source, count = re.subn(pattern, replace, source, flags=re.M | re.S)
    if count and 'import gleam/bool\n' not in source:
        source = source.replace('import gleam/list\n', 'import gleam/bool\nimport gleam/list\n')
    return source


def load(directory, name):
    path = directory / name
    assert path.stat().st_size <= 4_194_304
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == INPUTS[name]
    return data.decode("utf-8")


def rows(text):
    for line in text.splitlines():
        fields = [p.strip() for p in line.split("#", 1)[0].split(";")]
        if len(fields) < 2:
            continue
        endpoints = fields[0].split("..")
        yield int(endpoints[0], 16), int(endpoints[-1], 16), fields[1:]


def compact(cells):
    out = []
    for first, last, value in sorted(cells):
        assert 0 <= first <= last <= 0x10ffff
        if out and out[-1][1] + 1 == first and out[-1][2] == value:
            out[-1] = (out[-1][0], last, value)
        else:
            assert not out or out[-1][1] < first
            out.append((first, last, value))
    return out


def number(value):
    return f"{value:_}"


def table(name, entries, widths):
    cells = [f"{number(value)}:{width}" for row in entries for value, width in zip(row, widths)]
    lines, current = [], "  "
    for cell in cells:
        if len(current) + len(cell) + 2 > 77:
            lines.append(current)
            current = "  "
        current += cell + ", "
    if current.strip():
        lines.append(current)
    return f"const {name} = <<\n" + "\n".join(s.rstrip() for s in lines) + "\n>>\n"


def generate(directory):
    loaded = {name: load(directory, name) for name in INPUTS}
    maps, mapped = [], []
    statuses = {"valid": 0, "deviation": 0, "ignored": 1, "mapped": 2, "disallowed": 3}
    end = -1
    for first, last, fields in rows(loaded["IdnaMappingTable.txt"]):
        assert first == end + 1
        end = last
        status = statuses[fields[0]]
        expansion = [int(c, 16) for c in fields[1].split()] if len(fields) > 1 and status == 2 else []
        assert len(expansion) <= 18
        maps.append((first, last, status, len(mapped), len(expansion)))
        mapped.extend(expansion)
    assert end == 0x10ffff
    exclusions = set()
    for first, last, fields in rows(loaded["DerivedNormalizationProps.txt"]):
        if fields[0] == "Full_Composition_Exclusion":
            exclusions.update(range(first, last + 1))
    ccc, marks, decomps, comps = [], [], {}, []
    pending = None
    for line in loaded["UnicodeData.txt"].splitlines():
        fields = line.split(";")
        point = int(fields[0], 16)
        if fields[1].endswith(", First>"):
            pending = point
            continue
        first = pending if fields[1].endswith(", Last>") else point
        pending = None
        if int(fields[3]):
            ccc.append((first, point, int(fields[3])))
        if fields[2].startswith("M"):
            marks.append((first, point, 1))
        if fields[5] and not fields[5].startswith("<"):
            decomposition = [int(p, 16) for p in fields[5].split()]
            decomps[point] = decomposition
            if len(decomposition) == 2 and point not in exclusions:
                comps.append((decomposition[0] * 0x110000 + decomposition[1], point))
    def expand(point, depth=0):
        assert depth <= 4
        return [c for p in decomps.get(point, [point]) for c in
                (expand(p, depth + 1) if p in decomps else [p])]
    decomp_rows, decomp_data = [], []
    for point in sorted(decomps):
        values = expand(point)
        decomp_rows.append((point, len(decomp_data), len(values)))
        decomp_data.extend(values)
    assert max(row[2] for row in decomp_rows) == 4
    assert max(row[4] for row in maps) == 18
    bidi = compact([(a, b, BIDI.get(f[0], 11)) for a, b, f in rows(loaded["DerivedBidiClass.txt"])])
    joining = compact([(a, b, JOINING[f[0]]) for a, b, f in rows(loaded["DerivedJoiningType.txt"])])
    collections = {"classes": compact(ccc), "marks": compact(marks), "bidis": bidi, "joiners": joining}
    source = """//// Generated Unicode16 data; regenerate with scripts/url_host_tables.py.
//// SPDX-FileCopyrightText: 2024 Unicode®, Inc.
//// SPDX-FileCopyrightText: 2026 the http contributors
//// SPDX-License-Identifier: Unicode-3.0 AND (MIT OR Apache-2.0)
//// Maximum mapping18 and canonical decomposition4 scalars are generator-checked.
//// A 2048-byte host therefore expands to at most147456 intermediate scalars;
//// Hangul decomposition is at most3 and does not increase this bound.

import gleam/list

"""
    source += table("mappings", maps, [32, 32, 8, 32, 8])
    source += table("mapping_data", [(c,) for c in mapped], [32])
    source += table("decompositions", decomp_rows, [32, 32, 8])
    source += table("decomposition_data", [(c,) for c in decomp_data], [32])
    source += table("compositions", sorted(comps), [64, 32])
    for name, entries in collections.items():
        source += table(name, entries, [32, 32, 16])
    source += f"""
/// 0 valid/deviation, 1 ignored, 2 mapped, 3 disallowed (nontransitional).
pub fn mapping(code: Int) -> #(Int, List(Int)) {{
  mapping_at(code, 0, {len(maps)})
}}

fn mapping_at(code: Int, low: Int, high: Int) -> #(Int, List(Int)) {{
  case low >= high {{
    True -> #(3, [])
    False -> {{
      let middle = low + {{ high - low }} / 2
      let skipped = middle * 112
      case mappings {{
        <<_:size(skipped), first:32, last:32, status:8, offset:32, count:8, _:bits>> ->
          case code {{
            value if value < first -> mapping_at(code, low, middle)
            value if value > last -> mapping_at(code, middle + 1, high)
            _ -> #(status, codes(mapping_data, offset, count))
          }}
        _ -> #(3, [])
      }}
    }}
  }}
}}

pub fn decomposition(code: Int) -> List(Int) {{
  decomposition_at(code, 0, {len(decomp_rows)})
}}

fn decomposition_at(code: Int, low: Int, high: Int) -> List(Int) {{
  case low >= high {{
    True -> [code]
    False -> {{
      let middle = low + {{ high - low }} / 2
      let skipped = middle * 72
      case decompositions {{
        <<_:size(skipped), point:32, offset:32, count:8, _:bits>> -> case code {{
          value if value < point -> decomposition_at(code, low, middle)
          value if value > point -> decomposition_at(code, middle + 1, high)
          _ -> codes(decomposition_data, offset, count)
        }}
        _ -> [code]
      }}
    }}
  }}
}}

/// Missing canonical composition is -1; callers handle Hangul algorithmically.
pub fn composition(first: Int, second: Int) -> Int {{
  composition_at(first * 1_114_112 + second, 0, {len(comps)})
}}

fn composition_at(key: Int, low: Int, high: Int) -> Int {{
  case low >= high {{
    True -> -1
    False -> {{
      let middle = low + {{ high - low }} / 2
      let skipped = middle * 96
      case compositions {{
        <<_:size(skipped), found:64, composed:32, _:bits>> -> case key {{
          value if value < found -> composition_at(key, low, middle)
          value if value > found -> composition_at(key, middle + 1, high)
          _ -> composed
        }}
        _ -> -1
      }}
    }}
  }}
}}

fn codes(data: BitArray, offset: Int, count: Int) -> List(Int) {{
  let skipped = offset * 32
  let length = count * 32
  case data {{
    <<_:size(skipped), values:size(length)-bits, _:bits>> -> read_codes(values, [])
    _ -> []
  }}
}}

fn read_codes(data: BitArray, reversed: List(Int)) -> List(Int) {{
  case data {{
    <<code:32, rest:bits>> -> read_codes(rest, [code, ..reversed])
    _ -> list.reverse(reversed)
  }}
}}
"""
    for name, public, default in [("classes", "ccc", 0), ("marks", "mark", 0), ("bidis", "bidi", 0), ("joiners", "joining", 0)]:
        source += f"\npub fn {public}(code: Int) -> Int {{\n  property({name}, code, 0, {len(collections[name])}, {default})\n}}\n"
    source += """
fn property(data: BitArray, code: Int, low: Int, high: Int, default: Int) -> Int {
  case low >= high {
    True -> default
    False -> {
      let middle = low + { high - low } / 2
      let skipped = middle * 80
      case data {
        <<_:size(skipped), first:32, last:32, value:16, _:bits>> -> case code {
          point if point < first -> property(data, code, low, middle, default)
          point if point > last -> property(data, code, middle + 1, high, default)
          _ -> value
        }
        _ -> default
      }
    }
  }
}
"""
    return source


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_const", const="write", dest="mode")
    mode.add_argument("--check", action="store_const", const="check", dest="mode")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--formatter", type=Path, required=True)
    args = parser.parse_args()
    source = label_parameters(guard_helpers(generate(args.directory)))
    formatter_hash = hashlib.sha256(args.formatter.read_bytes()).hexdigest()
    assert formatter_hash in {
        "480d513f2e618a9435c654d073d1e1b18693d7442244b921796110117cca7875",
        "2d48c70edb9da6181224b82050179da9112bc42d7e374360475dc18109762a0e",
    }
    formatted = owned_run([str(args.formatter), "format", "--stdin"], input=source.encode(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
                               max_output_bytes=2_097_151, check=False)
    assert formatted.returncode == 0 and not formatted.stderr
    assert hashlib.sha256(args.formatter.read_bytes()).hexdigest() == formatter_hash
    source = formatted.stdout.decode("utf-8").replace("\r\n", "\n")
    target = Path("src/http/internal/url_pattern/host_data.gleam")
    if args.mode == "write":
        target.write_text(source, encoding="utf-8", newline="\n")
    else:
        assert target.read_text(encoding="utf-8") == source
    print("Unicode host table inputs=5 generated=true")


if __name__ == "__main__":
    main()
