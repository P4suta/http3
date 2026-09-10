import gleeunit
import http/digest
import http/structured_fields

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn rfc9530_sha256_and_sha512_vectors_test() -> Nil {
  let content = <<"{\"hello\": \"world\"}":utf8>>
  let assert Ok(values) =
    digest.compute_many(content, [digest.Sha256, digest.Sha512], 1024)
  assert digest.serialize(values)
    == Ok(
      "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
    )
}

pub fn parse_retains_unknown_algorithms_and_parameters_test() -> Nil {
  let field = "sha-256=:AQI=:;scope=content, example=:AwQ=:;version=2"
  let assert Ok(values) = digest.parse(field)
  assert digest.serialize(values) == Ok(field)
  assert values
    == [
      digest.Digest(algorithm: digest.Sha256, value: <<1, 2>>, parameters: [
        structured_fields.Parameter("scope", structured_fields.Token("content")),
      ]),
      digest.Digest(
        algorithm: digest.Extension("example"),
        value: <<3, 4>>,
        parameters: [
          structured_fields.Parameter("version", structured_fields.Integer(2)),
        ],
      ),
    ]
}

pub fn verification_checks_every_supported_value_in_constant_time_test() -> Nil {
  let content = <<"payload":utf8>>
  let assert Ok(values) =
    digest.compute_many(content, [digest.Sha512, digest.Sha256], 1024)
  assert digest.verify(content, values, digest.defaults()) == Ok(Nil)

  let assert [first, second] = values
  let corrupted = digest.Digest(..second, value: <<0:256>>)
  assert digest.verify(content, [first, corrupted], digest.defaults())
    == Error(digest.Mismatch)
  assert digest.verify(
      content,
      [digest.Digest(digest.Extension("private"), <<1>>, [])],
      digest.defaults(),
    )
    == Error(digest.NoAcceptableDigest)
}

pub fn digest_fields_and_preferences_are_strict_and_bounded_test() -> Nil {
  assert digest.parse("sha-256=token") == Error(digest.Invalid)
  assert digest.parse_preferences("sha-256=11") == Error(digest.Invalid)
  assert digest.parse_preferences("sha-512=3, sha-256=10, unixsum=0")
    == Ok([
      digest.Preference(digest.Sha512, 3),
      digest.Preference(digest.Sha256, 10),
      digest.Preference(digest.Extension("unixsum"), 0),
    ])
  assert digest.serialize_preferences([
      digest.Preference(digest.Sha512, 3),
      digest.Preference(digest.Sha256, 10),
    ])
    == Ok("sha-512=3, sha-256=10")

  assert digest.compute(<<1:1>>, digest.Sha256, 10)
    == Error(digest.NonByteAligned)
  assert digest.compute(<<1, 2, 3>>, digest.Sha256, 2)
    == Error(digest.LimitExceeded)
}
