## 5.0.2
  - Update gemspec summary

## 5.0.1
  - Fix some documentation issues

## 5.0.0
 - move `sev` and `deprecated_v1_fields` fields from deprecated to obsolete

## 4.1.2
 - added mapping for outcome = eventOutcome from CEF whitepaper (ref:p26/39)

## 4.1.1
 - changed rt from receiptTime to deviceReceiptTime (ref:p27/39)
 - changed tokenizer to include additional fields (ad.fieldname)

## 4.1.0
 - Add `delimiter` setting. This allows the decoder to be used with inputs like the TCP input where event delimiters are used.

## 4.0.0
 - Implements the dictionary translation for abbreviated CEF field names from chapter Chapter 2: ArcSight Extension Dictionary page 3 of 39 [CEF specification](https://protect724.hp.com/docs/DOC-1072).
 - add `_cefparsefailure` tag on failed decode

## 3.0.0
 - breaking: Updated plugin to use new Java Event APIs

## 2.1.3
 - Switch in-place sub! to sub when extracting `cef_version`. new Logstash Java Event does not support in-place String changes.

## 2.1.2
 - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

## 2.1.1
 - New dependency requirements for logstash-core for the 5.0 release

## 2.1.0
 - Implements `encode` with escaping according to the [CEF specification](https://protect724.hp.com/docs/DOC-1072).
 - Config option `sev` is deprecated, use `severity` instead.

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0
