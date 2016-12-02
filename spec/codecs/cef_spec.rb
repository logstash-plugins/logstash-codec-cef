# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/cef"
require "logstash/event"
require "json"

describe LogStash::Codecs::CEF do
  subject do
    next LogStash::Codecs::CEF.new
  end

  context "#encode" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    let(:results)   { [] }

    context "with delimiter set" do 
      # '\r\n' in single quotes to simulate the real input from a config
      # containing \r\n as 4-character sequence in the config:
      #
      #   delimiter => "\r\n"
      #
      # Related: https://github.com/elastic/logstash/issues/1645
      subject(:codec) { LogStash::Codecs::CEF.new("delimiter" => '\r\n') }

      it "should append the delimiter to the result" do
        codec.on_event { |data, newdata| results << newdata }
        codec.encode(LogStash::Event.new({}))
        expect(results.first).to end_with("\r\n")
      end
    end

    it "should not fail if fields is nil" do
      codec.on_event{|data, newdata| results << newdata}
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should assert all header fields are present" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should use default values for empty header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = ""
      codec.product = ""
      codec.version = ""
      codec.signature = ""
      codec.name = ""
      codec.severity = ""
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should use configured values for header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "vendor"
      codec.product = "product"
      codec.version = "2.0"
      codec.signature = "signature"
      codec.name = "name"
      codec.severity = "1"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|vendor\|product\|2.0\|signature\|name\|1\|$/m)
    end

    it "should use sprintf for header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "%{vendor}"
      codec.product = "%{product}"
      codec.version = "%{version}"
      codec.signature = "%{signature}"
      codec.name = "%{name}"
      codec.severity = "%{severity}"
      codec.fields = []
      event = LogStash::Event.new("vendor" => "vendor", "product" => "product", "version" => "2.0", "signature" => "signature", "name" => "name", "severity" => "1")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|vendor\|product\|2.0\|signature\|name\|1\|$/m)
    end

    it "should use default, if severity is not numeric" do
      codec.on_event{|data, newdata| results << newdata}
      codec.severity = "foo"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should use default, if severity is > 10" do
      codec.on_event{|data, newdata| results << newdata}
      codec.severity = "11"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should use default, if severity is < 0" do
      codec.on_event{|data, newdata| results << newdata}
      codec.severity = "-1"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should use default, if severity is float with decimal part" do
      codec.on_event{|data, newdata| results << newdata}
      codec.severity = "5.4"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should append fields as key/value pairs in cef extension part" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo", "bar" ]
      event = LogStash::Event.new("foo" => "foo value", "bar" => "bar value")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=foo value bar=bar value$/m)
    end

    it "should ignore fields in fields if not present in event" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo", "bar", "baz" ]
      event = LogStash::Event.new("foo" => "foo value", "baz" => "baz value")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=foo value baz=baz value$/m)
    end

    it "should sanitize header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "ven\ndor"
      codec.product = "pro|duct"
      codec.version = "ver\\sion"
      codec.signature = "sig\r\nnature"
      codec.name = "na\rme"
      codec.severity = "4\n"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|ven dor\|pro\\\|duct\|ver\\\\sion\|sig nature\|na me\|4\|$/m)
    end

    it "should sanitize extension keys" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "f o\no", "@b-a_r" ]
      event = LogStash::Event.new("f o\no" => "foo value", "@b-a_r" => "bar value")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=foo value bar=bar value$/m)
    end

    it "should sanitize extension values" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo", "bar", "baz" ]
      event = LogStash::Event.new("foo" => "foo\\value\n", "bar" => "bar=value\r")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=foo\\\\value\\n bar=bar\\=value\\n$/m)
    end

    it "should encode a hash value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => { "bar" => "bar value", "baz" => "baz value" })
      codec.encode(event)
      foo = results.first[/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=(.*)$/, 1]
      expect(foo).not_to be_nil
      foo_hash = JSON.parse(foo)
      expect(foo_hash).to eq({"bar" => "bar value", "baz" => "baz value"})
    end

    it "should encode an array value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => [ "bar", "baz" ])
      codec.encode(event)
      foo = results.first[/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=(.*)$/, 1]
      expect(foo).not_to be_nil
      foo_array = JSON.parse(foo)
      expect(foo_array).to eq(["bar", "baz"])
    end

    it "should encode a hash in an array value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => [ { "bar" => "bar value" }, "baz" ])
      codec.encode(event)
      foo = results.first[/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=(.*)$/, 1]
      expect(foo).not_to be_nil
      foo_array = JSON.parse(foo)
      expect(foo_array).to eq([{"bar" => "bar value"}, "baz"])
    end

    it "should encode a LogStash::Timestamp" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => LogStash::Timestamp.new)
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=[0-9TZ.:-]+$/m)
    end

    it "should use severity (instead of depricated sev), if severity is set)" do
      codec.on_event{|data, newdata| results << newdata}
      codec.sev = "4"
      codec.severity = "5"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|5\|$/m)
    end

    it "should use deprecated sev, if severity is not set (equals default value)" do
      codec.on_event{|data, newdata| results << newdata}
      codec.sev = "4"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|4\|$/m)
    end

    it "should use deprecated sev, if severity is explicitly set to default value)" do
      codec.on_event{|data, newdata| results << newdata}
      codec.sev = "4"
      codec.severity = "6"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|4\|$/m)
    end

    it "should use deprecated sev, if severity is invalid" do
      codec.on_event{|data, newdata| results << newdata}
      codec.sev = "4"
      codec.severity = ""
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|4\|$/m)
    end

    it "should use default value, if severity is not set and sev is invalid" do
      codec.on_event{|data, newdata| results << newdata}
      codec.sev = ""
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end
  end

  context "sanitize header field" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    it "should sanitize" do
      expect(codec.send(:sanitize_header_field, "foo")).to be == "foo"
      expect(codec.send(:sanitize_header_field, "foo\nbar")).to be == "foo bar"
      expect(codec.send(:sanitize_header_field, "foo\rbar")).to be == "foo bar"
      expect(codec.send(:sanitize_header_field, "foo\r\nbar")).to be == "foo bar"
      expect(codec.send(:sanitize_header_field, "foo\r\nbar\r\nbaz")).to be == "foo bar baz"
      expect(codec.send(:sanitize_header_field, "foo\\bar")).to be == "foo\\\\bar"
      expect(codec.send(:sanitize_header_field, "foo|bar")).to be == "foo\\|bar"
      expect(codec.send(:sanitize_header_field, "foo=bar")).to be == "foo=bar"
      expect(codec.send(:sanitize_header_field, 123)).to be == "123" # Input value is a Fixnum
      expect(codec.send(:sanitize_header_field, 123.123)).to be == "123.123" # Input value is a Float
      expect(codec.send(:sanitize_header_field, [])).to be == "[]" # Input value is an Array
      expect(codec.send(:sanitize_header_field, {})).to be == "{}" # Input value is a Hash
    end
  end

  context "sanitize extension key" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    it "should sanitize" do
      expect(codec.send(:sanitize_extension_key, " foo ")).to be == "foo"
      expect(codec.send(:sanitize_extension_key, " FOO 123 ")).to be == "FOO123"
      expect(codec.send(:sanitize_extension_key, "foo\nbar\rbaz")).to be == "foobarbaz"
      expect(codec.send(:sanitize_extension_key, "Foo_Bar\r\nBaz")).to be == "FooBarBaz"
      expect(codec.send(:sanitize_extension_key, "foo-@bar=baz")).to be == "foobarbaz"
      expect(codec.send(:sanitize_extension_key, "[foo]|bar.baz")).to be == "foobarbaz"
      expect(codec.send(:sanitize_extension_key, 123)).to be == "123" # Input value is a Fixnum
      expect(codec.send(:sanitize_extension_key, 123.123)).to be == "123123" # Input value is a Float, "." is not allowed and therefore removed
      expect(codec.send(:sanitize_extension_key, [])).to be == "" # Input value is an Array, "[" and "]" are not allowed and therefore removed
      expect(codec.send(:sanitize_extension_key, {})).to be == "" # Input value is a Hash, "{" and "}" are not allowed and therefore removed
    end
  end

  context "sanitize extension value" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    it "should sanitize" do
      expect(codec.send(:sanitize_extension_val, "foo")).to be == "foo"
      expect(codec.send(:sanitize_extension_val, "foo\nbar")).to be == "foo\\nbar"
      expect(codec.send(:sanitize_extension_val, "foo\rbar")).to be == "foo\\nbar"
      expect(codec.send(:sanitize_extension_val, "foo\r\nbar")).to be == "foo\\nbar"
      expect(codec.send(:sanitize_extension_val, "foo\r\nbar\r\nbaz")).to be == "foo\\nbar\\nbaz"
      expect(codec.send(:sanitize_extension_val, "foo\\bar")).to be == "foo\\\\bar"
      expect(codec.send(:sanitize_extension_val, "foo|bar")).to be == "foo|bar"
      expect(codec.send(:sanitize_extension_val, "foo=bar")).to be == "foo\\=bar"
      expect(codec.send(:sanitize_extension_val, 123)).to be == "123" # Input value is a Fixnum
      expect(codec.send(:sanitize_extension_val, 123.123)).to be == "123.123" # Input value is a Float
      expect(codec.send(:sanitize_extension_val, [])).to be == "[]" # Input value is an Array
      expect(codec.send(:sanitize_extension_val, {})).to be == "{}" # Input value is a Hash
    end
  end

  context "valid_severity?" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    it "should validate severity" do
      expect(codec.send(:valid_severity?, nil)).to be == false
      expect(codec.send(:valid_severity?, "")).to be == false
      expect(codec.send(:valid_severity?, "foo")).to be == false
      expect(codec.send(:valid_severity?, "1.5")).to be == false
      expect(codec.send(:valid_severity?, "-1")).to be == false
      expect(codec.send(:valid_severity?, "11")).to be == false
      expect(codec.send(:valid_severity?, "0")).to be == true
      expect(codec.send(:valid_severity?, "10")).to be == true
      expect(codec.send(:valid_severity?, "1.0")).to be == true
      expect(codec.send(:valid_severity?, 1)).to be == true
      expect(codec.send(:valid_severity?, 1.0)).to be == true
    end
  end

  context "#decode" do
    let (:message) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }

    def validate(e)
      insist { e.is_a?(LogStash::Event) }
      insist { e.get('cefVersion') } == "0"
      insist { e.get('deviceVersion') } == "1.0"
      insist { e.get('deviceEventClassId') } == "100"
      insist { e.get('name') } == "trojan successfully stopped"
      insist { e.get('severity') } == "10"
    end

    context "with delimiter set" do 
      # '\r\n' in single quotes to simulate the real input from a config
      # containing \r\n as 4-character sequence in the config:
      #
      #   delimiter => "\r\n"
      #
      # Related: https://github.com/elastic/logstash/issues/1645
      subject(:codec) { LogStash::Codecs::CEF.new("delimiter" => '\r\n') }

      it "should parse on the delimiter " do
        subject.decode(message) do |e|
          raise Exception.new("Should not get here. If we do, it means the decoder emitted an event before the delimiter was seen?")
        end

        event = false;
        subject.decode("\r\n") do |e|
          validate(e)
          insist { e.get("deviceVendor") } == "security"
          insist { e.get("deviceProduct") } == "threatmanager"
          event = true
        end

        expect(event).to be_truthy
      end
    end

    it "should parse the cef headers" do
      subject.decode(message) do |e|
        validate(e)
        insist { e.get("deviceVendor") } == "security"
        insist { e.get("deviceProduct") } == "threatmanager"
      end
    end

    it "should parse the cef body" do
      subject.decode(message) do |e|
        insist { e.get("sourceAddress")} == "10.0.0.192"
        insist { e.get("destinationAddress") } == "12.121.122.82"
        insist { e.get("sourcePort") } == "1232"
      end
    end

    let (:missing_headers) { "CEF:0|||1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "should be OK with missing CEF headers (multiple pipes in sequence)" do
      subject.decode(missing_headers) do |e|
        validate(e)
        insist { e.get("deviceVendor") } == ""
        insist { e.get("deviceProduct") } == ""
      end
    end

    let (:leading_whitespace) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10| src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "should strip leading whitespace from the message" do
      subject.decode(leading_whitespace) do |e|
        validate(e)
      end
    end

    let (:escaped_pipes) { 'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this\|has an escaped pipe' }
    it "should be OK with escaped pipes in the message" do
      subject.decode(escaped_pipes) do |e|
        insist { e.get("moo") } == 'this\|has an escaped pipe'
      end
    end

    let (:pipes_in_message) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this|has an pipe'}
    it "should be OK with not escaped pipes in the message" do
      subject.decode(pipes_in_message) do |e|
        insist { e.get("moo") } == 'this|has an pipe'
      end
    end

    let (:equal_in_message) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this =has = equals\='}
    it "should be OK with equal in the message" do
      subject.decode(equal_in_message) do |e|
        insist { e.get("moo") } == 'this =has = equals='
      end
    end

    let (:escaped_backslash_in_header) {'CEF:0|secu\\\\rity|threat\\\\manager|1.\\\\0|10\\\\0|tro\\\\jan successfully stopped|\\\\10|'}
    it "should be OK with escaped backslash in the headers" do
      subject.decode(escaped_backslash_in_header) do |e|
        insist { e.get("cefVersion") } == '0'
        insist { e.get("deviceVendor") } == 'secu\\rity'
        insist { e.get("deviceProduct") } == 'threat\\manager'
        insist { e.get("deviceVersion") } == '1.\\0'
        insist { e.get("deviceEventClassId") } == '10\\0'
        insist { e.get("name") } == 'tro\\jan successfully stopped'
        insist { e.get("severity") } == '\\10'
      end
    end

    let (:escaped_backslash_in_header_edge_case) {'CEF:0|security\\\\\\||threatmanager\\\\|1.0|100|trojan successfully stopped|10|'}
    it "should be OK with escaped backslash in the headers (edge case: escaped slash in front of pipe)" do
      subject.decode(escaped_backslash_in_header_edge_case) do |e|
        validate(e)
        insist { e.get("deviceVendor") } == 'security\\|'
        insist { e.get("deviceProduct") } == 'threatmanager\\'
      end
    end

    let (:escaped_pipes_in_header) {'CEF:0|secu\\|rity|threatmanager\\||1.\\|0|10\\|0|tro\\|jan successfully stopped|\\|10|'}
    it "should be OK with escaped pipes in the headers" do
      subject.decode(escaped_pipes_in_header) do |e|
        insist { e.get("cefVersion") } == '0'
        insist { e.get("deviceVendor") } == 'secu|rity'
        insist { e.get("deviceProduct") } == 'threatmanager|'
        insist { e.get("deviceVersion") } == '1.|0'
        insist { e.get("deviceEventClassId") } == '10|0'
        insist { e.get("name") } == 'tro|jan successfully stopped'
        insist { e.get("severity") } == '|10'
      end
    end

    let (:backslash_in_message) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this \\has \\ backslashs\\'}
    it "should be OK with backslashs in the message" do
      subject.decode(backslash_in_message) do |e|
        insist { e.get("moo") } == 'this \\has \\ backslashs\\'
      end
    end

    let (:equal_in_header) {'CEF:0|security|threatmanager=equal|1.0|100|trojan successfully stopped|10|'}
    it "should be OK with equal in the headers" do
      subject.decode(equal_in_header) do |e|
        validate(e)
        insist { e.get("deviceProduct") } == "threatmanager=equal"
      end
    end

    let (:spaces_in_between_keys) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10| src=10.0.0.192  dst=12.121.122.82  spt=1232'}
    it "should be OK to have one or more spaces between keys" do
      subject.decode(spaces_in_between_keys) do |e|
        validate(e)
        insist { e.get("sourceAddress") } == "10.0.0.192"
        insist { e.get("destinationAddress") } == "12.121.122.82"
        insist { e.get("sourcePort") } == "1232"
      end
    end

    let (:allow_spaces_in_values) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82  spt=1232 dproc=InternetExplorer x.x.x.x'}
    it "should be OK to have one or more spaces in values" do
      subject.decode(allow_spaces_in_values) do |e|
        validate(e)
        insist { e.get("sourceAddress") } == "10.0.0.192"
        insist { e.get("destinationAddress") } == "12.121.122.82"
        insist { e.get("sourcePort") } == "1232"
        insist { e.get("destinationProcessName") } == "InternetExplorer x.x.x.x"
      end
    end

    let (:trim_additional_fields_with_dot_notations) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 ad.field[0]=field0 ad.name[1]=new_name'}
    it "should remove ad.fields" do
      subject.decode(trim_additional_fields_with_dot_notations) do |e|
        validate(e)
        insist { e.get("sourceAddress") } == "10.0.0.192"
        insist { e.get("destinationAddress") } == "12.121.122.82"
        insist { e.get("ad.field[0]") } == nil
        insist { e.get("ad.name[1]") } == nil
      end
    end

    let (:preserve_unmatched_key_mappings) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 new_key_by_device=new_values here'}
    it "should remove ad.fields" do
      subject.decode(preserve_unmatched_key_mappings) do |e|
        validate(e)
        insist { e.get("sourceAddress") } == "10.0.0.192"
        insist { e.get("destinationAddress") } == "12.121.122.82"
        insist { e.get("new_key_by_device") } == "new_values here"
      end
    end

    let (:translate_abbreviated_cef_fields) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 proto=TCP shost=source.host.name dhost=destination.host.name spt=11024 dpt=9200'}
    it "should translate most known abbreviated CEF field names" do
      subject.decode(translate_abbreviated_cef_fields) do |e|
        validate(e)
        insist { e.get("sourceAddress") } == "10.0.0.192"
        insist { e.get("destinationAddress") } == "12.121.122.82"
        insist { e.get("transportProtocol") } == "TCP"
        insist { e.get("sourceHostName") } == "source.host.name"
        insist { e.get("destinationHostName") } == "destination.host.name"
        insist { e.get("sourcePort") } == "11024"
        insist { e.get("destinationPort") } == "9200"
      end
    end

    let (:syslog) { "Syslogdate Sysloghost CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "Should detect headers before CEF starts" do
      subject.decode(syslog) do |e|
        validate(e)
        insist { e.get('syslog') } == 'Syslogdate Sysloghost'
      end
    end
  end
  
  context "decode with deprecated version option" do
    let (:message) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    let(:options) {
      {
        "deprecated_v1_fields" => true
      }
    }
    
    subject(:codec) { LogStash::Codecs::CEF.new(options) }
    
    def validate(e) 
      insist { e.is_a?(LogStash::Event) }
      insist { e.get('cef_version') } == "0"
      insist { e.get('cef_device_version') } == "1.0"
      insist { e.get('cef_sigid') } == "100"
      insist { e.get('cef_name') } == "trojan successfully stopped"
      insist { e.get('cef_severity') } == "10"
      insist { e.get('cefVersion') } == "0"
      insist { e.get('deviceVersion') } == "1.0"
      insist { e.get('deviceEventClassId') } == "100"
      insist { e.get('name') } == "trojan successfully stopped"
      insist { e.get('severity') } == "10"
    end

    it "should parse the cef headers" do
      subject.decode(message) do |e|
        validate(e)
        ext = e.get('cef_ext')
        insist { e.get("cef_vendor") } == "security"
        insist { e.get("cef_product") } == "threatmanager"
        insist { e.get("deviceVendor") } == "security"
        insist { e.get("deviceProduct") } == "threatmanager"
      end
    end

    it "should parse the cef body" do
      subject.decode(message) do |e|
        ext = e.get('cef_ext')
        insist { ext['src'] } == "10.0.0.192"
        insist { ext['dst'] } == "12.121.122.82"
        insist { ext['spt'] } == "1232"
        insist { e.get("sourceAddress")} == "10.0.0.192"
        insist { e.get("destinationAddress") } == "12.121.122.82"
        insist { e.get("sourcePort") } == "1232"
      end
    end

    let (:no_ext) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|" }
    it "should be OK with no extension dictionary" do
      subject.decode(no_ext) do |e|
        validate(e)
        insist { e.get("cef_ext") } == nil
      end 
    end

    let (:missing_headers) { "CEF:0|||1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "should be OK with missing CEF headers (multiple pipes in sequence)" do
      subject.decode(missing_headers) do |e|
        validate(e)
        insist { e.get("cef_vendor") } == ""
        insist { e.get("cef_product") } == ""
        insist { e.get("deviceVendor") } == ""
        insist { e.get("deviceProduct") } == ""
      end 
    end

    let (:leading_whitespace) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10| src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "should strip leading whitespace from the message" do
      subject.decode(leading_whitespace) do |e|
        validate(e)
      end 
    end

    let (:escaped_pipes) { 'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this\|has an escaped pipe' }
    it "should be OK with escaped pipes in the message" do
      subject.decode(escaped_pipes) do |e|
        ext = e.get('cef_ext')
        insist { ext['moo'] } == 'this\|has an escaped pipe'
      end 
    end

    let (:pipes_in_message) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this|has an pipe'}
    it "should be OK with not escaped pipes in the message" do
      subject.decode(pipes_in_message) do |e|
        ext = e.get('cef_ext')
        insist { ext['moo'] } == 'this|has an pipe'
      end
    end

    let (:escaped_equal_in_message) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this \=has escaped \= equals\='}
    it "should be OK with escaped equal in the message" do
      subject.decode(escaped_equal_in_message) do |e|
        ext = e.get('cef_ext')
        insist { ext['moo'] } == 'this =has escaped = equals='
      end
    end

    let (:escaped_backslash_in_header) {'CEF:0|secu\\\\rity|threat\\\\manager|1.\\\\0|10\\\\0|tro\\\\jan successfully stopped|\\\\10|'}
    it "should be OK with escaped backslash in the headers" do
      subject.decode(escaped_backslash_in_header) do |e|
        insist { e.get("cef_version") } == '0'
        insist { e.get("cef_vendor") } == 'secu\\rity'
        insist { e.get("cef_product") } == 'threat\\manager'
        insist { e.get("cef_device_version") } == '1.\\0'
        insist { e.get("cef_sigid") } == '10\\0'
        insist { e.get("cef_name") } == 'tro\\jan successfully stopped'
        insist { e.get("cef_severity") } == '\\10'
      end
    end

    let (:escaped_backslash_in_header_edge_case) {'CEF:0|security\\\\\\||threatmanager\\\\|1.0|100|trojan successfully stopped|10|'}
    it "should be OK with escaped backslash in the headers (edge case: escaped slash in front of pipe)" do
      subject.decode(escaped_backslash_in_header_edge_case) do |e|
        validate(e)
        insist { e.get("cef_vendor") } == 'security\\|'
        insist { e.get("cef_product") } == 'threatmanager\\'
      end
    end

    let (:escaped_pipes_in_header) {'CEF:0|secu\\|rity|threatmanager\\||1.\\|0|10\\|0|tro\\|jan successfully stopped|\\|10|'}
    it "should be OK with escaped pipes in the headers" do
      subject.decode(escaped_pipes_in_header) do |e|
        insist { e.get("cef_version") } == '0'
        insist { e.get("cef_vendor") } == 'secu|rity'
        insist { e.get("cef_product") } == 'threatmanager|'
        insist { e.get("cef_device_version") } == '1.|0'
        insist { e.get("cef_sigid") } == '10|0'
        insist { e.get("cef_name") } == 'tro|jan successfully stopped'
        insist { e.get("cef_severity") } == '|10'
        insist { e.get("cefVersion") } == '0'
        insist { e.get("deviceVendor") } == 'secu|rity'
        insist { e.get("deviceProduct") } == 'threatmanager|'
        insist { e.get("deviceVersion") } == '1.|0'
        insist { e.get("deviceEventClassId") } == '10|0'
        insist { e.get("name") } == 'tro|jan successfully stopped'
        insist { e.get("severity") } == '|10'
      end
    end

    let (:escaped_backslash_in_message) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this \\\\has escaped \\\\ backslashs\\\\'}
    it "should be OK with escaped backslashs in the message" do
      subject.decode(escaped_backslash_in_message) do |e|
        ext = e.get('cef_ext')
        insist { ext['moo'] } == 'this \\has escaped \\ backslashs\\'
      end
    end

    let (:equal_in_header) {'CEF:0|security|threatmanager=equal|1.0|100|trojan successfully stopped|10|'}
    it "should be OK with equal in the headers" do
      subject.decode(equal_in_header) do |e|
        validate(e)
        insist { e.get("cef_product") } == "threatmanager=equal"
      end
    end

    let (:syslog) { "Syslogdate Sysloghost CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "Should detect headers before CEF starts" do
      subject.decode(syslog) do |e|
        validate(e)
        insist { e.get('syslog') } == 'Syslogdate Sysloghost'
      end
    end

    context "when payload is not in CEF" do
      let (:message) { "potatoes" }
      it "Should detect headers before CEF starts" do
        subject.decode(message) do |e|
          insist { e.get('tags') } == ['_cefparsefailure']
        end
      end
    end
  end

  context "encode and decode" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    let(:results)   { [] }

    it "should return an equal event if encoded and decoded again" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "%{deviceVendor}"
      codec.product = "%{deviceProduct}"
      codec.version = "%{deviceVersion}"
      codec.signature = "%{deviceEventClassId}"
      codec.name = "%{name}"
      codec.severity = "%{severity}"
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("deviceVendor" => "vendor", "deviceProduct" => "product", "deviceVersion" => "2.0", "deviceEventClassId" => "signature", "name" => "name", "severity" => "1", "foo" => "bar")
      codec.encode(event)
      codec.decode(results.first) do |e|
        expect(e.get('deviceVendor')).to be == event.get('deviceVendor')
        expect(e.get('deviceProduct')).to be == event.get('deviceProduct')
        expect(e.get('deviceVersion')).to be == event.get('deviceVersion')
        expect(e.get('deviceEventClassId')).to be == event.get('deviceEventClassId')
        expect(e.get('name')).to be == event.get('name')
        expect(e.get('severity')).to be == event.get('severity')
        expect(e.get('foo')).to be == event.get('foo')
      end
    end
  end

end
